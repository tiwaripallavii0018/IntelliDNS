from pathlib import Path
from threat_intelligence.blacklist import DomainBlacklist
from threat_intelligence.stix_feed import STIXFeedLoader
import logging
import time
import threading

import dns.message
import dns.query

from dnslib import DNSRecord

from monitoring.database import (
    initialize_database,
    save_query,
    is_ip_blocked
)

from monitoring.threat_store import (
    initialize_threat_store,
    save_threat_event
)

from dns_engine.cache import DNSCache

from security.alert_manager import AlertManager
from security.rate_limiter import RateLimiter
from security.advanced_detector import AdvancedThreatDetector
from security.response_manager import ThreatResponseManager


logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("IntelliDNS")


class IntelliDNSResolver:

    def __init__(self):

        initialize_database()
        initialize_threat_store()

        self.cache = DNSCache(max_size=10000)

        self.rate_limiter = RateLimiter()
        self.threat_detector = AdvancedThreatDetector()
                # Local blacklist and STIX threat intelligence
        self.blacklist = DomainBlacklist()
        self.stix_loader = STIXFeedLoader()

        feed_path = (
            Path(__file__).resolve().parent.parent
            / "threat_intelligence"
            / "feeds"
            / "local_stix_bundle.json"
        )

        self.stix_domains = self.stix_loader.load_domains(
            str(feed_path)
        )

        self.blacklist.add_domains(self.stix_domains)

        logger.info(
            "THREAT INTELLIGENCE LOADED | DOMAINS=%d",
            len(self.blacklist.get_domains())
        )

        self.alert_manager = AlertManager()

        self.response_manager = ThreatResponseManager(
            default_block_duration=300
        )

        self.total_queries = 0
        self.blocked_queries = 0
        self.failed_queries = 0

        self.stats_lock = threading.Lock()

    def create_alert(
        self,
        alert_type,
        client_ip,
        domain,
        severity,
        details
    ):

        try:
            self.alert_manager.raise_alert(
                alert_type,
                client_ip,
                domain,
                severity,
                details
            )
        except Exception as error:
            logger.error("Alert creation failed: %s", error)

    def make_response(self, data, rcode):

        request = DNSRecord.parse(data)

        response = request.reply()
        response.header.rcode = rcode

        return response.pack()

    def process_query(self, data, client_ip):

        start_time = time.time()

        domain = "unknown"
        status = "ERROR"

        try:

            # Parse incoming DNS packet.

            request = DNSRecord.parse(data)

            if not request.questions:
                status = "INVALID"

                return self.make_response(data, 1)

            question = request.questions[0]

            domain = str(question.qname).lower().rstrip(".")

            qtype = question.qtype
            qclass = question.qclass

            with self.stats_lock:
                self.total_queries += 1

            # Persistent IP block check.

            if is_ip_blocked(client_ip):

                with self.stats_lock:
                    self.blocked_queries += 1

                status = "BLOCKED"

                self.create_alert(
                    "blocked_ip_query",
                    client_ip,
                    domain,
                    "HIGH",
                    "Query received from a blocked IP"
                )

                return self.make_response(data, 5)

            # Rate limiting.

            allowed, retry_after = self.rate_limiter.allow_request(
                client_ip
            )

            if not allowed:

                with self.stats_lock:
                    self.blocked_queries += 1

                status = "RATE_LIMITED"

                self.create_alert(
                    "rate_limit_exceeded",
                    client_ip,
                    domain,
                    "HIGH",
                    {
                        "message": "Client exceeded DNS request rate",
                        "retry_after": retry_after
                    }
                )

                return self.make_response(data, 5)
                        # STIX and local blacklist detection

            if self.blacklist.is_blocked(domain):

                with self.stats_lock:
                    self.blocked_queries += 1

                is_stix = any(
                    domain == item or domain.endswith("." + item)
                    for item in self.stix_domains
                )

                category = (
                    "STIX_BLACKLIST"
                    if is_stix
                    else "LOCAL_BLACKLIST"
                )

                threat_event = {
                    "client_ip": client_ip,
                    "domain": domain,
                    "risk_score": 100,
                    "severity": "CRITICAL",
                    "category": category,
                    "is_suspicious": True,
                    "reasons": [
                        "Domain matched threat intelligence blacklist",
                        "DNS resolution blocked"
                    ]
                }

                try:
                    save_threat_event(threat_event)
                except Exception as error:
                    logger.error(
                        "Threat event storage failed: %s", error
                    )

                self.create_alert(
                    "threat_intelligence_block",
                    client_ip,
                    domain,
                    "CRITICAL",
                    threat_event
                )

                status = "BLOCKED"

                logger.warning(
                    "THREAT INTEL BLOCK | DOMAIN=%s | CATEGORY=%s",
                    domain,
                    category
                )

                return self.make_response(data, 3)

            # Advanced threat detection.

            threat_result = self.threat_detector.analyze(
                client_ip=client_ip,
                domain=domain,
                query_size=len(data),
                qtype=qtype
            )

            risk_score = threat_result["risk_score"]

            if threat_result["is_suspicious"]:

                threat_result["category"] = "ADVANCED_DNS_THREAT"

                try:
                    save_threat_event(threat_result)
                except Exception as error:
                    logger.error(
                        "Threat event storage failed: %s",
                        error
                    )

                self.create_alert(
                    "advanced_dns_threat",
                    client_ip,
                    domain,
                    threat_result["severity"],
                    threat_result
                )

                logger.warning(
                    "DNS THREAT | IP=%s | DOMAIN=%s | SCORE=%s",
                    client_ip,
                    domain,
                    risk_score
                )

            # Automatic IP blocking.

            if risk_score >= 90 and not is_ip_blocked(client_ip):

                self.response_manager.block_ip(
                    client_ip,
                    reason="Critical DNS threat score: " + str(risk_score),
                    duration=300
                )

                self.create_alert(
                    "automatic_ip_block",
                    client_ip,
                    domain,
                    "CRITICAL",
                    {
                        "risk_score": risk_score,
                        "reasons": threat_result["reasons"]
                    }
                )

                with self.stats_lock:
                    self.blocked_queries += 1

                status = "BLOCKED"

                return self.make_response(data, 5)

            # Cache key includes domain, query type and query class.

            cache_key = (
                domain,
                qtype,
                qclass
            )

            cached_response = self.cache.get(
                cache_key,
                request.header.id
            )

            if cached_response:

                status = "CACHED"

                return cached_response

            # Resolve through Cloudflare DNS.

            response = dns.query.udp(
                dns.message.from_wire(data),
                "1.1.1.1",
                timeout=3
            )

            response_data = response.to_wire()

            self.cache.set(
                cache_key,
                response_data
            )

            status = "SUCCESS"

            return response_data

        except Exception as error:

            logger.error(
                "DNS resolver error: %s",
                error
            )

            with self.stats_lock:
                self.failed_queries += 1

            status = "ERROR"

            try:
                return self.make_response(data, 2)
            except Exception:
                return b""

        finally:

            elapsed = time.time() - start_time

            try:
                save_query(
                    domain,
                    client_ip,
                    status,
                    elapsed
                )
            except Exception as error:

                logger.error(
                    "Could not save DNS query: %s",
                    error
                )

    def get_stats(self):

        with self.stats_lock:

            stats = {
                "total_queries": self.total_queries,
                "blocked_queries": self.blocked_queries,
                "failed_queries": self.failed_queries
            }

        stats["cache"] = self.cache.get_stats()

        return stats