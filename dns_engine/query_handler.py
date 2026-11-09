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

from security.alert_manager import AlertManager
from security.rate_limiter import RateLimiter
from security.advanced_detector import AdvancedThreatDetector
from security.response_manager import ThreatResponseManager


logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("IntelliDNS")


class DNSCache:

    def __init__(self, ttl=60):
        self.ttl = ttl
        self.cache = {}
        self.lock = threading.Lock()

    def get(self, domain, qtype):
        key = (domain, qtype)

        with self.lock:
            item = self.cache.get(key)

            if not item:
                return None

            data, expiry = item

            if time.time() > expiry:
                del self.cache[key]
                return None

            return data

    def set(self, domain, qtype, data):
        key = (domain, qtype)

        with self.lock:
            self.cache[key] = (
                data,
                time.time() + self.ttl
            )


class IntelliDNSResolver:

    def __init__(self):
        initialize_database()
        initialize_threat_store()

        self.cache = DNSCache()
        self.rate_limiter = RateLimiter()
        self.threat_detector = AdvancedThreatDetector()

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
        self.alert_manager.raise_alert(
            alert_type,
            client_ip,
            domain,
            severity,
            details
        )

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
            request = DNSRecord.parse(data)

            if not request.questions:
                return self.make_response(data, 1)

            question = request.questions[0]

            domain = str(question.qname).lower().rstrip(".")
            qtype = question.qtype

            with self.stats_lock:
                self.total_queries += 1

            # Check persistent IP blocks.

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

            # Correctly handle RateLimiter's tuple response.

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

            # Advanced threat analysis.

            threat_result = self.threat_detector.analyze(
                client_ip=client_ip,
                domain=domain,
                query_size=len(data),
                qtype=qtype
            )

            risk_score = threat_result["risk_score"]

            if threat_result["is_suspicious"]:

                threat_result["category"] = "ADVANCED_DNS_THREAT"

                save_threat_event(threat_result)

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

            # Automatically block only at very high risk.
            # Existing active blocks are not recreated.

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

            # Cache lookup.

            cached_response = self.cache.get(domain, qtype)

            if cached_response:
                cached_record = DNSRecord.parse(cached_response)

                # Preserve the current DNS transaction ID.
                cached_record.header.id = request.header.id

                status = "CACHED"

                return cached_record.pack()

            # Resolve through Cloudflare DNS.

            response = dns.query.udp(
                dns.message.from_wire(data),
                "1.1.1.1",
                timeout=3
            )

            response_data = response.to_wire()

            self.cache.set(
                domain,
                qtype,
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
            return {
                "total_queries": self.total_queries,
                "blocked_queries": self.blocked_queries,
                "failed_queries": self.failed_queries,
                "cache_entries": len(self.cache.cache)
            }