import logging
import time
import threading
from pathlib import Path

import dns.message
import dns.query

from dnslib import DNSRecord

from dns_engine.cache import DNSCache
from threat_intelligence.blacklist import DomainBlacklist
from threat_intelligence.stix_feed import STIXFeedLoader

from monitoring.database import (
    initialize_database,
    save_query
)

from security.rate_limiter import RateLimiter
from security.domain_analyzer import analyze_domain
from security.tunneling_detector import TunnelingDetector
from security.anomaly_detector import AnomalyDetector
from security.alert_manager import AlertManager


class IntelliDNSResolver:

    def __init__(self, upstream="1.1.1.1"):

        self.upstream = upstream

        initialize_database()

        self.blacklist = DomainBlacklist()
        self.cache = DNSCache()

        # Load STIX threat intelligence.

        feed_path = (
            Path(__file__).resolve().parents[1]
            / "threat_intelligence"
            / "feeds"
            / "local_stix_bundle.json"
        )

        self.stix_loader = STIXFeedLoader()

        stix_domains = self.stix_loader.load_domains(
            feed_path
        )

        self.blacklist.add_domains(stix_domains)

        logging.info(
            "THREAT INTELLIGENCE READY | TOTAL DOMAINS=%d",
            len(self.blacklist.get_domains())
        )

        # Initialize security modules.

        self.rate_limiter = RateLimiter()

        self.tunneling_detector = TunnelingDetector()

        self.anomaly_detector = AnomalyDetector()

        self.alert_manager = AlertManager()

        # DNS statistics.

        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "allowed_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0
        }

        self.stats_lock = threading.Lock()

    def update_stats(self, key):

        with self.stats_lock:
            self.stats[key] += 1

    def create_alert(
        self,
        alert_type,
        client_ip,
        domain,
        severity,
        details
    ):

        try:

            created = self.alert_manager.raise_alert(
                alert_type,
                client_ip,
                domain,
                severity,
                details
            )

            if created:

                logging.warning(
                    "SECURITY ALERT | TYPE=%s | IP=%s | DOMAIN=%s",
                    alert_type,
                    client_ip,
                    domain
                )

        except Exception as error:

            logging.error(
                "ALERT ERROR | %s",
                str(error)
            )

    def process_query(self, data, client_ip):

        start_time = time.perf_counter()

        domain = "UNKNOWN"
        status = "ERROR"

        try:

            # Parse DNS request.

            request = DNSRecord.parse(data)

            if not request.questions:
                return None

            question = request.questions[0]

            domain = str(question.qname).lower().rstrip(".")

            qtype = question.qtype
            qclass = question.qclass

            self.update_stats("total_queries")

            # 1. Rate limiting.

            allowed, retry_after = (
                self.rate_limiter.allow_request(client_ip)
            )

            if not allowed:

                self.update_stats("blocked_queries")

                status = "BLOCKED"

                self.create_alert(
                    "RATE_LIMIT",
                    client_ip,
                    domain,
                    "HIGH",
                    {
                        "message": "Client exceeded DNS request limit",
                        "retry_after_seconds": retry_after
                    }
                )

                response = request.reply()

                response.header.rcode = 5

                logging.warning(
                    "RATE LIMITED | IP=%s | DOMAIN=%s",
                    client_ip,
                    domain
                )

                return response.pack()

            # 2. Suspicious domain analysis.

            domain_result = analyze_domain(domain)

            if domain_result["is_suspicious"]:

                severity = (
                    "HIGH"
                    if domain_result["risk_score"] >= 70
                    else "MEDIUM"
                )

                self.create_alert(
                    "SUSPICIOUS_DOMAIN",
                    client_ip,
                    domain,
                    severity,
                    domain_result
                )

            # 3. DNS tunneling detection.

            tunnel_result = self.tunneling_detector.detect(
                domain
            )

            if tunnel_result["is_tunneling"]:

                self.create_alert(
                    "DNS_TUNNELING",
                    client_ip,
                    domain,
                    "HIGH",
                    tunnel_result
                )

            # 4. Client anomaly detection.

            anomaly_result = self.anomaly_detector.check_activity(
                client_ip,
                domain
            )

            if anomaly_result["is_anomaly"]:

                self.create_alert(
                    "ANOMALOUS_ACTIVITY",
                    client_ip,
                    domain,
                    "MEDIUM",
                    anomaly_result
                )

            # 5. Check existing blacklist.

            if self.blacklist.is_blocked(domain):

                response = request.reply()

                response.header.rcode = 3

                self.update_stats("blocked_queries")

                status = "BLOCKED"

                logging.warning(
                    "BLOCKED | IP=%s | DOMAIN=%s",
                    client_ip,
                    domain
                )

                return response.pack()

            # 6. Check DNS cache.

            cache_key = (domain, qtype, qclass)

            cached_response = self.cache.get(
                cache_key,
                request.header.id
            )

            if cached_response is not None:

                self.update_stats("cache_hits")
                self.update_stats("allowed_queries")

                status = "ALLOWED"

                logging.info(
                    "CACHE HIT | IP=%s | DOMAIN=%s",
                    client_ip,
                    domain
                )

                return cached_response

            self.update_stats("cache_misses")

            # 7. Forward request to upstream DNS.

            upstream_request = dns.message.from_wire(data)

            upstream_response = dns.query.udp(
                upstream_request,
                self.upstream,
                timeout=3
            )

            response_data = upstream_response.to_wire()

            response = DNSRecord.parse(response_data)

            response.header.id = request.header.id

            # 8. Cache successful response.

            self.cache.set(
                cache_key,
                response.pack()
            )

            self.update_stats("allowed_queries")

            status = "ALLOWED"

            logging.info(
                "ALLOWED | IP=%s | DOMAIN=%s",
                client_ip,
                domain
            )

            return response.pack()

        except Exception as error:

            self.update_stats("errors")

            status = "ERROR"

            logging.error(
                "DNS ERROR | IP=%s | ERROR=%s",
                client_ip,
                str(error)
            )

            try:

                request = DNSRecord.parse(data)

                response = request.reply()

                response.header.rcode = 2

                return response.pack()

            except Exception:

                return None

        finally:

            elapsed = (
                time.perf_counter() - start_time
            ) * 1000

            logging.info(
                "QUERY TIME | IP=%s | %.2f ms",
                client_ip,
                elapsed
            )

            try:

                save_query(
                    domain,
                    client_ip,
                    status,
                    round(elapsed, 2)
                )

            except Exception as error:

                logging.error(
                    "MONITORING ERROR | %s",
                    str(error)
                )

    def get_stats(self):

        with self.stats_lock:
            return self.stats.copy()