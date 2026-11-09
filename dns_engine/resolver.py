import logging
import time
import threading

import dns.message
import dns.query
import dns.rcode

from dnslib import DNSRecord

from monitoring.database import (
    initialize_database,
    save_query,
    is_ip_blocked
)

from security.alert_manager import AlertManager
from security.rate_limiter import RateLimiter
from security.domain_analyzer import analyze_domain
from security.tunneling_detector import TunnelingDetector
from security.anomaly_detector import AnomalyDetector


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

        self.cache = DNSCache()
        self.rate_limiter = RateLimiter()
        self.tunneling_detector = TunnelingDetector()
        self.anomaly_detector = AnomalyDetector()
        self.alert_manager = AlertManager()

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

            domain = str(question.qname).rstrip(".")
            qtype = question.qtype

            with self.stats_lock:
                self.total_queries += 1

            if is_ip_blocked(client_ip):
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

            if not self.rate_limiter.allow_request(client_ip):
                self.blocked_queries += 1
                status = "RATE_LIMITED"

                self.create_alert(
                    "rate_limit_exceeded",
                    client_ip,
                    domain,
                    "MEDIUM",
                    "Client exceeded DNS request rate"
                )

                return self.make_response(data, 5)

            try:
                analysis = analyze_domain(domain)

                if analysis:
                    if isinstance(analysis, dict) and analysis.get("suspicious"):
                        self.create_alert(
                            "suspicious_domain",
                            client_ip,
                            domain,
                            "HIGH",
                            analysis
                        )
            except Exception as error:
                logger.warning("Domain analysis error: %s", error)

            try:
                tunneling_result = self.tunneling_detector.detect(domain)

                if tunneling_result:
                    self.create_alert(
                        "dns_tunneling",
                        client_ip,
                        domain,
                        "HIGH",
                        str(tunneling_result)
                    )
            except Exception as error:
                logger.warning("Tunneling detection error: %s", error)

            try:
                anomaly_result = self.anomaly_detector.detect(
                    client_ip,
                    domain
                )

                if anomaly_result:
                    self.create_alert(
                        "dns_anomaly",
                        client_ip,
                        domain,
                        "MEDIUM",
                        str(anomaly_result)
                    )
            except Exception as error:
                logger.warning("Anomaly detection error: %s", error)

            cached_response = self.cache.get(domain, qtype)

            if cached_response:
                status = "CACHED"
                return cached_response

            response = dns.query.udp(
                dns.message.from_wire(data),
                "1.1.1.1",
                timeout=3
            )

            response_data = response.to_wire()

            self.cache.set(domain, qtype, response_data)

            status = "SUCCESS"

            return response_data

        except Exception as error:
            logger.error("DNS resolver error: %s", error)

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
                logger.error("Could not save DNS query: %s", error)

    def get_stats(self):
        with self.stats_lock:
            return {
                "total_queries": self.total_queries,
                "blocked_queries": self.blocked_queries,
                "failed_queries": self.failed_queries,
                "cache_entries": len(self.cache.cache)
            }