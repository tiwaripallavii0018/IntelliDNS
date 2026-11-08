
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
from monitoring.database import save_query


class IntelliDNSResolver:

    def __init__(self, upstream="1.1.1.1"):

        self.upstream = upstream

        # Initialize blacklist and DNS cache.
        self.blacklist = DomainBlacklist()
        self.cache = DNSCache()

        # Load local STIX threat intelligence.
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

    def process_query(self, data, client_ip):

        start_time = time.perf_counter()

        domain = "UNKNOWN"
        status = "ERROR"

        try:

            # Parse incoming DNS request.
            request = DNSRecord.parse(data)

            if not request.questions:
                return None

            question = request.questions[0]

            domain = str(question.qname).lower().rstrip(".")

            qtype = question.qtype
            qclass = question.qclass

            self.update_stats("total_queries")

            # 1. Check blacklist.
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

            # 2. Check DNS cache.
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

            # 3. Forward query to upstream DNS.
            upstream_request = dns.message.from_wire(data)

            upstream_response = dns.query.udp(
                upstream_request,
                self.upstream,
                timeout=3
            )

            response_data = upstream_response.to_wire()

            response = DNSRecord.parse(response_data)

            # Preserve client's DNS transaction ID.
            response.header.id = request.header.id

            # 4. Cache successful responses.
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

            # Save DNS activity in monitoring database.
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
                    error
                )

    def get_stats(self):

        with self.stats_lock:
            return self.stats.copy()
