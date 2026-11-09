import time
import threading

from dnslib import DNSRecord


class DNSCache:

    def __init__(self, max_size=10000):
        self.cache = {}
        self.max_size = max_size
        self.lock = threading.Lock()

        self.hits = 0
        self.misses = 0

    def get(self, key, request_id):

        with self.lock:

            entry = self.cache.get(key)

            if entry is None:
                self.misses += 1
                return None

            response_data, created_at, ttl = entry

            elapsed = time.time() - created_at

            if elapsed >= ttl:
                del self.cache[key]
                self.misses += 1
                return None

            response = DNSRecord.parse(response_data)

            response.header.id = request_id

            remaining = max(0, int(ttl - elapsed))

            for section in (
                response.rr,
                response.auth,
                response.ar
            ):
                for record in section:
                    record.ttl = min(record.ttl, remaining)

            self.hits += 1

            return response.pack()

    def set(self, key, response_data):

        response = DNSRecord.parse(response_data)

        if response.header.rcode != 0 or not response.rr:
            return

        ttl = min(record.ttl for record in response.rr)

        if ttl <= 0:
            return

        with self.lock:

            if key not in self.cache and len(self.cache) >= self.max_size:
                if self.cache:
                    oldest_key = next(iter(self.cache))
                    del self.cache[oldest_key]

            self.cache[key] = (
                response_data,
                time.time(),
                ttl
            )

    def clear(self):

        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    def get_stats(self):

        with self.lock:
            return {
                "entries": len(self.cache),
                "hits": self.hits,
                "misses": self.misses
            }