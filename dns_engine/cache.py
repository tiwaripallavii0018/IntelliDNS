import time
import threading

from dnslib import DNSRecord


class DNSCache:

    def __init__(self, max_size=10000):

        self.cache = {}
        self.max_size = max_size
        self.lock = threading.Lock()

    def get(self, key, request_id):

        with self.lock:

            entry = self.cache.get(key)

            if entry is None:
                return None

            response_data, created_at, ttl = entry

            elapsed = time.time() - created_at

            if elapsed >= ttl:
                del self.cache[key]
                return None

            response = DNSRecord.parse(response_data)

            # DNS transaction ID must match the current request.
            response.header.id = request_id

            # Reduce the remaining TTL.
            remaining = max(0, int(ttl - elapsed))

            for record in response.rr:
                record.ttl = min(record.ttl, remaining)

            return response.pack()

    def set(self, key, response_data):

        response = DNSRecord.parse(response_data)

        # Cache only successful responses with answer records.
        if response.header.rcode != 0 or not response.rr:
            return

        ttl = min(record.ttl for record in response.rr)

        if ttl <= 0:
            return

        with self.lock:

            if len(self.cache) >= self.max_size:
                self.cache.pop(next(iter(self.cache)))

            self.cache[key] = (
                response_data,
                time.time(),
                ttl
            )

    def clear(self):

        with self.lock:
            self.cache.clear()