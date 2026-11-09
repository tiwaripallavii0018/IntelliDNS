import unittest
from unittest.mock import patch

from dnslib import DNSRecord, RR, A

from dns_engine.cache import DNSCache


class TestDNSCache(unittest.TestCase):

    def create_response(self, ttl=30):

        request = DNSRecord.question("example.com")

        response = request.reply()

        response.add_answer(
            RR(
                "example.com",
                rtype=1,
                ttl=ttl,
                rdata=A("93.184.216.34")
            )
        )

        return response.pack()

    def test_cache_hit(self):

        cache = DNSCache()

        response = self.create_response()

        cache.set(("example.com", 1, 1), response)

        result = cache.get(("example.com", 1, 1), 1234)

        self.assertIsNotNone(result)

        parsed = DNSRecord.parse(result)

        self.assertEqual(parsed.header.id, 1234)

        print("PASS: Cache Hit")

    def test_cache_miss(self):

        cache = DNSCache()

        result = cache.get(("missing.com", 1, 1), 1234)

        self.assertIsNone(result)

        print("PASS: Cache Miss")

    def test_ttl_expiry(self):

        cache = DNSCache()

        response = self.create_response(ttl=30)

        with patch(
            "dns_engine.cache.time.time",
            side_effect=[100, 131]
        ):
            cache.set(("example.com", 1, 1), response)

            result = cache.get(("example.com", 1, 1), 1234)

        self.assertIsNone(result)

        print("PASS: Cache TTL Expiry")

    def test_remaining_ttl(self):

        cache = DNSCache()

        response = self.create_response(ttl=30)

        with patch(
            "dns_engine.cache.time.time",
            side_effect=[100, 105]
        ):
            cache.set(("example.com", 1, 1), response)

            result = cache.get(("example.com", 1, 1), 1234)

        parsed = DNSRecord.parse(result)

        self.assertEqual(parsed.rr[0].ttl, 25)

        print("PASS: Remaining TTL Calculation")

    def test_transaction_id(self):

        cache = DNSCache()

        response = self.create_response()

        cache.set(("example.com", 1, 1), response)

        result = cache.get(("example.com", 1, 1), 5678)

        parsed = DNSRecord.parse(result)

        self.assertEqual(parsed.header.id, 5678)

        print("PASS: DNS Transaction ID")

    def test_cache_max_size(self):

        cache = DNSCache(max_size=1)

        response = self.create_response()

        cache.set(("first.com", 1, 1), response)
        cache.set(("second.com", 1, 1), response)

        self.assertEqual(len(cache.cache), 1)

        self.assertIsNone(
            cache.get(("first.com", 1, 1), 1234)
        )

        print("PASS: Cache Maximum Size")

    def test_cache_clear(self):

        cache = DNSCache()

        response = self.create_response()

        cache.set(("example.com", 1, 1), response)

        cache.clear()

        self.assertEqual(len(cache.cache), 0)

        print("PASS: Cache Clear")

    def test_nxdomain_not_cached(self):

        cache = DNSCache()

        request = DNSRecord.question("missing.example")

        response = request.reply()
        response.header.rcode = 3

        cache.set(
            ("missing.example", 1, 1),
            response.pack()
        )

        result = cache.get(
            ("missing.example", 1, 1),
            1234
        )

        self.assertIsNone(result)

        print("PASS: NXDOMAIN Not Cached")


if __name__ == "__main__":

    unittest.main()