from security.rate_limiter import RateLimiter
from security.domain_analyzer import analyze_domain
from security.tunneling_detector import TunnelingDetector
from security.anomaly_detector import AnomalyDetector


# Test 1: Rate limiter

limiter = RateLimiter(
    max_requests=2,
    window_seconds=10
)

assert limiter.allow_request("127.0.0.1")[0] is True
assert limiter.allow_request("127.0.0.1")[0] is True
assert limiter.allow_request("127.0.0.1")[0] is False

print("PASS: Rate Limiter")


# Test 2: Suspicious domain detection

domain = (
    "a8F3kL9pQ2xM7vN4bR8sT6yW1zA4bC7dE9fG2hJ5kL8mN1pQ4rS7tU"
    ".example.com"
)

result = analyze_domain(domain)

assert result["is_suspicious"] is True

print("PASS: Domain Analyzer")


# Test 3: DNS tunneling detection

detector = TunnelingDetector()

result = detector.detect(domain)

assert result["is_tunneling"] is True

print("PASS: DNS Tunneling Detector")


# Test 4: Anomaly detection

anomaly = AnomalyDetector(
    window_seconds=60,
    max_unique_domains=3
)

anomaly.check_activity("127.0.0.1", "one.example.com")
anomaly.check_activity("127.0.0.1", "two.example.com")

result = anomaly.check_activity(
    "127.0.0.1",
    "three.example.com"
)

assert result["is_anomaly"] is True

print("PASS: Anomaly Detector")


print("\nALL SECURITY TESTS PASSED")