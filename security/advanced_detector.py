import math
import time
import threading

from collections import defaultdict, deque, Counter

from security.domain_analyzer import analyze_domain, calculate_entropy
from security.tunneling_detector import TunnelingDetector


class AdvancedThreatDetector:

    def __init__(
        self,
        window_seconds=60,
        max_requests=100,
        max_unique_domains=30
    ):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.max_unique_domains = max_unique_domains

        self.client_activity = defaultdict(deque)
        self.tunneling_detector = TunnelingDetector()

        self.lock = threading.Lock()

    def detect_dga(self, domain):
        domain = domain.lower().rstrip(".")
        labels = domain.split(".")

        score = 0
        reasons = []

        for label in labels[:-1]:
            if len(label) < 12:
                continue

            entropy = calculate_entropy(label)

            digits = sum(char.isdigit() for char in label)
            digit_ratio = digits / len(label)

            vowels = sum(
                char in "aeiou"
                for char in label
                if char.isalpha()
            )

            letters = sum(char.isalpha() for char in label)

            vowel_ratio = vowels / max(letters, 1)

            if entropy >= 3.7:
                score += 25
                reasons.append("High entropy domain label")

            if digit_ratio >= 0.30:
                score += 20
                reasons.append("High digit ratio in domain")

            if letters >= 10 and vowel_ratio < 0.15:
                score += 20
                reasons.append("Unusual consonant distribution")

        score = min(score, 100)

        return {
            "score": score,
            "is_suspicious": score >= 40,
            "reasons": reasons
        }

    def detect_query_behavior(
        self,
        client_ip,
        domain,
        query_size,
        qtype
    ):
        current_time = time.time()

        with self.lock:
            activity = self.client_activity[client_ip]

            while (
                activity
                and current_time - activity[0][0] >= self.window_seconds
            ):
                activity.popleft()

            activity.append((current_time, domain))

            request_count = len(activity)

            unique_domains = len({
                item[1] for item in activity
            })

        score = 0
        reasons = []

        if request_count > self.max_requests:
            score += 40
            reasons.append("Excessive DNS request rate")

        if unique_domains > self.max_unique_domains:
            score += 30
            reasons.append("High number of unique queried domains")

        if query_size > 1200:
            score += 25
            reasons.append("Unusually large DNS query packet")

        if qtype == 255 or str(qtype).upper() == "ANY":
            score += 20
            reasons.append("DNS ANY query detected")

        return {
            "score": min(score, 100),
            "request_count": request_count,
            "unique_domains": unique_domains,
            "reasons": reasons
        }

    def analyze(self, client_ip, domain, query_size, qtype):
        domain_result = analyze_domain(domain)

        tunneling_result = self.tunneling_detector.detect(domain)

        dga_result = self.detect_dga(domain)

        behavior_result = self.detect_query_behavior(
            client_ip,
            domain,
            query_size,
            qtype
        )

        score = (
            domain_result["risk_score"] * 0.30
            + tunneling_result["risk_score"] * 0.25
            + dga_result["score"] * 0.25
            + behavior_result["score"] * 0.20
        )

        score = min(round(score), 100)

        reasons = []

        reasons.extend(domain_result["reasons"])
        reasons.extend(tunneling_result["reasons"])
        reasons.extend(dga_result["reasons"])
        reasons.extend(behavior_result["reasons"])

        reasons = list(dict.fromkeys(reasons))

        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 35:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "domain": domain,
            "client_ip": client_ip,
            "risk_score": score,
            "severity": severity,
            "is_suspicious": score >= 35,
            "domain_analysis": domain_result,
            "tunneling_analysis": tunneling_result,
            "dga_analysis": dga_result,
            "behavior_analysis": behavior_result,
            "reasons": reasons
        }