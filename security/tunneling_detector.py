from security.domain_analyzer import calculate_entropy


class TunnelingDetector:

    def detect(self, domain):

        domain = domain.lower().rstrip(".")

        labels = domain.split(".")

        score = 0
        reasons = []

        for label in labels:

            entropy = calculate_entropy(label)

            if len(label) >= 50:

                score += 50
                reasons.append("Very long DNS label")

            elif len(label) >= 35 and entropy >= 3.5:

                score += 40
                reasons.append("Long encoded-looking DNS label")

            elif len(label) >= 25 and entropy >= 4.0:

                score += 25
                reasons.append("High entropy DNS label")

        if len(labels) >= 6:

            score += 20
            reasons.append("Unusually deep DNS subdomain")

        score = min(score, 100)

        return {
            "is_tunneling": score >= 50,
            "risk_score": score,
            "reasons": list(set(reasons))
        }