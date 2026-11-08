import math
from collections import Counter


def calculate_entropy(value):

    if not value:
        return 0

    counts = Counter(value)
    length = len(value)

    entropy = 0

    for count in counts.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy


def analyze_domain(domain):

    domain = domain.lower().rstrip(".")

    labels = domain.split(".")

    score = 0
    reasons = []

    if len(labels) > 4:

        score += 15
        reasons.append("Excessive subdomains")

    for label in labels:

        if len(label) >= 50:

            score += 35
            reasons.append("Extremely long domain label")

        elif len(label) >= 30:

            score += 20
            reasons.append("Unusually long domain label")

        entropy = calculate_entropy(label)

        if len(label) >= 20 and entropy >= 3.5:

            score += 25
            reasons.append("High entropy domain label")

        digits = sum(char.isdigit() for char in label)

        if len(label) >= 15 and digits / len(label) > 0.5:

            score += 10
            reasons.append("Unusually high numeric character ratio")

    score = min(score, 100)

    return {
        "domain": domain,
        "risk_score": score,
        "is_suspicious": score >= 50,
        "reasons": list(set(reasons))
    }