import json
import logging
import re

from datetime import datetime, timezone


class STIXFeedLoader:

    DOMAIN_PATTERN = re.compile(
        r"\[\s*domain-name:value\s*=\s*(['\"])(.*?)\1\s*\]",
        re.IGNORECASE
    )

    def parse_timestamp(self, value):

        if not value:
            return None

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

        except (ValueError, TypeError):
            return None

    def load_domains(self, file_path):

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                bundle = json.load(file)

        except (OSError, json.JSONDecodeError) as error:

            logging.error(
                "STIX FEED ERROR | %s",
                error
            )

            return set()

        if bundle.get("type") != "bundle":
            logging.error("Invalid STIX bundle.")
            return set()

        domains = set()

        now = datetime.now(timezone.utc)

        for indicator in bundle.get("objects", []):

            if indicator.get("type") != "indicator":
                continue

            if indicator.get("revoked", False):
                continue

            if indicator.get("pattern_type") != "stix":
                continue

            valid_from = self.parse_timestamp(
                indicator.get("valid_from")
            )

            valid_until = self.parse_timestamp(
                indicator.get("valid_until")
            )

            if valid_from is None:
                continue

            if valid_from > now:
                continue

            if valid_until is not None and valid_until <= now:
                continue

            pattern = indicator.get("pattern", "")

            matches = self.DOMAIN_PATTERN.findall(pattern)

            for _, domain in matches:

                domain = domain.lower().rstrip(".")

                if domain:
                    domains.add(domain)

        logging.info(
            "STIX FEED PROCESSED | DOMAINS=%d",
            len(domains)
        )

        return domains