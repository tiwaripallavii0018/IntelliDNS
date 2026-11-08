class DomainBlacklist:

    def __init__(self):

        self.domains = {
            "malware-test.example",
            "phishing-test.example",
            "c2-test.example"
        }

    def normalize(self, domain):

        return domain.lower().rstrip(".")

    def is_blocked(self, domain):

        domain = self.normalize(domain)

        for malicious_domain in self.domains:

            if (
                domain == malicious_domain
                or domain.endswith("." + malicious_domain)
            ):
                return True

        return False

    def add_domain(self, domain):

        self.domains.add(
            self.normalize(domain)
        )

    def add_domains(self, domains):

        for domain in domains:
            self.add_domain(domain)

    def remove_domain(self, domain):

        self.domains.discard(
            self.normalize(domain)
        )

    def get_domains(self):

        return sorted(self.domains)