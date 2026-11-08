import dns.message
import dns.query
import dns.rcode


SERVER = "127.0.0.1"
PORT = 5353


def test_domain(domain):

    query = dns.message.make_query(
        domain,
        "A"
    )

    try:

        response = dns.query.udp(
            query,
            SERVER,
            port=PORT,
            timeout=5
        )

        print("\nDomain:", domain)

        print(
            "Response:",
            dns.rcode.to_text(response.rcode())
        )

        for answer in response.answer:
            print("Answer:", answer)

    except Exception as error:

        print("Query failed:", error)


if __name__ == "__main__":

    # Legitimate domains
    test_domain("google.com")
    test_domain("example.com")

    # Original manually configured blacklist
    test_domain("malware-test.example")

    # Domains imported from STIX
    test_domain("feed-malware.example")
    test_domain("feed-phishing.example")

    # Subdomain of an imported malicious domain
    test_domain("sub.feed-malware.example")