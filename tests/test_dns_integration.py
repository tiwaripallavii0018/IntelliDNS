from dnslib import DNSRecord

domain = (
    "a8F3kL9pQ2xM7vN4bR8sT6yW1zA4bC7dE9fG2hJ5kL8mN1pQ4rS7tU"
    ".example.com"
)

print("Sending suspicious DNS request...")

try:
    request = DNSRecord.question(domain)

    response = request.send(
        "127.0.0.1",
        port=5353,
        timeout=5
    )

    result = DNSRecord.parse(response)

    print("DNS request sent successfully")
    print("Domain:", domain)
    print("Response code:", result.header.rcode)

except Exception as error:
    print("DNS integration test failed:", error)
