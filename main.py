import os
import logging
import socketserver

from dns_engine.query_handler import IntelliDNSResolver


os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/intellidns.log", encoding="utf-8")
    ]
)


class DNSHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data, sock = self.request
        client_ip = self.client_address[0]

        response = self.server.resolver.process_query(
            data,
            client_ip
        )

        if response:
            sock.sendto(response, self.client_address)


class ThreadedDNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    host = os.getenv("DNS_HOST", "0.0.0.0")
    port = int(os.getenv("DNS_PORT", "5353"))

    resolver = IntelliDNSResolver()

    server = ThreadedDNSServer(
        (host, port),
        DNSHandler
    )

    server.resolver = resolver

    print("=" * 50)
    print("       IntelliDNS DNS Security Server")
    print("=" * 50)
    print(f"Server running at {host}:{port}")
    print("Press CTRL+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping IntelliDNS...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()