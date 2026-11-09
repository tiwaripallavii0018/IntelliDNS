import time
import threading

from collections import defaultdict, deque

from security.ip_blocklist import IPBlocklist


class ResponseEngine:

    def __init__(
        self,
        block_duration=300,
        violation_limit=3,
        window_seconds=30
    ):

        self.blocklist = IPBlocklist(block_duration)

        self.violation_limit = violation_limit
        self.window_seconds = window_seconds

        self.violations = defaultdict(deque)

        self.lock = threading.Lock()

    def record_violation(self, client_ip, reason):

        current_time = time.time()

        with self.lock:

            client_violations = self.violations[client_ip]

            while (
                client_violations
                and current_time - client_violations[0] >= self.window_seconds
            ):

                client_violations.popleft()

            client_violations.append(current_time)

            count = len(client_violations)

            if count >= self.violation_limit:

                client_violations.clear()

                self.blocklist.block_ip(
                    client_ip,
                    reason=reason
                )

                return True

            return False

    def is_blocked(self, client_ip):

        return self.blocklist.is_blocked(client_ip)

    def block_ip(self, client_ip, duration=300, reason="Manual block"):

        return self.blocklist.block_ip(
            client_ip,
            duration,
            reason
        )

    def unblock_ip(self, client_ip):

        return self.blocklist.unblock_ip(client_ip)

    def get_blocked_ips(self):

        return self.blocklist.get_blocked_ips()

    def get_block_history(self):

        return self.blocklist.get_block_history()