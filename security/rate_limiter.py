import time
import threading
from collections import defaultdict, deque


class RateLimiter:

    def __init__(self, max_requests=60, window_seconds=10):

        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self.requests = defaultdict(deque)
        self.lock = threading.Lock()

    def allow_request(self, client_ip):

        current_time = time.time()

        with self.lock:

            client_requests = self.requests[client_ip]

            while (
                client_requests
                and current_time - client_requests[0] >= self.window_seconds
            ):
                client_requests.popleft()

            if len(client_requests) >= self.max_requests:

                retry_after = (
                    self.window_seconds
                    - (current_time - client_requests[0])
                )

                return False, round(retry_after, 2)

            client_requests.append(current_time)

            return True, 0