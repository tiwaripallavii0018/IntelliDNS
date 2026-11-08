import time
import threading
from collections import defaultdict, deque


class AnomalyDetector:

    def __init__(self, window_seconds=60, max_unique_domains=25):

        self.window_seconds = window_seconds
        self.max_unique_domains = max_unique_domains

        self.activity = defaultdict(deque)
        self.lock = threading.Lock()

    def check_activity(self, client_ip, domain):

        current_time = time.time()

        with self.lock:

            client_activity = self.activity[client_ip]

            while (
                client_activity
                and current_time - client_activity[0][0] >= self.window_seconds
            ):
                client_activity.popleft()

            client_activity.append((current_time, domain))

            unique_domains = {
                item[1] for item in client_activity
            }

            reasons = []

            if len(unique_domains) >= self.max_unique_domains:

                reasons.append(
                    "High number of unique domains queried by client"
                )

            return {
                "is_anomaly": len(reasons) > 0,
                "unique_domains": len(unique_domains),
                "reasons": reasons
            }