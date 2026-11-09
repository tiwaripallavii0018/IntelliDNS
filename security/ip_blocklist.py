
import time
import threading


class IPBlocklist:

    def __init__(self, default_duration=300):

        self.default_duration = default_duration
        self.blocked_ips = {}
        self.lock = threading.Lock()

    def block_ip(self, ip, duration=None, reason="Security policy"):

        if duration is None:
            duration = self.default_duration

        duration = max(1, int(duration))

        expiry = time.time() + duration

        with self.lock:
            self.blocked_ips[ip] = {
                "expires_at": expiry,
                "reason": reason
            }

        return {
            "ip": ip,
            "blocked": True,
            "duration": duration,
            "expires_at": expiry,
            "reason": reason
        }

    def is_blocked(self, ip):

        with self.lock:

            entry = self.blocked_ips.get(ip)

            if entry is None:
                return False

            if time.time() >= entry["expires_at"]:

                del self.blocked_ips[ip]

                return False

            return True

    def unblock_ip(self, ip):

        with self.lock:

            if ip in self.blocked_ips:

                del self.blocked_ips[ip]

                return True

            return False

    def get_blocked_ips(self):

        current_time = time.time()

        with self.lock:

            expired_ips = [
                ip
                for ip, entry in self.blocked_ips.items()
                if current_time >= entry["expires_at"]
            ]

            for ip in expired_ips:
                del self.blocked_ips[ip]

            result = []

            for ip, entry in self.blocked_ips.items():

                remaining = max(
                    0,
                    int(entry["expires_at"] - current_time)
                )

                result.append({
                    "ip": ip,
                    "expires_at": entry["expires_at"],
                    "remaining_seconds": remaining,
                    "reason": entry["reason"]
                })

            return result
