import time
from datetime import datetime

from monitoring.database import (
    save_ip_block,
    deactivate_ip_block,
    get_active_ip_blocks,
    is_ip_blocked,
    create_incident
)


class ThreatResponseManager:

    def __init__(self, default_block_duration=300):
        self.default_block_duration = default_block_duration

    def block_ip(
        self,
        client_ip,
        reason="Suspicious activity",
        duration=None
    ):
        if duration is None:
            duration = self.default_block_duration

        duration = int(duration)

        if duration < 1 or duration > 86400:
            raise ValueError("Duration must be between 1 and 86400 seconds")

        expires_timestamp = time.time() + duration

        expires_at = datetime.fromtimestamp(
            expires_timestamp
        ).strftime("%Y-%m-%d %H:%M:%S")

        save_ip_block(
            client_ip,
            reason,
            duration,
            expires_at
        )

        return {
            "message": "IP blocked successfully",
            "ip": client_ip,
            "reason": reason,
            "duration": duration,
            "expires_at": expires_at
        }

    def is_blocked(self, client_ip):
        return is_ip_blocked(client_ip)

    def unblock_ip(self, client_ip):
        return deactivate_ip_block(client_ip)

    def get_blocked_ips(self):
        return get_active_ip_blocks()

    def create_incident(
        self,
        alert_id,
        alert_type,
        client_ip,
        domain,
        severity,
        details
    ):
        title = alert_type.replace("_", " ")

        return create_incident(
            alert_id,
            title,
            str(details),
            client_ip,
            domain,
            severity
        )