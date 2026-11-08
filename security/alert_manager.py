import time
import threading

from monitoring.database import save_alert


class AlertManager:

    def __init__(self, cooldown_seconds=60):

        self.cooldown_seconds = cooldown_seconds

        self.last_alerts = {}

        self.lock = threading.Lock()

    def raise_alert(
        self,
        alert_type,
        client_ip,
        domain,
        severity,
        details
    ):

        current_time = time.time()

        alert_key = (
            alert_type,
            client_ip,
            domain
        )

        with self.lock:

            last_time = self.last_alerts.get(alert_key, 0)

            if current_time - last_time < self.cooldown_seconds:

                return False

            self.last_alerts[alert_key] = current_time

        save_alert(
            alert_type,
            client_ip,
            domain,
            severity,
            details
        )

        return True