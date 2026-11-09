import unittest
import time
from datetime import datetime, timedelta

from monitoring.database import (
    initialize_database,
    save_ip_block,
    is_ip_blocked,
    deactivate_ip_block,
    save_alert,
    create_incident,
    get_incident,
    acknowledge_incident,
    resolve_incident
)


class TestPhase5(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        initialize_database()

    def test_ip_block_and_unblock(self):
        ip = "192.0.2.10"

        expires_at = (
            datetime.now() + timedelta(seconds=60)
        ).strftime("%Y-%m-%d %H:%M:%S")

        save_ip_block(
            ip,
            "Phase 5 test",
            60,
            expires_at
        )

        self.assertTrue(is_ip_blocked(ip))

        deactivate_ip_block(ip)

        self.assertFalse(is_ip_blocked(ip))

    def test_incident_lifecycle(self):
        alert_id = save_alert(
            "test_alert",
            "192.0.2.20",
            "test.example",
            "HIGH",
            "Phase 5 incident test"
        )

        incident_id = create_incident(
            alert_id,
            "Test Incident",
            "Testing incident lifecycle",
            "192.0.2.20",
            "test.example",
            "HIGH"
        )

        incident = get_incident(incident_id)

        self.assertEqual(incident["status"], "OPEN")

        result = acknowledge_incident(incident_id)

        self.assertTrue(result)

        incident = get_incident(incident_id)

        self.assertEqual(incident["status"], "ACKNOWLEDGED")

        result = resolve_incident(
            incident_id,
            "Test completed"
        )

        self.assertTrue(result)

        incident = get_incident(incident_id)

        self.assertEqual(incident["status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()