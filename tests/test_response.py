
import time

from security.ip_blocklist import IPBlocklist


def test_ip_blocking():

    blocklist = IPBlocklist(default_duration=5)

    result = blocklist.block_ip(
        "192.168.1.100",
        reason="Testing"
    )

    assert result["blocked"] is True

    assert blocklist.is_blocked(
        "192.168.1.100"
    ) is True

    print("PASS: IP Blocking")


def test_ip_unblocking():

    blocklist = IPBlocklist()

    blocklist.block_ip("192.168.1.101")

    assert blocklist.unblock_ip(
        "192.168.1.101"
    ) is True

    assert blocklist.is_blocked(
        "192.168.1.101"
    ) is False

    print("PASS: IP Unblocking")


def test_ip_expiry():

    blocklist = IPBlocklist(default_duration=1)

    blocklist.block_ip("192.168.1.102")

    time.sleep(1.2)

    assert blocklist.is_blocked(
        "192.168.1.102"
    ) is False

    print("PASS: Automatic Expiry")


def test_blocked_ip_list():

    blocklist = IPBlocklist()

    blocklist.block_ip("192.168.1.103")

    result = blocklist.get_blocked_ips()

    assert len(result) == 1

    assert result[0]["ip"] == "192.168.1.103"

    print("PASS: Blocked IP Listing")


if __name__ == "__main__":

    test_ip_blocking()

    test_ip_unblocking()

    test_ip_expiry()

    test_blocked_ip_list()

    print("\nALL RESPONSE TESTS PASSED")
