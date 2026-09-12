from netsentinel.detectors.ssh_bruteforce import SSHBruteForceDetector


def test_ssh_brute_force_detection():

    detector = SSHBruteForceDetector(
        timeframe=60,
        threshold=5
    )

    source = "192.168.1.50"

    alert = None

    for _ in range(5):

        event = {
            "type": "SSH_AUTH_FAILURE",
            "source": source
        }

        alert = detector.process(event)

    assert alert is not None
    assert alert["type"] == "SSH_BRUTEFORCE"
    assert alert["source"] == source