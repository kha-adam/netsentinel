from scapy.all import IP, TCP

from netsentinel.detectors.syn_flood import SynFloodDetector


class FakeTracker:

    def get_pending(self, source):
        return 5


def test_syn_flood_detection():

    tracker = FakeTracker()

    detector = SynFloodDetector(
        tracker=tracker,
        timeframe=20,
        syn_rate_threshold=5,
        pending_threshold=5
    )

    source = "192.168.1.50"
    destination = "192.168.1.100"

    alert = None

    for i in range(5):

        packet = (
            IP(src=source, dst=destination)
            / TCP(
                sport=50000 + i,
                dport=80,
                flags="S"
            )
        )

        alert = detector.process(packet)

    assert alert is not None
    assert alert["type"] == "SYN_FLOOD"
    assert alert["source"] == source

def test_no_syn_flood_with_low_pending_connections():

    tracker = FakeTracker()

    # Only 2 pending connections, below the threshold of 5
    tracker.get_pending = lambda source: 2

    detector = SynFloodDetector(
        tracker=tracker,
        timeframe=20,
        syn_rate_threshold=5,
        pending_threshold=5
    )

    source = "192.168.1.50"
    destination = "192.168.1.100"

    alert = None

    for i in range(5):

        packet = (
            IP(src=source, dst=destination)
            / TCP(
                sport=50000 + i,
                dport=80,
                flags="S"
            )
        )

        alert = detector.process(packet)

    assert alert is None