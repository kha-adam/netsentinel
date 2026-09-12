from scapy.all import IP, TCP

from netsentinel.detectors.port_scan import PortScanDetector


def test_port_scan_detection():

    detector = PortScanDetector(
        timeframe=5,
        threshold=5
    )

    source = "192.168.1.50"
    destination = "192.168.1.100"

    alert = None

    for port in [21, 22, 23, 80, 443]:

        packet = (
            IP(src=source, dst=destination)
            / TCP(
                sport=50000 + port,
                dport=port,
                flags="S"
            )
        )

        alert = detector.process(packet)
    assert alert is not None
    assert alert["type"] == "PORT_SCAN"
    assert alert["source"] == source
    
def test_no_port_scan_for_same_port():

    detector = PortScanDetector(
        timeframe=5,
        threshold=5
    )

    source = "192.168.1.50"
    destination = "192.168.1.100"

    alert = None

    for i in range(5):

        packet = (
            IP(src=source, dst=destination)
            / TCP(
                sport=50000 + i,
                dport=443,
                flags="S"
            )
        )

        alert = detector.process(packet)

    assert alert is None

def test_port_scan_below_threshold():

    detector = PortScanDetector(
        timeframe=5,
        threshold=5
    )

    source = "192.168.1.50"
    destination = "192.168.1.100"

    alert = None

    for port in [21, 22, 80, 443]:

        packet = (
            IP(src=source, dst=destination)
            / TCP(
                sport=50000 + port,
                dport=port,
                flags="S"
            )
        )

        alert = detector.process(packet)

    assert alert is None