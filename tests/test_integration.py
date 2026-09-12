from scapy.all import IP, TCP

from netsentinel.connection_tracker import ConnectionTracker
from netsentinel.detectors.port_scan import PortScanDetector
from netsentinel.detectors.syn_flood import SynFloodDetector
from netsentinel.database import Database
from netsentinel.alert_manager import AlertManager


def test_port_scan_pipeline(tmp_path):

    database = Database(str(tmp_path / "test.db"))
    alert_manager = AlertManager(database)

    tracker = ConnectionTracker()

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

        tracker.process(packet)

        alert = detector.process(packet)

        if alert:
            alert_manager.handle(alert)

    alerts = database.get_alerts()

    assert len(alerts) == 1
    assert alerts[0]["type"] == "PORT_SCAN"
    assert alerts[0]["source"] == source



def test_syn_flood_pipeline(tmp_path):

    database = Database(str(tmp_path / "test.db"))
    alert_manager = AlertManager(database)

    tracker = ConnectionTracker()

    detector = SynFloodDetector(
        tracker=tracker,
        timeframe=20,
        syn_rate_threshold=5,
        pending_threshold=5
    )

    source = "192.168.1.50"
    destination = "192.168.1.100"

    for i in range(5):

        packet = (
            IP(src=source, dst=destination)
            / TCP(
                sport=50000 + i,
                dport=80,
                flags="S"
            )
        )

        tracker.process(packet)

        alert = detector.process(packet)

        if alert:
            alert_manager.handle(alert)

    alerts = database.get_alerts()

    assert len(alerts) == 1
    assert alerts[0]["type"] == "SYN_FLOOD"
    assert alerts[0]["source"] == source