from scapy.all import sniff, TCP
import time
from netsentinel.connection_tracker import ConnectionTracker
from netsentinel.detectors.port_scan import PortScanDetector
from netsentinel.detectors.syn_flood import SynFloodDetector
from netsentinel.alert_manager import AlertManager



tracker = ConnectionTracker()
port_scan_detector = PortScanDetector(timeframe=5, threshold=5)
syn_detector = SynFloodDetector(tracker=tracker, timeframe=20, syn_rate_threshold=5, pending_threshold=5)
alert_manager = AlertManager()


def packet_callback(packet):
    tracker.process(packet)
    alert_manager.handle(port_scan_detector.process(packet)) 
    alert_manager.handle(syn_detector.process(packet))

if __name__ == "__main__":
    sniff(iface="lo0", prn=packet_callback)
