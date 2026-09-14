from scapy.all import sniff, TCP
import time
from netsentinel.connection_tracker import ConnectionTracker
from netsentinel.detectors.port_scan import PortScanDetector
from netsentinel.detectors.syn_flood import SynFloodDetector
from netsentinel.alert_manager import AlertManager
from netsentinel.database import Database
from dotenv import load_dotenv


database = Database(path=os.getenv("DATABASE_PATH"))
tracker = ConnectionTracker()
port_scan_detector = PortScanDetector(timeframe=int(os.getenv("PORT_SCAN_TIMEFRAME", 5)), threshold=int(os.getenv("PORT_SCAN_THRESHOLD", 5)))
syn_detector = SynFloodDetector(tracker=tracker, timeframe=int(os.getenv("SYN_FLOOD_TIMEFRAME", 5)), syn_rate_threshold=int(os.getenv("SYN_RATE_THRESHOLD", 5)), pending_threshold=int(os.getenv("SYN_PENDING_THRESHOLD", 5)))
alert_manager = AlertManager(database)


def packet_callback(packet):
    tracker.process(packet)
    alert_manager.handle(port_scan_detector.process(packet)) 
    alert_manager.handle(syn_detector.process(packet))

if __name__ == "__main__":
    sniff(iface="eth0", prn=packet_callback)
