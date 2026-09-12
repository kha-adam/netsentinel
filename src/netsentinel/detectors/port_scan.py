import time
from scapy.all import TCP

class PortScanDetector:
    def __init__(self, timeframe=5, threshold=10):
        self.timeframe = timeframe
        self.threshold = threshold
        self.syn_attempts = {}
        self.alert_cooldown = 10
        self.last_alert = {}

    def process(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            source = packet["IP"].src
            port = packet["TCP"].dport
            timestamp = time.time()

            if source not in self.syn_attempts:
                self.syn_attempts[source] = []
            self.syn_attempts[source].append((timestamp, port))

            while self.syn_attempts[source] and timestamp - self.syn_attempts[source][0][0] > self.timeframe:
                del self.syn_attempts[source][0]
            
            scanned_ports = {port for _, port in self.syn_attempts[source]}

            if len(scanned_ports) >= self.threshold:

                last_alert = self.last_alert.get(source)

                if last_alert == None or timestamp - self.last_alert[source] > self.alert_cooldown:
                    self.last_alert[source] = timestamp
                    
                    return {
                        "timestamp": timestamp,
                        "type": "PORT_SCAN",
                        "source": source,
                        "severity": "HIGH",
                        "details": {
                            "ports": list(scanned_ports),
                            "timeframe": self.timeframe
                        }
                    }
            
            return None