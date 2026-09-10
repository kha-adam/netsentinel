from ..connection_tracker import ConnectionTracker 
import time
from scapy.all import TCP

class SynFloodDetector:
    def __init__(self, tracker, syn_rate_threshold = 10, pending_threshold = 10, timeframe = 60):
        self.tracker = tracker
        self.syn_rate_threshold = syn_rate_threshold
        self.pending_threshold = pending_threshold
        self.syn_attempts = {}
        self.timeframe = timeframe
        self.alert_cooldown = 30
        self.last_alert = {}
    
    def process(self, packet):
        if not (packet.haslayer(TCP) and packet[TCP].flags == "S"):
            return None

        timestamp = time.time()
        source = packet["IP"].src

        if source not in self.syn_attempts:
            self.syn_attempts[source] = []

        self.syn_attempts[source].append(timestamp)

        while self.syn_attempts[source] and timestamp - self.syn_attempts[source][0] >= self.timeframe:
            del self.syn_attempts[source][0]

        syn_rate = len(self.syn_attempts[source])
        pending = self.tracker.get_pending(source)

        if syn_rate >= self.syn_rate_threshold and pending >= self.pending_threshold:

            last_alert = self.last_alert.get(source)

            if last_alert is None or timestamp - last_alert > self.alert_cooldown:

                self.last_alert[source] = timestamp

                return {
                    "type": "SYN_FLOOD",
                    "source": source,
                    "severity": "HIGH",
                    "syn_rate": syn_rate,
                    "pending": pending,
                    "timeframe": self.timeframe
                }
        return None


