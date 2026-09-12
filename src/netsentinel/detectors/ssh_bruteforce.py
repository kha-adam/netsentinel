import time


class SSHBruteForceDetector:

    def __init__(self, timeframe=60, threshold=10):
        self.timeframe = timeframe
        self.threshold = threshold
        self.failures = {}
        self.alert_cooldown = 30
        self.last_alert = {}
    
    def process(self, event):
        if event["type"] == "SSH_AUTH_FAILURE":
            source = event["source"]
            timestamp = time.time()

            if source not in self.failures:
                self.failures[source] = []

            self.failures[source].append(timestamp)

            while self.failures and timestamp - self.failures[source][0] > self.timeframe:
                del self.failures[source][0]
            
            failures_rate = len(self.failures[source])
            
            if failures_rate >= self.threshold:
                last_alert = self.last_alert.get(source)
                if last_alert is None or timestamp - last_alert > self.alert_cooldown:
                    self.last_alert[source] = timestamp
                    return {
                        "timestamp": timestamp,
                        "type": "SSH_BRUTEFORCE",
                        "source": source,
                        "severity": "HIGH",
                        "details": {
                            "timeframe": self.timeframe,
                            "failures_rate": failures_rate
                        }
                    }
        return None


if __name__ == "__main__":
    detector = SSHBruteForceDetector(
        timeframe=15,
        threshold=5
    )

    for _ in range(5):
        event = {
            "type": "SSH_AUTH_FAILURE",
            "source": "192.168.1.50"
        }

        alert = detector.process(event)
        time.sleep(5)
        if alert:
            print(alert)