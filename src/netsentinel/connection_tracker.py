from collections import deque
from scapy.all import TCP
import time
import threading

class ConnectionTracker:

    def __init__(self):

        self.connections = {}
        self.connection_queue = deque()
        self.connections_lock = threading.Lock()
        self.queue_lock = threading.Lock()

        cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
        cleanup_thread.start()


    def process(self, packet):    
        timestamp = time.time()

        if packet.haslayer(TCP):
            source = packet["IP"].src
            dport = packet["TCP"].dport
            endpoint1 = (packet["IP"].src, packet["TCP"].sport)
            endpoint2 = (packet["IP"].dst, packet["TCP"].dport)
            connection = tuple(sorted([endpoint1, endpoint2]))

            if "S" == packet[TCP].flags:
                with self.connections_lock:
                    if connection in self.connections:
                        return
                    self.connections[connection] = {
                        "state": "SYN_SENT",
                        "time": timestamp,
                        "initiator": source,
                        "port": dport
                    }
                with self.queue_lock:
                    self.connection_queue.append((timestamp, connection))

            elif "SA" == packet[TCP].flags:
                with self.connections_lock:
                    if connection in self.connections:
                        self.connections[connection]["state"] = "SYN_RECEIVED"

            elif "A" == packet[TCP].flags:
                with self.connections_lock:
                    if connection in self.connections:
                        self.connections[connection]["state"] = "ESTABLISHED"

            elif "R" in packet[TCP].flags:
                with self.connections_lock:
                    if connection in self.connections:
                        self.connections[connection]["state"] = "REFUSED"

    def cleanup(self):
        while True:
            with self.queue_lock:
                if not self.connection_queue:
                    break
                timestamp, connection = self.connection_queue[0]
                if time.time() - timestamp <= 10:
                    break
            self.connection_queue.popleft()
            
            with self.connections_lock:
                conn = self.connections.get(connection)
                if conn and conn["state"] in ["SYN_SENT", "SYN_RECEIVED"]:
                    self.connections.pop(connection, None)
                    print(f"Expired handshake: {connection}")


    def cleanup_loop(self):
        while True:
            self.cleanup()
            time.sleep(5)


    def get_pending(self, initiator):
        with self.connections_lock:
            pending = sum(
                conn["initiator"] == initiator and conn["state"] in ["SYN_SENT", "SYN_RECEIVED", "REFUSED"] for conn in self.connections.values()
            )
        return pending       