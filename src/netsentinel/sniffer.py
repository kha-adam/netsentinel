from scapy.all import sniff, TCP
import time
from collections import deque
import threading

connections = {}
connection_queue = deque()
syn_attempts = {}
connections_lock = threading.Lock()
queue_lock = threading.Lock()

def cleanup_connections():
    while connection_queue:
        with queue_lock:
            timestamp, connection = connection_queue[0]
            if time.time() - timestamp <= 10:
                break
            
            connection_queue.popleft()
        with connections_lock:
            conn = connections.get(connection)
            if conn and conn["state"] in ["SYN_SENT", "SYN_RECEIVED", "REFUSED"]:
                connections.pop(connection, None)
                print(f"Expired handshake: {connection}")

def cleanup_loop():
    while True:
        cleanup_connections()
        time.sleep(5)

def packet_callback(packet):
    timeframe = 5
    
    timestamp = time.time()

    if packet.haslayer(TCP):
        source = packet["IP"].src
        initiator = None
        dport = packet["TCP"].dport
        endpoint1 = (packet["IP"].src, packet["TCP"].sport)
        endpoint2 = (packet["IP"].dst, packet["TCP"].dport)
        connection = tuple(sorted([endpoint1, endpoint2]))


        if "S" == packet[TCP].flags:
            with connections_lock:
                if connection not in connections:
                    connections[connection] = {
                        "state": "SYN_SENT",
                        "time": time.time(),
                        "initiator": source,
                        "port": dport
                    }
            with queue_lock:
                connection_queue.append((timestamp, connection))

            if source not in syn_attempts:
                syn_attempts[source] = []

            syn_attempts[source].append((timestamp, dport))

            while timestamp - syn_attempts[source][0][0] > timeframe:
                del syn_attempts[source][0]

            scanned_ports = {port for timestamp, port in syn_attempts[source]}
            
            if len(scanned_ports) >= 10:
                print(f"Possible port scan from {source} on {scanned_ports}")
                print(f"Ports scanned: {len(scanned_ports)}")
                print(f"Window: {timeframe}s")

            initiator = source

        elif "SA" == packet[TCP].flags:
            initiator = packet["IP"].dst
            with connections_lock:
                if connection in connections:
                    connections[connection]["state"] = "SYN_RECEIVED"

        elif "A" == packet[TCP].flags:
            initiator = source
            with connections_lock:
                if connection in connections:
                    connections[connection]["state"] = "ESTABLISHED"

        elif "R" in packet[TCP].flags:
            initiator = packet["IP"].dst
            with connections_lock:
                if connection in connections:
                    connections[connection]["state"] = "REFUSED"
        
        with connections_lock:
            pending = sum(
                conn["initiator"] == initiator and conn["state"] == "SYN_SENT" for conn in connections.values()
            )

            accepted = sum(
                conn["initiator"] == initiator and conn["state"] == "ESTABLISHED" for conn in connections.values()
            )

            refused = sum(
                conn["initiator"] == initiator and conn["state"] == "REFUSED" for conn in connections.values()
            )
        if pending + accepted + refused >= 10:
                print(f"Possible port scan from {source}: \nPending: {pending}, \nAccepted: {accepted}, \nRefused: {refused}")
                print(f"Window: {timeframe}s")
if __name__ == "__main__":
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()
    sniff(iface="lo0", prn=packet_callback)