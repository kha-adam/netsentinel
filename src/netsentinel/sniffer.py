from scapy.all import sniff, TCP
import time

connections = {}
syn_attempts = {}

def packet_callback(packet):
    timeframe = 5

    if packet.haslayer(TCP):
        endpoint1 = (packet["IP"].src, packet["TCP"].sport)
        endpoint2 = (packet["IP"].dst, packet["TCP"].dport)
        connection = tuple(sorted([endpoint1, endpoint2]))

        if "S" == packet[TCP].flags:
            if connection not in connections:
                connections[connection] = {
                    "state": "SYN_SENT",
                    "time" : time.time()
                }

            source = packet["IP"].src

            if source not in syn_attempts:
                syn_attempts[source] = []

            timestamp = time.time()
            dport = packet["IP"].dport
            syn_attempts[source].append((timestamp, dport))

            while timestamp - syn_attempts[source][0][0] > timeframe:
                del syn_attempts[source][0]

            ports = {port for timestamp, port in syn_attempts[source]}
            #print(ports)
            if len(ports) >= 10:
                print(f"Possible port scan from {source}: {ports}")

            # print(f"{source} has tryed to SYN at port {dport}. Tried to connect {len(syn_attempts[source])} times in the past {timeframe} seconds")

        elif "SA" == packet[TCP].flags and connection in connections:
            connections[connection]["state"] = "SYN_RECEIVED"

        elif "A" == packet[TCP].flags and connection in connections:
            connections[connection]["state"] = "ESTABLISHED"

        if connection in connections:
            elapsed = time.time() - connections[connection]["time"]
            #print(f"Connection: {connection} -> {connections[connection]} : {elapsed}")

if __name__ == "__main__":
    sniff(iface="lo0", prn=packet_callback)