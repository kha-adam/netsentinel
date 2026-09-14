from scapy.all import IP, TCP, send
import time

target = "127.0.0.1"

for port in range(10000, 10020):
    packet = IP(dst=target) / TCP(
        sport=40000 + port,
        dport=port,
        flags="S"
    )

    send(packet, verbose=False)
    time.sleep(0.1)