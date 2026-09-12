from scapy.all import IP, TCP

from netsentinel.connection_tracker import ConnectionTracker


def test_tcp_handshake():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    syn = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="S")
    )

    syn_ack = (
        IP(src=server, dst=client)
        / TCP(sport=80, dport=50000, flags="SA")
    )

    ack = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="A")
    )

    tracker.process(syn)

    connection = tuple(sorted([
        (client, 50000),
        (server, 80)
    ]))

    assert tracker.connections[connection]["state"] == "SYN_SENT"

    tracker.process(syn_ack)

    assert tracker.connections[connection]["state"] == "SYN_RECEIVED"

    tracker.process(ack)

    assert tracker.connections[connection]["state"] == "ESTABLISHED"

def test_refused_connection():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    syn = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="S")
    )

    rst = (
        IP(src=server, dst=client)
        / TCP(sport=80, dport=50000, flags="RA")
    )

    tracker.process(syn)

    connection = tuple(sorted([
        (client, 50000),
        (server, 80)
    ]))

    assert tracker.connections[connection]["state"] == "SYN_SENT"

    tracker.process(rst)

    assert tracker.connections[connection]["state"] == "REFUSED"

def test_get_pending_connections():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    for i in range(3):

        syn = (
            IP(src=client, dst=server)
            / TCP(
                sport=50000 + i,
                dport=80 + i,
                flags="S"
            )
        )

        tracker.process(syn)

    assert tracker.get_pending(client) == 3


def test_get_pending_unknown_source():
    tracker = ConnectionTracker()

    assert tracker.get_pending("192.168.1.99") == 0

def test_duplicate_syn_is_ignored():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    syn = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="S")
    )

    tracker.process(syn)
    tracker.process(syn)

    connection = tuple(sorted([
        (client, 50000),
        (server, 80)
    ]))

    assert len(tracker.connections) == 1
    assert tracker.connections[connection]["state"] == "SYN_SENT"
    assert tracker.get_pending(client) == 1

def test_established_connection_not_pending():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    syn = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="S")
    )

    syn_ack = (
        IP(src=server, dst=client)
        / TCP(sport=80, dport=50000, flags="SA")
    )

    ack = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="A")
    )

    tracker.process(syn)
    tracker.process(syn_ack)
    tracker.process(ack)

    assert tracker.get_pending(client) == 0

def test_established_connection_not_pending():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    syn = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="S")
    )

    syn_ack = (
        IP(src=server, dst=client)
        / TCP(sport=80, dport=50000, flags="SA")
    )

    ack = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="A")
    )

    tracker.process(syn)
    tracker.process(syn_ack)
    tracker.process(ack)

    assert tracker.get_pending(client) == 0

def test_expired_handshake_is_removed():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    syn = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="S")
    )

    tracker.process(syn)

    connection = tuple(sorted([
        (client, 50000),
        (server, 80)
    ]))

    assert connection in tracker.connections

    # Pretend the SYN happened more than 60 seconds ago.
    old_timestamp = tracker.connections[connection]["time"] - 61

    # The cleanup queue contains the original timestamp,
    # so update it there as well.
    tracker.connection_queue[0] = (old_timestamp, connection)

    tracker.cleanup()

    assert connection not in tracker.connections

def test_established_connection_survives_cleanup():

    tracker = ConnectionTracker()

    client = "192.168.1.50"
    server = "192.168.1.100"

    syn = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="S")
    )

    syn_ack = (
        IP(src=server, dst=client)
        / TCP(sport=80, dport=50000, flags="SA")
    )

    ack = (
        IP(src=client, dst=server)
        / TCP(sport=50000, dport=80, flags="A")
    )

    tracker.process(syn)
    tracker.process(syn_ack)
    tracker.process(ack)

    connection = tuple(sorted([
        (client, 50000),
        (server, 80)
    ]))

    assert tracker.connections[connection]["state"] == "ESTABLISHED"

    # Pretend the connection is old.
    old_timestamp = tracker.connections[connection]["time"] - 61
    tracker.connection_queue[0] = (old_timestamp, connection)

    tracker.cleanup()

    assert connection in tracker.connections
    assert tracker.connections[connection]["state"] == "ESTABLISHED"