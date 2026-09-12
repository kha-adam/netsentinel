from netsentinel.log_reader import SSHLogReader


def test_parse_failed_ssh_login():

    reader = SSHLogReader()

    line = (
        "Sep 12 10:15:32 server sshd[1234]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 54321 ssh2"
    )

    event = reader.parse_line(line)

    assert event is not None
    assert event["type"] == "SSH_AUTH_FAILURE"
    assert event["source"] == "192.168.1.50"
    
def test_ignore_unrelated_log_line():

    reader = SSHLogReader()

    line = "Sep 12 10:15:32 server systemd[1]: Started some service."

    event = reader.parse_line(line)

    assert event is None