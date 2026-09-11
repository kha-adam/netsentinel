import re

class SSHLogReader:
    def parse_line(self, line):
        if "Failed password" not in line: return None

        match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        
        if not match: return None

        return {
            "event": "SSH_AUTH_FAILURE",
            "source": match.group(1)
        }


if __name__ == "__main__":
    line = "Sep 10 15:20:31 server sshd[1234]: Failed password for user from 192.168.1.50 port 54321 ssh2"

    reader = SSHLogReader()

    print(reader.parse_line(line))