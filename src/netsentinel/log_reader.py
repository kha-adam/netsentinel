import re
import time

class SSHLogReader:
    def parse_line(self, line):
        if "Failed password" not in line: return None

        match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        
        if not match: return None

        return {
            "type": "SSH_AUTH_FAILURE",
            "source": match.group(1)
        }

    def follow(self, path):
        with open(path, "r") as file:
            file.seek(0,2)

            while True:
                line = file.readline()

                if not line:
                    time.sleep(0.5)
                    continue
                event = self.parse_line(line)

                if event:
                    yield event

if __name__ == "__main__":
    line = "Sep 10 15:20:31 server sshd[1234]: Failed password for user from 192.168.1.50 port 54321 ssh2"

    reader = SSHLogReader()

    print(reader.parse_line(line))