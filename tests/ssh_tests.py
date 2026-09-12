from netsentinel.detectors.ssh_bruteforce import SSHBruteForceDetector
from netsentinel.log_reader import SSHLogReader
from netsentinel.alert_manager import AlertManager
from netsentinel.database import Database

database = Database()
reader = SSHLogReader()
ssh_bruteforce = SSHBruteForceDetector(threshold=3)
alert = AlertManager(database)

for event in reader.follow("tests/fake_auth.log"):
    alert.handle(ssh_bruteforce.process(event))

        


