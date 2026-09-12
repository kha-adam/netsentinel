class AlertManager:
    def __init__(self, database):
        self.database = database

    def handle(self, alert):
        if alert:
            print(f"{alert}")
            self.database.save_alert(alert)
    