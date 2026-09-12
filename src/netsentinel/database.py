import sqlite3
import json

class Database:
    def __init__(self, path="netsentinel.db"):
        self.connection = sqlite3.connect(path)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                type TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT
            )
        """)

        self.connection.commit()

    def save_alert(self, alert):
        self.connection.execute("""
            INSERT INTO alerts (
                timestamp,
                type,
                source,
                severity,
                details
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert["timestamp"],
            alert["type"],
            alert["source"],
            alert["severity"],
            json.dumps(alert["details"])
        ))

        self.connection.commit()
        
    def get_alerts(self, limit=100):
        cursor = self.connection.execute("""
            SELECT id, timestamp, type, source, severity, details
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
    """, (limit,))

        rows = cursor.fetchall()
        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "type": row[2],
                "source": row[3],
                "severity": row[4],
                "details": json.loads(row[5])                
            }
            for row in rows
        ]
    def close(self):
        self.connection.close()

        
if __name__ == "__main__":
    db = Database()
    alerts = db.get_alerts()
    for alert in alerts:
        print(alert)    