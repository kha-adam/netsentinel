import sqlite3
import json

class Database:
    def __init__(self, path="netsentinel.db"):
        # self.connection = sqlite3.connect(path)
        self.path = path
        connection = sqlite3.connect(self.path)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                type TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT
            )
        """)

        connection.commit()
        connection.close()

    def save_alert(self, alert):
        connection = sqlite3.connect(self.path)
        connection.execute("""
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

        connection.commit()
        connection.close()
        
    def get_alerts(self, limit=100):
        connection = sqlite3.connect(self.path)
        cursor = connection.execute("""
            SELECT id, timestamp, type, source, severity, details
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
    """, (limit,))

        rows = cursor.fetchall()
        connection.close()
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
    # def close(self):
    #     self.connection.close()

 