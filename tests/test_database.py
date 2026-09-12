from netsentinel.database import Database


def test_save_and_get_alert(tmp_path):

    database_path = tmp_path / "test.db"

    database = Database(str(database_path))

    alert = {
        "timestamp": 1234567890,
        "type": "PORT_SCAN",
        "source": "192.168.1.50",
        "severity": "HIGH",
        "details": {
            "ports": [21, 22, 80],
            "timeframe": 5
        }
    }

    database.save_alert(alert)

    alerts = database.get_alerts()

    assert len(alerts) == 1
    assert alerts[0]["type"] == "PORT_SCAN"
    assert alerts[0]["source"] == "192.168.1.50"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["details"]["ports"] == [21, 22, 80]

def test_get_alerts_returns_newest_first(tmp_path):

    database_path = tmp_path / "test.db"

    database = Database(str(database_path))

    alerts = [
        {
            "timestamp": 100,
            "type": "PORT_SCAN",
            "source": "192.168.1.10",
            "severity": "HIGH",
            "details": {}
        },
        {
            "timestamp": 200,
            "type": "SYN_FLOOD",
            "source": "192.168.1.20",
            "severity": "HIGH",
            "details": {}
        },
        {
            "timestamp": 300,
            "type": "SSH_BRUTE_FORCE",
            "source": "192.168.1.30",
            "severity": "HIGH",
            "details": {}
        }
    ]

    for alert in alerts:
        database.save_alert(alert)

    results = database.get_alerts()

    assert len(results) == 3
    assert results[0]["timestamp"] == 300
    assert results[1]["timestamp"] == 200
    assert results[2]["timestamp"] == 100