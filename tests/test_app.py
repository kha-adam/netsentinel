from netsentinel.app import create_app
from netsentinel.database import Database


def test_api_alerts_returns_database_alert(tmp_path):

    database_path = tmp_path / "test.db"
    database = Database(str(database_path))

    alert = {
        "timestamp": 1234567890,
        "type": "PORT_SCAN",
        "source": "192.168.1.50",
        "severity": "HIGH",
        "details": {
            "ports": [21, 22, 23]
        }
    }

    database.save_alert(alert)

    test_app = create_app(database)
    client = test_app.test_client()

    response = client.get("/api/alerts")

    assert response.status_code == 200

    data = response.get_json()

    assert len(data) == 1
    assert data[0]["type"] == "PORT_SCAN"
    assert data[0]["source"] == "192.168.1.50"
    assert data[0]["severity"] == "HIGH"
    assert data[0]["details"]["ports"] == [21, 22, 23]

def test_dashboard_page(tmp_path):

    database_path = tmp_path / "test.db"
    database = Database(str(database_path))

    database.save_alert({
        "timestamp": 1234567890,
        "type": "PORT_SCAN",
        "source": "192.168.1.50",
        "severity": "HIGH",
        "details": {
            "ports": [21, 22, 23]
        }
    })

    test_app = create_app(database)
    client = test_app.test_client()

    response = client.get("/")

    assert response.status_code == 200

    html = response.data.decode()

    assert "NetSentinel" in html
    assert "PORT_SCAN" in html
    assert "192.168.1.50" in html