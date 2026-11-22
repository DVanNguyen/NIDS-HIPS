"""
Dashboard HTTP & SocketIO Route Verification Test.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.queue_manager import PacketQueue
from core.alert_manager import AlertManager
from dashboard.app import create_dashboard_app


def test_dashboard_routes():
    queue = PacketQueue(maxsize=100)
    alert_manager = AlertManager()
    app, socketio = create_dashboard_app(queue, alert_manager)

    client = app.test_client()

    # Test Index Route
    res_index = client.get("/")
    assert res_index.status_code == 200, "Index route failed!"
    assert b"NIDS OBSERVABLE MONITOR" in res_index.data, "Index content missing!"

    # Test API Stats
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200, "Stats API failed!"
    data = res_stats.get_json()
    assert "queue" in data and "alerts" in data, "Stats payload invalid!"

    # Test API Alerts
    res_alerts = client.get("/api/alerts")
    assert res_alerts.status_code == 200, "Alerts API failed!"

    print("[SUCCESS] Dashboard routes and template verified successfully!")


if __name__ == "__main__":
    test_dashboard_routes()
