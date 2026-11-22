"""
Flask + Flask-SocketIO Real-time Observable Dashboard Server.
Streams high-frequency queue metrics and security alerts to connected web clients.
"""
import time
import threading
from pathlib import Path
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from config.settings import DASHBOARD_HOST, DASHBOARD_PORT
from core.queue_manager import PacketQueue
from core.alert_manager import AlertManager


def create_dashboard_app(queue: PacketQueue, alert_manager: AlertManager):
    base_dir = Path(__file__).resolve().parent
    template_folder = base_dir / "templates"

    app = Flask(__name__, template_folder=str(template_folder))
    app.config["SECRET_KEY"] = "nids-observable-secret-key-2026"
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    # Forward alerts from AlertManager directly to WebSocket clients
    def on_new_alert(alert_data):
        socketio.emit("new_alert", alert_data)

    alert_manager.register_listener(on_new_alert)

    # Periodic background thread pushing telemetry every 1 second
    def telemetry_broadcaster():
        while True:
            time.sleep(1.0)
            data = {
                "queue": queue.get_stats(),
                "alerts": alert_manager.get_stats(),
                "timestamp": time.time()
            }
            socketio.emit("telemetry_update", data)

    t = threading.Thread(target=telemetry_broadcaster, name="TelemetryBroadcaster", daemon=True)
    t.start()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/architecture")
    def architecture():
        return render_template("architecture.html")

    @app.route("/api/stats")
    def get_stats():
        return jsonify({
            "queue": queue.get_stats(),
            "alerts": alert_manager.get_stats()
        })

    @app.route("/api/alerts")
    def get_alerts():
        return jsonify(alert_manager.get_recent_alerts(50))

    return app, socketio
