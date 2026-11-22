"""
Main Entrypoint for Multi-threaded Network IDS (Producer–Consumer Architecture).
Coordinates Producer, Queue Buffer, Consumer Worker Pool, Alert Manager, and Real-time Dashboard.
"""
import sys
import time
import argparse
import threading
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from config.settings import (
    QUEUE_MAXSIZE,
    NUM_CONSUMER_WORKERS,
    DASHBOARD_HOST,
    DASHBOARD_PORT
)
from core.queue_manager import PacketQueue
from core.alert_manager import AlertManager
from core.consumer_pool import ConsumerWorkerPool
from core.producer import PacketProducer
from dashboard.app import create_dashboard_app
from benchmark.traffic_generator import save_benchmark_pcap, generate_benchmark_attacks
from benchmark.suricata_benchmark import SuricataBenchmarkComparator


def list_available_interfaces():
    print("\n" + "=" * 70)
    print("      DANH SÁCH CARD MẠNG KHẢ DỤNG (SCAPY INTERFACE ENUMERATION)     ")
    print("=" * 70)
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            print(f"{'Tên Card (Name)':<32} | {'Địa chỉ IP':<25} | {'GUID'}")
            print("-" * 75)
            for iface in interfaces:
                ips = [ip for ip in iface.get('ips', []) if not ip.startswith('fe80')]
                name = iface.get('name', 'Unknown')
                # Filter out noisy internal sub-virtual filter drivers
                if ("Filter Driver" in name) or ("Packet Scheduler" in name) or ("LightWeight" in name):
                    continue
                print(f"{name:<32} | {str(ips):<25} | {iface.get('guid', '')[:18]}...")
        except Exception as e:
            print(f"[!] Lỗi đọc danh sách card mạng: {e}")
    else:
        from scapy.all import get_if_list
        for iface in get_if_list():
            print(f"- {iface}")
    print("=" * 70)
    print("[*] Gợi ý: Dùng đúng tên trong cột 'Tên Card' (ví dụ: 'Wi-Fi' hoặc 'Ethernet') cho cờ --interface\n")


def run_ids(mode: str = "demo",
            interface: str = None,
            pcap_file: str = None,
            num_workers: int = NUM_CONSUMER_WORKERS,
            enable_dashboard: bool = True,
            port: int = DASHBOARD_PORT,
            with_target_server: bool = False):

    print("=" * 70)
    print("      MULTI-THREADED NETWORK INTRUSION DETECTION SYSTEM (NIDS)      ")
    print("      Model: Producer–Consumer | TCP/IP & HTTP Layer-7 Inspector     ")
    print("=" * 70)

    # 1. Initialize Thread-safe Buffer Queue & Alert Manager
    queue = PacketQueue(maxsize=QUEUE_MAXSIZE)
    alert_manager = AlertManager()

    # 2. Initialize and Start Consumer Pool
    consumer_pool = ConsumerWorkerPool(
        queue=queue,
        alert_manager=alert_manager,
        num_workers=num_workers
    )
    consumer_pool.start()

    # 3. Initialize Producer
    producer = PacketProducer(queue=queue)

    # 4. Optional: Start Built-in Dummy Victim Web Server (port 8080)
    if with_target_server:
        from benchmark.victim_web_server import TargetAppHandler
        from http.server import HTTPServer

        def _run_target_server():
            try:
                target_httpd = HTTPServer(("0.0.0.0", 8080), TargetAppHandler)
                print("[TargetServer] Built-in Victim Web Server active at http://0.0.0.0:8080 (ready for attack traffic)")
                target_httpd.serve_forever()
            except Exception as e:
                print(f"[TargetServer] Notice: Port 8080 already in use or unavailable: {e}")

        target_thread = threading.Thread(target=_run_target_server, name="TargetServerThread", daemon=True)
        target_thread.start()

    # 5. Initialize Web Dashboard if enabled
    dashboard_thread = None
    socketio_server = None
    if enable_dashboard:
        app, socketio = create_dashboard_app(queue=queue, alert_manager=alert_manager)
        socketio_server = socketio

        def _run_server():
            print(f"[Dashboard] Real-time Web Dashboard available at: http://{DASHBOARD_HOST}:{port}")
            socketio.run(app, host=DASHBOARD_HOST, port=port, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)

        dashboard_thread = threading.Thread(target=_run_server, name="DashboardServer", daemon=True)
        dashboard_thread.start()

    # 6. Execute based on selected mode
    try:
        if mode == "demo":
            print("[Mode: DEMO] Preparing attack scenario and launching live observable simulation...")
            pcap_path = save_benchmark_pcap("data/benchmark_attacks.pcap")
            time.sleep(1.5)  # Allow dashboard to initialize

            print(f"\n[DEMO READY] Open your browser at: http://127.0.0.1:{port}")
            print("[DEMO] Injecting attack packets (SQLi, XSS, Path Traversal, Port Scan, SYN Flood) in 2 seconds...")
            time.sleep(2.0)

            # Replay benchmark attack packets at realistic speed
            producer.start_pcap_replay(pcap_path, speed_multiplier=2.0)

            print("[DEMO] Traffic injection started. Monitoring real-time detections... (Press Ctrl+C to stop)")
            while True:
                time.sleep(1.0)

        elif mode == "live":
            print(f"[Mode: LIVE] Sniffing live traffic on interface: {interface or 'Default'}")
            producer.start_live_capture(interface=interface)
            while True:
                time.sleep(1.0)

        elif mode == "pcap":
            if not pcap_file or not Path(pcap_file).exists():
                print(f"[Error] Specified PCAP file does not exist: {pcap_file}")
                return
            print(f"[Mode: PCAP] Replaying file: {pcap_file}")
            producer.start_pcap_replay(pcap_file, speed_multiplier=1.0)
            while True:
                time.sleep(1.0)

        elif mode == "benchmark":
            print("[Mode: BENCHMARK] Generating comparison report with Suricata...")
            comparator = SuricataBenchmarkComparator()
            report = comparator.generate_comparison_report()
            print("\n" + report)

            # Save report to logs
            report_file = Path("logs/suricata_comparison_report.md")
            report_file.parent.mkdir(parents=True, exist_ok=True)
            report_file.write_text(report, encoding="utf-8")
            print(f"\n[Report Saved] -> {report_file.resolve()}")

    except KeyboardInterrupt:
        print("\n[Shutting down] User requested termination...")
    finally:
        producer.stop()
        consumer_pool.stop()
        print("[NIDS] System shut down cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded NIDS (Producer–Consumer)")
    parser.add_argument("--mode", choices=["demo", "live", "pcap", "benchmark"], default="demo",
                        help="Operation mode: 'demo' (simulate attacks), 'live' (sniff network), 'pcap' (replay file), 'benchmark' (compare with Suricata)")
    parser.add_argument("--interface", type=str, default=None, help="Network card interface name for live mode")
    parser.add_argument("--pcap", type=str, default=None, help="Path to PCAP file for replay mode")
    parser.add_argument("--workers", type=int, default=NUM_CONSUMER_WORKERS, help="Number of consumer worker threads")
    parser.add_argument("--port", type=int, default=DASHBOARD_PORT, help="Port for the real-time web dashboard")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable web dashboard")
    parser.add_argument("--list-interfaces", action="store_true", help="Liệt kê danh sách các card mạng khả dụng trên máy tính")
    parser.add_argument("--with-target-server", action="store_true", help="Tự động chạy máy chủ Web mục tiêu giả lập tại port 8080 để tiếp nhận traffic từ Máy 1")

    args = parser.parse_args()

    if args.list_interfaces:
        list_available_interfaces()
        sys.exit(0)

    run_ids(
        mode=args.mode,
        interface=args.interface,
        pcap_file=args.pcap,
        num_workers=args.workers,
        enable_dashboard=not args.no_dashboard,
        port=args.port,
        with_target_server=args.with_target_server
    )
