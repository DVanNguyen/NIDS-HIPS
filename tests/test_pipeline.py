"""
Automated Pipeline Verification Test.
Feeds benchmark attack packets directly through Producer-Consumer pipeline
and asserts that all attack categories are correctly detected.
"""
import sys
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core.queue_manager import PacketQueue
from core.alert_manager import AlertManager
from core.consumer_pool import ConsumerWorkerPool
from benchmark.traffic_generator import generate_benchmark_attacks


def run_pipeline_test():
    print("[Test] Initializing pipeline components...")
    queue = PacketQueue(maxsize=1000)
    alert_manager = AlertManager()
    consumer_pool = ConsumerWorkerPool(queue=queue, alert_manager=alert_manager, num_workers=2)
    consumer_pool.start()

    print("[Test] Generating synthetic benchmark attack packets...")
    pkts = generate_benchmark_attacks(target_ip="192.168.1.50")
    print(f"[Test] Injecting {len(pkts)} packets into PacketQueue...")

    for pkt in pkts:
        queue.put(pkt, block=False)
        time.sleep(0.01)

    # Wait for consumer workers to finish processing queue
    time.sleep(2.0)
    consumer_pool.stop()

    # Collect stats
    queue_stats = queue.get_stats()
    alert_stats = alert_manager.get_stats()
    alerts = alert_manager.get_recent_alerts(50)

    print("\n--- TEST EXECUTION SUMMARY ---")
    print(f"Total Packets Put:       {queue_stats['total_received']}")
    print(f"Total Packets Processed: {queue_stats['total_processed']}")
    print(f"Total Packets Dropped:   {queue_stats['total_dropped']}")
    print(f"Total Alerts Triggered:  {alert_stats['total_alerts']}")
    print(f"Categories Detected:     {list(alert_stats['categories'].keys())}")

    # Assertions
    assert queue_stats["total_dropped"] == 0, "Packet drop occurred during test!"
    assert queue_stats["total_processed"] > 0, "No packets were processed!"
    assert alert_stats["total_alerts"] > 0, "No alerts were generated!"

    detected_categories = set(alert_stats["categories"].keys())
    expected_categories = {"SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "PORT_SCAN", "DOS_SYN_FLOOD"}

    for exp in expected_categories:
        assert exp in detected_categories, f"Failed to detect expected attack: {exp}"

    print("\n[SUCCESS] All verification tests passed! All attack categories accurately detected.")
    return True


if __name__ == "__main__":
    run_pipeline_test()
