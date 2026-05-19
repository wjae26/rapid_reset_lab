import os
import sys
import json
import signal
import time
import psutil

# Must match config.py CPU_THRESHOLD
CPU_THRESHOLD = 70.0
RESULTS_DIR   = "/results"
METRICS_FILE  = f"{RESULTS_DIR}/victim_metrics.json"
SAMPLE_INTERVAL = 1  # seconds

samples: list[float] = []
running = True


def save_metrics() -> dict:
    avg = round(sum(samples) / len(samples), 2) if samples else 0.0
    mx  = round(max(samples), 2) if samples else 0.0
    data = {
        "cpu_samples":         samples,
        "cpu_avg":             avg,
        "cpu_max":             mx,
        "threshold_exceeded":  mx >= CPU_THRESHOLD,
        "sample_count":        len(samples),
    }
    with open(METRICS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return data


def handle_signal(sig, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT,  handle_signal)

os.makedirs(RESULTS_DIR, exist_ok=True)

print(f"📊 [Victim Monitor] CPU 측정 시작 (임계치: {CPU_THRESHOLD}%, 간격: {SAMPLE_INTERVAL}s)")
print(f"📁 저장 경로: {METRICS_FILE}")
sys.stdout.flush()

try:
    while running:
        cpu  = psutil.cpu_percent(interval=SAMPLE_INTERVAL)
        samples.append(cpu)
        data = save_metrics()
        flag = "⚠️  OVER" if cpu >= CPU_THRESHOLD else "✅  OK  "
        print(
            f"CPU: {cpu:5.1f}% {flag} | "
            f"Avg: {data['cpu_avg']:5.1f}% | Max: {data['cpu_max']:5.1f}%"
        )
        sys.stdout.flush()
finally:
    final = save_metrics()
    print(
        f"\n📊 [Victim Monitor] 종료 — "
        f"avg={final['cpu_avg']}%  max={final['cpu_max']}%  "
        f"exceeded={final['threshold_exceeded']}"
    )
