"""
HTTP/2 Rapid Reset — Orchestrator v3 (Low Cancel Rate SSL Test)
============================================================
SSL 환경에서 낮은 cancel_rate (0.0 ~ 0.3)의 영향을 측정합니다.
결과는 ./results3 폴더에 저장됩니다.
"""

import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config

# --- Overrides for SSL Low CR Test ---
ATTACKER_SCRIPT = "attacker_multi_3.py"
RESULTS_DIR = "./results3"
EXP2_CSV = os.path.join(RESULTS_DIR, "exp_low_cr_sweep.csv")
VICTIM_METRICS_FILE_HOST = "./results/victim_metrics.json"
# -----------------------------------

from config import (
    ATTACKER_CONTAINER, COOLDOWN_BETWEEN_EXPERIMENTS, CPU_THRESHOLD,
    EXP2_RPS, EXPERIMENT_DURATION, IDS_IPS_CONTAINER, IDS_LOG_A,
    TSHARK_IFACE, VICTIM_CONTAINER, VICTIM_IP
)

def sync_attacker_script():
    src = os.path.abspath(ATTACKER_SCRIPT)
    dst = f"{ATTACKER_CONTAINER}:/root/{ATTACKER_SCRIPT}"
    subprocess.run(["docker", "cp", src, dst], capture_output=True)
    print(f"    [docker cp {ATTACKER_SCRIPT} → {ATTACKER_CONTAINER} ✓]")

def docker_exec(container: str, cmd: str, detach: bool = False) -> str:
    flag = ["-d"] if detach else []
    full = ["docker", "exec"] + flag + [container, "bash", "-c", cmd]
    if detach:
        subprocess.Popen(full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ""
    try:
        r = subprocess.run(full, capture_output=True, encoding="utf-8", errors="replace", timeout=15)
        return (r.stdout or "").strip()
    except: return ""

def start_victim_monitor():
    docker_exec(VICTIM_CONTAINER, "pkill -f victim_monitor.py || true")
    docker_exec(VICTIM_CONTAINER, "python3 /root/victim_monitor.py", detach=True)
    time.sleep(1)

def stop_victim_monitor():
    docker_exec(VICTIM_CONTAINER, "pkill -f victim_monitor.py || true")

def run_attack(cancel_rate: float, rps: int, duration: int):
    cmd = f"python3 /root/{ATTACKER_SCRIPT} {cancel_rate} --duration {duration} --rps {rps}"
    docker_exec(ATTACKER_CONTAINER, cmd, detach=True)

def stop_attack():
    docker_exec(ATTACKER_CONTAINER, f"pkill -f {ATTACKER_SCRIPT} || true")

def read_victim_metrics() -> dict:
    empty = {"cpu_avg": 0.0, "cpu_max": 0.0, "threshold_exceeded": False}
    try:
        with open(VICTIM_METRICS_FILE_HOST, "r", encoding="utf-8") as f:
            return json.load(f)
    except: return empty

def append_csv(path: str, row: dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    columns = list(row.keys())
    new_file = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        if new_file: writer.writeheader()
        writer.writerow(row)

def single_run(cancel_rate: float, rps: int) -> dict:
    start_victim_monitor()
    time.sleep(1)
    run_attack(cancel_rate, rps, EXPERIMENT_DURATION)
    
    label = f"attack (SSL, CR={cancel_rate:.1f}) "
    for i in range(EXPERIMENT_DURATION):
        sys.stdout.write(f"\r    {label}{i + 1:3d}/{EXPERIMENT_DURATION}s")
        sys.stdout.flush()
        time.sleep(1)
    print()

    metrics = read_victim_metrics()
    stop_attack()
    stop_victim_monitor()

    cpu_avg = round(metrics.get("cpu_avg", 0.0), 2)
    cpu_max = round(metrics.get("cpu_max", 0.0), 2)
    print(f"  ← CPU avg={cpu_avg:5.1f}%  max={cpu_max:5.1f}%")

    return {
        "cancel_rate": cancel_rate,
        "rps": rps,
        "victim_cpu_avg": cpu_avg,
        "victim_cpu_max": cpu_max,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("=" * 66)
    print("  🚀 HTTP/2 Rapid Reset Orchestrator v3 (SSL LOW CR TEST)")
    sync_attacker_script()
    print(f"     Results Directory: {RESULTS_DIR}")
    print("=" * 66)

    fixed_rps = EXP2_RPS # 800
    test_points = [0.0, 0.1, 0.2, 0.3]

    for cr in test_points:
        print(f"\n  ▶  cancel_rate={cr:.1f}  RPS={fixed_rps}")
        m = single_run(cr, fixed_rps)
        append_csv(EXP2_CSV, m)
        
        print(f"    cooldown {COOLDOWN_BETWEEN_EXPERIMENTS}s...")
        time.sleep(COOLDOWN_BETWEEN_EXPERIMENTS)

    print("\n" + "=" * 66)
    print(f"  ✅  Low CR SSL 실험 완료. 결과: {EXP2_CSV}")
    print("=" * 66)

if __name__ == "__main__":
    main()
