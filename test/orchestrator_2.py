"""
HTTP/2 Rapid Reset — Orchestrator v2 (Plain HTTP/2 Test)
======================================================
SSL을 제외한 순수 HTTP/2 최적화 공격의 성능을 측정합니다.
결과는 ./results2 폴더에 저장됩니다.
"""

import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime

# Windows cp949 콘솔에서 이모지 출력 시 UnicodeEncodeError 방지
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# config에서 기본값 로드
import config

# --- Overrides for Plain H2 Test ---
ATTACKER_SCRIPT = "attacker_multi_2.py"
RESULTS_DIR = "./results2"
EXP1_CSV = os.path.join(RESULTS_DIR, "exp1_rps_sweep.csv")
EXP2_CSV = os.path.join(RESULTS_DIR, "exp2_cancel_sweep.csv")
EXP3_CSV = os.path.join(RESULTS_DIR, "exp3_mixed.csv")
VICTIM_METRICS_FILE_HOST = "./results/victim_metrics.json" # Docker 볼륨 매핑 위치 유지
# -----------------------------------

from config import (
    ATTACKER_CONTAINER, 
    BINARY_SEARCH_MAX_ITERATIONS, BINARY_SEARCH_PRECISION,
    BINARY_SEARCH_SUCCESS_THRESHOLD, BINARY_SEARCH_TRIALS,
    CLIENT_CONTAINER, CLIENT_SCRIPT,
    COOLDOWN_BETWEEN_EXPERIMENTS, CPU_TARGET_FOR_EXP2, CPU_THRESHOLD,
    EXP0_CANCEL_RATE,
    EXP1_CANCEL_RATE, EXP1_COLUMNS, EXP1_RPS_VALUES,
    EXP2_CANCEL_RATE_RANGE, EXP2_CANCEL_RATE_STEP, EXP2_COLUMNS, EXP2_RPS,
    EXP3_COLUMNS, 
    EXPERIMENT_DURATION, EXPERIMENT_SELECT,
    IDS_ALERT_KEYWORD, IDS_IPS_CONTAINER, IDS_LOG_A,
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

def reset_iptables(): docker_exec(IDS_IPS_CONTAINER, "iptables -F FORWARD")
def clear_ids_log(): docker_exec(IDS_IPS_CONTAINER, f"truncate -s 0 {IDS_LOG_A} 2>/dev/null; touch {IDS_LOG_A}")

def start_detector():
    docker_exec(IDS_IPS_CONTAINER, "pkill -f tshark || true")
    docker_exec(IDS_IPS_CONTAINER, "pkill -f detector || true")
    time.sleep(1)
    tshark = f"tshark -i {TSHARK_IFACE} -d tcp.port==80,http2 -Nn -l -T fields -e ip.src -e http2.type -E separator=, -Y 'http2 and ip.dst == {VICTIM_IP}' 2>/dev/null"
    pipeline = f"{tshark} | stdbuf -oL python3 -u /root/detector.py | tee {IDS_LOG_A}"
    docker_exec(IDS_IPS_CONTAINER, pipeline, detach=True)
    time.sleep(1)

def stop_detector():
    docker_exec(IDS_IPS_CONTAINER, "pkill -f tshark || true")
    docker_exec(IDS_IPS_CONTAINER, "pkill -f detector || true")

def start_victim_monitor():
    docker_exec(VICTIM_CONTAINER, "pkill -f victim_monitor.py || true")
    # victim_monitor.py 내부의 RESULTS_DIR은 /results로 고정되어 있음 (docker 볼륨 매핑)
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

def append_csv(path: str, columns: list, row: dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    new_file = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        if new_file: writer.writeheader()
        writer.writerow(row)

def single_run(cancel_rate: float, rps: int, with_client: bool = False) -> dict:
    reset_iptables()
    clear_ids_log()
    start_detector()
    start_victim_monitor()
    time.sleep(1)
    run_attack(cancel_rate, rps, EXPERIMENT_DURATION)
    
    label = "attack (Plain) "
    for i in range(EXPERIMENT_DURATION):
        sys.stdout.write(f"\r    {label}{i + 1:3d}/{EXPERIMENT_DURATION}s")
        sys.stdout.flush()
        time.sleep(1)
    print()

    metrics = read_victim_metrics()
    stop_attack()
    stop_victim_monitor()
    stop_detector()

    cpu_avg = round(metrics.get("cpu_avg", 0.0), 2)
    cpu_max = round(metrics.get("cpu_max", 0.0), 2)
    print(f"  ← CPU avg={cpu_avg:5.1f}%  max={cpu_max:5.1f}%")

    return {
        "victim_cpu_avg": cpu_avg,
        "victim_cpu_max": cpu_max,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("=" * 66)
    print("  🚀 HTTP/2 Rapid Reset Orchestrator v2 (PLAIN H2 TEST)")
    sync_attacker_script()
    print(f"     Results Directory: {RESULTS_DIR}")
    print("=" * 66)

    # 단순화를 위해 실험 2 구간만 수행 (0.5 ~ 1.0)
    fixed_rps = EXP2_RPS
    points = []
    cr = EXP2_CANCEL_RATE_RANGE[0]
    while cr <= EXP2_CANCEL_RATE_RANGE[1] + 1e-9:
        points.append(round(cr, 4))
        cr = round(cr + EXP2_CANCEL_RATE_STEP, 4)

    for cr in points:
        print(f"\n  ▶  cancel_rate={cr:.4f}  RPS={fixed_rps}")
        m = single_run(cr, fixed_rps)
        row = {
            "experiment": 2,
            "phase": 1,
            "trial": 1,
            "cancel_rate": cr,
            "rps": fixed_rps,
            "duration_sec": EXPERIMENT_DURATION,
            "ids_alert": False,
            "ips_blocked": False,
            "victim_cpu_avg": m["victim_cpu_avg"],
            "victim_cpu_max": m["victim_cpu_max"],
            "cpu_threshold_exceeded": m["victim_cpu_max"] >= CPU_THRESHOLD,
            "timestamp": m["timestamp"],
        }
        append_csv(EXP2_CSV, EXP2_COLUMNS, row)
        
        sys.stdout.write("  cooldown ")
        for i in range(COOLDOWN_BETWEEN_EXPERIMENTS):
            sys.stdout.write(f"\r    cooldown {i + 1:3d}/{COOLDOWN_BETWEEN_EXPERIMENTS}s")
            sys.stdout.flush()
            time.sleep(1)
        print()

    print("\n" + "=" * 66)
    print(f"  ✅  Plain H2 실험 완료. 결과: {EXP2_CSV}")
    print("=" * 66)

if __name__ == "__main__":
    main()
