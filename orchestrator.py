"""
HTTP/2 Rapid Reset (CVE-2023-44487) — Orchestrator
====================================================
Phase 1: Dual-mode scan — one attack, MODE A + B observe simultaneously.
         Results written as two rows (mode=A / mode=B) per cancel_rate.
Phase 2: Binary search, MODE A only (2 trials, 1/2 consensus).
         MODE B is excluded: sliding window reliability degrades on short runs.

IPS (ips_blocker.py) is intentionally NOT started during experiments.
iptables FORWARD is still flushed before each run to clear any residue.
"""

import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime

from config import (
    ATTACKER_CONTAINER, ATTACKER_SCRIPT,
    BINARY_SEARCH_PRECISION, BINARY_SEARCH_SUCCESS_THRESHOLD,
    BINARY_SEARCH_TRIALS, CANCEL_RATE_RANGE, CANCEL_RATE_STEP,
    COOLDOWN_BETWEEN_EXPERIMENTS, CPU_THRESHOLD, CSV_COLUMNS,
    EXPERIMENT_DURATION, IDS_ALERT_KEYWORD, IDS_IPS_CONTAINER,
    IDS_LOG_A, IDS_LOG_B, RESULTS_DIR, EXPERIMENT_LOG,
    TSHARK_IFACE, VICTIM_CONTAINER, VICTIM_IP,
    VICTIM_METRICS_FILE_HOST,
)


# ── Docker helper ──────────────────────────────────────────────────────────────

def docker_exec(container: str, cmd: str, detach: bool = False) -> str:
    flag = ["-d"] if detach else []
    full = ["docker", "exec"] + flag + [container, "bash", "-c", cmd]
    if detach:
        subprocess.Popen(full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ""
    try:
        r = subprocess.run(
            full, capture_output=True,
            encoding="utf-8", errors="replace",
            timeout=15,
        )
        return (r.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


# ── State management ───────────────────────────────────────────────────────────

def reset_iptables():
    docker_exec(IDS_IPS_CONTAINER, "iptables -F FORWARD")
    _log("iptables FORWARD cleared")


def _truncate(log_path: str):
    docker_exec(IDS_IPS_CONTAINER, f"truncate -s 0 {log_path} 2>/dev/null; "
                                    f"touch {log_path}")


def clear_ids_logs():
    _truncate(IDS_LOG_A)
    _truncate(IDS_LOG_B)
    _log("ids_a.log + ids_b.log cleared")


def clear_ids_log_a():
    _truncate(IDS_LOG_A)
    _log("ids_a.log cleared")


def _start_pipeline(script: str, log_file: str):
    """Start one tshark | detector pipeline writing to log_file (background)."""
    tshark = (
        f"tshark -i {TSHARK_IFACE} -d tcp.port==80,http2 -Nn -l "
        f"-T fields -e ip.src -e http2.type -E separator=, "
        f"-Y 'http2 and ip.dst == {VICTIM_IP}' 2>/dev/null"
    )
    pipeline = (
        f"{tshark} "
        f"| stdbuf -oL python3 -u /root/{script} "
        f"| tee {log_file}"
    )
    docker_exec(IDS_IPS_CONTAINER, pipeline, detach=True)


def start_dual_detectors():
    """Kill existing pipelines, then launch MODE A and MODE B simultaneously."""
    docker_exec(IDS_IPS_CONTAINER, "pkill -f tshark   || true")
    docker_exec(IDS_IPS_CONTAINER, "pkill -f detector || true")
    time.sleep(1.5)
    _start_pipeline("detector.py",        IDS_LOG_A)
    time.sleep(0.3)   # slight stagger so both tshark instances don't race on init
    _start_pipeline("detector_window.py", IDS_LOG_B)
    _log("dual detectors started (A→ids_a.log  B→ids_b.log)")
    time.sleep(2.0)   # tshark warmup


def start_detector_a():
    """Kill existing pipelines, start MODE A only."""
    docker_exec(IDS_IPS_CONTAINER, "pkill -f tshark   || true")
    docker_exec(IDS_IPS_CONTAINER, "pkill -f detector || true")
    time.sleep(1.5)
    _start_pipeline("detector.py", IDS_LOG_A)
    _log("detector MODE A started (→ids_a.log)")
    time.sleep(2.0)


def stop_detectors():
    docker_exec(IDS_IPS_CONTAINER, "pkill -f tshark   || true")
    docker_exec(IDS_IPS_CONTAINER, "pkill -f detector || true")
    time.sleep(0.5)


def start_victim_monitor():
    docker_exec(VICTIM_CONTAINER, "pkill -f victim_monitor.py || true")
    time.sleep(0.3)
    docker_exec(VICTIM_CONTAINER, "python3 /root/victim_monitor.py", detach=True)
    _log("victim_monitor started")
    time.sleep(1.0)


def stop_victim_monitor():
    docker_exec(VICTIM_CONTAINER, "pkill -f victim_monitor.py || true")
    time.sleep(0.5)


def run_attack(cancel_rate: float, duration: int):
    cmd = f"python3 /root/{ATTACKER_SCRIPT} {cancel_rate} --duration {duration}"
    docker_exec(ATTACKER_CONTAINER, cmd, detach=True)
    _log(f"attack ({ATTACKER_SCRIPT})  cancel_rate={cancel_rate:.4f}  duration={duration}s")


def stop_attack():
    docker_exec(ATTACKER_CONTAINER, f"pkill -f {ATTACKER_SCRIPT} || true")


# ── Result collection ──────────────────────────────────────────────────────────

def check_ids_alert(log_file: str) -> bool:
    content = docker_exec(
        IDS_IPS_CONTAINER, f"cat {log_file} 2>/dev/null || true"
    )
    return IDS_ALERT_KEYWORD in content


def check_ips_blocked() -> bool:
    rules = docker_exec(IDS_IPS_CONTAINER, "iptables -L FORWARD -n 2>/dev/null || true")
    return "DROP" in rules


def read_victim_metrics() -> dict:
    empty = {"cpu_avg": 0.0, "cpu_max": 0.0, "threshold_exceeded": False}
    try:
        with open(VICTIM_METRICS_FILE_HOST, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return empty


def append_csv(row: dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    new_file = not os.path.exists(EXPERIMENT_LOG)
    with open(EXPERIMENT_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


# ── UI helpers ─────────────────────────────────────────────────────────────────

def _log(msg: str):
    print(f"    [{msg}]")


def _progress(total: int, label: str = ""):
    for i in range(total):
        sys.stdout.write(f"\r    {label}{i + 1:3d}/{total}s")
        sys.stdout.flush()
        time.sleep(1)
    print()


def _cooldown(seconds: int):
    sys.stdout.write(f"  cooldown ")
    _progress(seconds)


# ── Dual experiment (Phase 1) ──────────────────────────────────────────────────

def run_dual_experiment(cancel_rate: float) -> tuple:
    """One attack observed by both MODE A and B simultaneously.
    Returns (row_a, row_b) — same CPU metrics, independent IDS results.
    """
    print(f"\n  ▶  cancel_rate={cancel_rate:.2f}  MODE A+B (simultaneous)")

    reset_iptables()
    clear_ids_logs()
    start_dual_detectors()
    start_victim_monitor()
    time.sleep(1)

    run_attack(cancel_rate, EXPERIMENT_DURATION)
    _progress(EXPERIMENT_DURATION + 3, "attack+buffer ")

    ids_a       = check_ids_alert(IDS_LOG_A)
    ids_b       = check_ids_alert(IDS_LOG_B)
    ips_blocked = check_ips_blocked()
    metrics     = read_victim_metrics()

    stop_attack()
    stop_victim_monitor()
    stop_detectors()

    cpu_avg = round(metrics.get("cpu_avg", 0.0), 2)
    cpu_max = round(metrics.get("cpu_max", 0.0), 2)
    exceeded = metrics.get("threshold_exceeded", False)
    ts = datetime.now().isoformat(timespec="seconds")

    base = dict(
        duration_sec=EXPERIMENT_DURATION,
        ips_blocked=ips_blocked,
        victim_cpu_avg=cpu_avg,
        victim_cpu_max=cpu_max,
        cpu_threshold_exceeded=exceeded,
        timestamp=ts,
    )
    row_a = {**base, "phase": 1, "trial": 1, "cancel_rate": cancel_rate,
             "mode": "A", "ids_alert": ids_a}
    row_b = {**base, "phase": 1, "trial": 1, "cancel_rate": cancel_rate,
             "mode": "B", "ids_alert": ids_b}

    fa = "🚨" if ids_a else "  "
    fb = "🚨" if ids_b else "  "
    fc = "⚠️ " if exceeded else "  "
    print(
        f"  ← {fa}A={str(ids_a):<5}  {fb}B={str(ids_b):<5}  "
        f"{fc}CPU avg={cpu_avg:5.1f}%  max={cpu_max:5.1f}%"
    )
    return row_a, row_b


# ── Single experiment (Phase 2, MODE A only) ───────────────────────────────────

def run_phase2_experiment(cancel_rate: float, trial: int) -> dict:
    print(f"    trial {trial}/{BINARY_SEARCH_TRIALS}  cancel_rate={cancel_rate:.4f}")

    reset_iptables()
    clear_ids_log_a()
    start_detector_a()
    start_victim_monitor()
    time.sleep(1)

    run_attack(cancel_rate, EXPERIMENT_DURATION)
    _progress(EXPERIMENT_DURATION + 3, "attack+buffer ")

    ids_alert   = check_ids_alert(IDS_LOG_A)
    ips_blocked = check_ips_blocked()
    metrics     = read_victim_metrics()

    stop_attack()
    stop_victim_monitor()
    stop_detectors()

    fi = "🚨" if ids_alert else "  "
    print(f"    {fi}IDS={str(ids_alert):<5}")

    return {
        "phase": 2,
        "trial": trial,
        "cancel_rate": cancel_rate,
        "mode": "A",
        "duration_sec": EXPERIMENT_DURATION,
        "ids_alert": ids_alert,
        "ips_blocked": ips_blocked,
        "victim_cpu_avg": round(metrics.get("cpu_avg", 0.0), 2),
        "victim_cpu_max": round(metrics.get("cpu_max", 0.0), 2),
        "cpu_threshold_exceeded": metrics.get("threshold_exceeded", False),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


# ── Phase 1: Linear scan ───────────────────────────────────────────────────────

def phase1() -> list:
    print("\n" + "=" * 66)
    print(f"  Phase 1 — Dual scan  "
          f"{CANCEL_RATE_RANGE[0]:.1f} → {CANCEL_RATE_RANGE[1]:.1f}  "
          f"step={CANCEL_RATE_STEP}  (1 attack → MODE A+B simultaneously)")
    print("=" * 66)

    detected = []
    rate = CANCEL_RATE_RANGE[0]

    while rate <= CANCEL_RATE_RANGE[1] + 1e-9:
        r = round(rate, 4)
        row_a, row_b = run_dual_experiment(r)
        append_csv(row_a)
        append_csv(row_b)

        if (row_a["ids_alert"] or row_b["ids_alert"]) and r not in detected:
            detected.append(r)

        _cooldown(COOLDOWN_BETWEEN_EXPERIMENTS)
        rate = round(rate + CANCEL_RATE_STEP, 4)

    print("\n  Phase 1 complete. First detection at: "
          + (str(sorted(detected)) if detected else "none"))
    return detected


# ── Phase 2: Binary search (MODE A only) ──────────────────────────────────────

def _binary_search_a(lo: float, hi: float) -> float:
    """Return smallest cancel_rate where MODE A reliably fires."""
    threshold = hi

    while hi - lo > BINARY_SEARCH_PRECISION:
        mid = round((lo + hi) / 2, 4)
        print(f"\n    [{lo:.4f}, {hi:.4f}]  mid={mid:.4f}  "
              f"({BINARY_SEARCH_TRIALS} trials, need ≥{BINARY_SEARCH_SUCCESS_THRESHOLD})")

        successes = 0
        for trial in range(1, BINARY_SEARCH_TRIALS + 1):
            row = run_phase2_experiment(mid, trial)
            append_csv(row)
            if row["ids_alert"]:
                successes += 1
            if trial < BINARY_SEARCH_TRIALS:
                _cooldown(COOLDOWN_BETWEEN_EXPERIMENTS)

        detected = successes >= BINARY_SEARCH_SUCCESS_THRESHOLD
        direction = "하향 ↓" if detected else "상향 ↑"
        print(f"    → {successes}/{BINARY_SEARCH_TRIALS}  {direction}")

        if detected:
            threshold = mid
            hi = mid
        else:
            lo = mid

        _cooldown(COOLDOWN_BETWEEN_EXPERIMENTS)

    return threshold


def phase2(detected: list) -> dict:
    print("\n" + "=" * 66)
    if not detected:
        print("  Phase 2 — 탐지 지점 없음, 스킵.")
        return {}

    min_detected = min(detected)
    lo = round(max(0.0, min_detected - CANCEL_RATE_STEP), 4)
    hi = min_detected

    print(f"  Phase 2 — Binary search (MODE A only)")
    print(f"  lo={lo}  hi={hi}  precision={BINARY_SEARCH_PRECISION}")
    print(f"  (MODE B 결과는 Phase 1에서만 기록 — 슬라이딩 윈도우 단기 반복 신뢰도 낮음)")
    print("=" * 66)

    threshold = _binary_search_a(lo, hi)
    print(f"\n  🎯 MODE A 최적 임계치: {threshold:.4f}  ({threshold * 100:.2f}%)")
    return {"A": threshold}


# ── Entry point ────────────────────────────────────────────────────────────────

def _backup_old_csv():
    """Rename existing experiment_log.csv to avoid schema-mismatch accumulation."""
    if os.path.exists(EXPERIMENT_LOG):
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = EXPERIMENT_LOG.replace(".csv", f"_{ts}.csv")
        os.rename(EXPERIMENT_LOG, backup)
        print(f"  📦 이전 결과 백업: {backup}")


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    _backup_old_csv()

    print("=" * 66)
    print("  🚀 HTTP/2 Rapid Reset Orchestrator")
    print(f"     cancel_rate: {CANCEL_RATE_RANGE[0]}–{CANCEL_RATE_RANGE[1]}"
          f"  step={CANCEL_RATE_STEP}")
    print(f"     duration={EXPERIMENT_DURATION}s  cooldown={COOLDOWN_BETWEEN_EXPERIMENTS}s")
    print(f"     Phase 1: dual (A+B simultaneous) | Phase 2: MODE A binary search")
    print(f"     IPS: disabled  |  CPU threshold: {CPU_THRESHOLD}%")
    print(f"     results → {EXPERIMENT_LOG}")
    print("=" * 66)

    detected   = phase1()
    thresholds = phase2(detected)

    print("\n" + "=" * 66)
    print("  ✅  Experiment complete")
    print(f"  📁  Results: {EXPERIMENT_LOG}")
    if thresholds:
        for mode, val in sorted(thresholds.items()):
            print(f"  🎯  MODE {mode}: {val:.4f}  ({val * 100:.2f}%)")
    else:
        print("  ⚠️   No threshold found. Widen CANCEL_RATE_RANGE in config.py.")
    print("=" * 66)

    # Auto-generate report
    print("\n  📊 Generating report...\n")
    subprocess.run([sys.executable, "report.py"], check=False)


if __name__ == "__main__":
    main()
