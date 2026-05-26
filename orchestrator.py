"""
HTTP/2 Rapid Reset (CVE-2023-44487) — Orchestrator v2
======================================================
실험 1: RPS 스윕  — cancel_rate=1.0 고정, RPS 변화로 CPU 기준선 확보
실험 2: cancel_rate 스윕 — 실험 1에서 CPU≈50% RPS 고정, IDS 탐지 임계치 측정
실험 3: 혼합 트래픽 — 실험 2 조건 + client_vm 정상 트래픽 병행

config.py의 EXPERIMENT_SELECT로 실험 번호 선택 ("1", "2", "3", "all")
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
    BINARY_SEARCH_MAX_ITERATIONS, BINARY_SEARCH_PRECISION,
    BINARY_SEARCH_SUCCESS_THRESHOLD, BINARY_SEARCH_TRIALS,
    CLIENT_CONTAINER, CLIENT_SCRIPT,
    COOLDOWN_BETWEEN_EXPERIMENTS, CPU_TARGET_FOR_EXP2, CPU_THRESHOLD,
    EXP1_CANCEL_RATE, EXP1_COLUMNS, EXP1_CSV, EXP1_RPS_VALUES,
    EXP2_CANCEL_RATE_RANGE, EXP2_CANCEL_RATE_STEP, EXP2_COLUMNS, EXP2_CSV, EXP2_RPS,
    EXP3_COLUMNS, EXP3_CSV,
    EXPERIMENT_DURATION, EXPERIMENT_SELECT,
    IDS_ALERT_KEYWORD, IDS_IPS_CONTAINER, IDS_LOG_A,
    RESULTS_DIR, TSHARK_IFACE, VICTIM_CONTAINER, VICTIM_IP,
    VICTIM_METRICS_FILE_HOST,
)


# ── Script sync ───────────────────────────────────────────────────────────────

def sync_attacker_script():
    """docker cp로 호스트의 attacker_multi.py를 컨테이너에 복사.
    이미지 재빌드 없이 --rps 등 최신 변경사항을 반영한다."""
    src = os.path.abspath(ATTACKER_SCRIPT)
    dst = f"{ATTACKER_CONTAINER}:/root/{ATTACKER_SCRIPT}"
    r = subprocess.run(
        ["docker", "cp", src, dst],
        capture_output=True, encoding="utf-8",
    )
    if r.returncode != 0:
        print(f"  ❌ {ATTACKER_SCRIPT} 동기화 실패: {r.stderr.strip()}")
        sys.exit(1)
    print(f"    [docker cp {ATTACKER_SCRIPT} → {ATTACKER_CONTAINER} ✓]")


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


def clear_ids_log():
    docker_exec(IDS_IPS_CONTAINER,
                f"truncate -s 0 {IDS_LOG_A} 2>/dev/null; touch {IDS_LOG_A}")
    _log("ids_a.log cleared")


def start_detector():
    docker_exec(IDS_IPS_CONTAINER, "pkill -f tshark   || true")
    docker_exec(IDS_IPS_CONTAINER, "pkill -f detector || true")
    time.sleep(1.5)
    tshark = (
        f"tshark -i {TSHARK_IFACE} -d tcp.port==80,http2 -Nn -l "
        f"-T fields -e ip.src -e http2.type -E separator=, "
        f"-Y 'http2 and ip.dst == {VICTIM_IP}' 2>/dev/null"
    )
    pipeline = (
        f"{tshark} "
        f"| stdbuf -oL python3 -u /root/detector.py "
        f"| tee {IDS_LOG_A}"
    )
    docker_exec(IDS_IPS_CONTAINER, pipeline, detach=True)
    _log("detector MODE A started")
    time.sleep(2.0)


def stop_detector():
    docker_exec(IDS_IPS_CONTAINER, "pkill -f tshark   || true")
    docker_exec(IDS_IPS_CONTAINER, "pkill -f detector || true")
    time.sleep(0.5)


def start_victim_monitor():
    docker_exec(VICTIM_CONTAINER, "pkill -f victim_monitor.py || true")
    time.sleep(0.3)
    docker_exec(VICTIM_CONTAINER, "python3 /root/victim_monitor.py", detach=True)
    time.sleep(1.0)


def stop_victim_monitor():
    docker_exec(VICTIM_CONTAINER, "pkill -f victim_monitor.py || true")
    time.sleep(0.3)


def start_client_traffic():
    docker_exec(CLIENT_CONTAINER, f"pkill -f {CLIENT_SCRIPT} || true")
    time.sleep(0.3)
    docker_exec(CLIENT_CONTAINER,
                f"python3 /root/{CLIENT_SCRIPT} 0.1", detach=True)
    _log("client_vm 정상 트래픽 시작")
    time.sleep(1.0)


def stop_client_traffic():
    docker_exec(CLIENT_CONTAINER, f"pkill -f {CLIENT_SCRIPT} || true")
    _log("client_vm 트래픽 종료")


def run_attack(cancel_rate: float, rps: int, duration: int):
    cmd = (
        f"python3 /root/{ATTACKER_SCRIPT} {cancel_rate} "
        f"--duration {duration} --rps {rps}"
    )
    docker_exec(ATTACKER_CONTAINER, cmd, detach=True)
    _log(f"attack  cancel_rate={cancel_rate:.4f}  rps={rps}  duration={duration}s")


def stop_attack():
    docker_exec(ATTACKER_CONTAINER, f"pkill -f {ATTACKER_SCRIPT} || true")


# ── Result collection ──────────────────────────────────────────────────────────

def check_ids_alert() -> bool:
    content = docker_exec(IDS_IPS_CONTAINER, f"cat {IDS_LOG_A} 2>/dev/null || true")
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


def append_csv(path: str, columns: list, row: dict):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    new_file = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
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


def _cooldown():
    sys.stdout.write("  cooldown ")
    _progress(COOLDOWN_BETWEEN_EXPERIMENTS)


def _print_timing():
    per_run   = EXPERIMENT_DURATION + COOLDOWN_BETWEEN_EXPERIMENTS
    exp1_runs = len(EXP1_RPS_VALUES)
    exp2_scan = round((EXP2_CANCEL_RATE_RANGE[1] - EXP2_CANCEL_RATE_RANGE[0])
                      / EXP2_CANCEL_RATE_STEP) + 1
    exp2_bs   = BINARY_SEARCH_MAX_ITERATIONS * BINARY_SEARCH_TRIALS
    exp2_runs = exp2_scan + exp2_bs
    exp3_runs = exp2_scan

    # 각 run의 실제 소요: duration + cooldown + setup 오버헤드(tshark 워밍업 등 ~4s)
    overhead  = 4
    per_run_actual = per_run + overhead

    t1 = exp1_runs * per_run_actual
    t2 = exp2_runs * per_run_actual
    t3 = exp3_runs * per_run_actual
    total = t1 + t2 + t3

    sel = EXPERIMENT_SELECT
    print("\n  ┌─ 예상 소요 시간 ────────────────────────────────")
    unit = f"{per_run}s+{overhead}s"
    if sel in ("1", "all"):
        print(f"  │  실험 1 (RPS 스윕):        {exp1_runs:2d}회 × ({unit}) = {t1}s  "
              f"(~{t1//60}분 {t1%60:02d}초)")
    if sel in ("2", "all"):
        print(f"  │  실험 2 (cancel 스윕):  최대 {exp2_runs:2d}회 × ({unit}) = {t2}s  "
              f"(~{t2//60}분 {t2%60:02d}초)")
    if sel in ("3", "all"):
        print(f"  │  실험 3 (혼합 트래픽):     {exp3_runs:2d}회 × ({unit}) = {t3}s  "
              f"(~{t3//60}분 {t3%60:02d}초)")
    if sel == "all":
        total_runs = exp1_runs + exp2_runs + exp3_runs
        print(f"  │  전체 합계:          최대 {total_runs:2d}회  "
              f"≈ {total}s (~{total//60}분 {total%60:02d}초)")
    print("  └────────────────────────────────────────────────")


# ── Core single-run function ───────────────────────────────────────────────────

def single_run(cancel_rate: float, rps: int, with_client: bool = False) -> dict:
    reset_iptables()
    clear_ids_log()
    start_detector()
    start_victim_monitor()
    if with_client:
        start_client_traffic()
    time.sleep(1)

    run_attack(cancel_rate, rps, EXPERIMENT_DURATION)
    _progress(EXPERIMENT_DURATION, "attack ")

    ids_alert   = check_ids_alert()
    ips_blocked = check_ips_blocked()
    metrics     = read_victim_metrics()

    stop_attack()
    if with_client:
        stop_client_traffic()
    stop_victim_monitor()
    stop_detector()

    cpu_avg  = round(metrics.get("cpu_avg",  0.0), 2)
    cpu_max  = round(metrics.get("cpu_max",  0.0), 2)
    exceeded = metrics.get("threshold_exceeded", False)

    fa = "🚨" if ids_alert else "  "
    fc = "⚠️ " if exceeded else "  "
    print(
        f"  ← {fa}IDS={str(ids_alert):<5}  "
        f"{fc}CPU avg={cpu_avg:5.1f}%  max={cpu_max:5.1f}%"
    )

    return {
        "ids_alert":             ids_alert,
        "ips_blocked":           ips_blocked,
        "victim_cpu_avg":        cpu_avg,
        "victim_cpu_max":        cpu_max,
        "cpu_threshold_exceeded": exceeded,
        "timestamp":             datetime.now().isoformat(timespec="seconds"),
    }


# ── Experiment 1: RPS sweep ────────────────────────────────────────────────────

def experiment_1() -> int:
    print("\n" + "=" * 66)
    print("  실험 1 — RPS 스윕  (cancel_rate=1.0 고정, CPU 기준선 확보)")
    print(f"  RPS: {EXP1_RPS_VALUES}  duration={EXPERIMENT_DURATION}s")
    print("=" * 66)

    results = []
    for rps in EXP1_RPS_VALUES:
        print(f"\n  ▶  RPS={rps}  cancel_rate={EXP1_CANCEL_RATE:.1f}")
        m = single_run(EXP1_CANCEL_RATE, rps)
        row = {
            "experiment":             1,
            "rps":                    rps,
            "cancel_rate":            EXP1_CANCEL_RATE,
            "duration_sec":           EXPERIMENT_DURATION,
            **{k: m[k] for k in ("ids_alert", "ips_blocked",
                                  "victim_cpu_avg", "victim_cpu_max",
                                  "cpu_threshold_exceeded", "timestamp")},
        }
        append_csv(EXP1_CSV, EXP1_COLUMNS, row)
        results.append((rps, m["victim_cpu_avg"]))
        _cooldown()

    print(f"\n  실험 1 완료. CPU 결과:")
    for rps, cpu in results:
        mark = " ←" if abs(cpu - CPU_TARGET_FOR_EXP2) == min(abs(c - CPU_TARGET_FOR_EXP2) for _, c in results) else ""
        print(f"    RPS={rps:4d}  CPU avg={cpu:5.1f}%{mark}")

    # 목표 CPU에 가장 가까운 RPS 선택
    fixed_rps = min(results, key=lambda x: abs(x[1] - CPU_TARGET_FOR_EXP2))[0]
    print(f"\n  🎯 실험 2/3 고정 RPS: {fixed_rps}  "
          f"(CPU≈{CPU_TARGET_FOR_EXP2:.0f}% 기준)")
    print(f"  📁 {EXP1_CSV}")
    return fixed_rps


# ── Experiment 2: cancel_rate sweep + binary search ───────────────────────────

def _cancel_rate_points() -> list:
    points = []
    cr = EXP2_CANCEL_RATE_RANGE[0]
    while cr <= EXP2_CANCEL_RATE_RANGE[1] + 1e-9:
        points.append(round(cr, 4))
        cr = round(cr + EXP2_CANCEL_RATE_STEP, 4)
    return points


def _exp2_run(phase: int, trial: int, cancel_rate: float, rps: int) -> dict:
    print(f"\n  ▶  phase={phase}  trial={trial}  "
          f"cancel_rate={cancel_rate:.4f}  RPS={rps}")
    m = single_run(cancel_rate, rps)
    row = {
        "experiment":             2,
        "phase":                  phase,
        "trial":                  trial,
        "cancel_rate":            cancel_rate,
        "rps":                    rps,
        "duration_sec":           EXPERIMENT_DURATION,
        **{k: m[k] for k in ("ids_alert", "ips_blocked",
                              "victim_cpu_avg", "victim_cpu_max",
                              "cpu_threshold_exceeded", "timestamp")},
    }
    append_csv(EXP2_CSV, EXP2_COLUMNS, row)
    return row


def experiment_2(fixed_rps: int) -> float | None:
    print("\n" + "=" * 66)
    print(f"  실험 2 — cancel_rate 스윕  (RPS={fixed_rps} 고정)")
    print(f"  cancel_rate: {EXP2_CANCEL_RATE_RANGE[0]}→{EXP2_CANCEL_RATE_RANGE[1]}"
          f"  step={EXP2_CANCEL_RATE_STEP}  이후 바이너리 서치 (최대 {BINARY_SEARCH_MAX_ITERATIONS}회)")
    print("=" * 66)

    # Phase 1: linear scan
    detected = []
    for cr in _cancel_rate_points():
        row = _exp2_run(phase=1, trial=1, cancel_rate=cr, rps=fixed_rps)
        if row["ids_alert"] and cr not in detected:
            detected.append(cr)
        _cooldown()

    print(f"\n  Phase 1 완료. 탐지된 cancel_rate: "
          + (str(sorted(detected)) if detected else "없음"))

    if not detected:
        print("  ⚠️  탐지 없음 — 바이너리 서치 스킵.")
        print(f"  📁 {EXP2_CSV}")
        return None

    # Phase 2: binary search (MODE A, max BINARY_SEARCH_MAX_ITERATIONS)
    min_detected = min(detected)
    lo = round(max(0.0, min_detected - EXP2_CANCEL_RATE_STEP), 4)
    hi = min_detected
    threshold = hi

    print(f"\n  Phase 2 — 바이너리 서치  [{lo:.4f}, {hi:.4f}]")

    iteration = 0
    while hi - lo > BINARY_SEARCH_PRECISION and iteration < BINARY_SEARCH_MAX_ITERATIONS:
        iteration += 1
        mid = round((lo + hi) / 2, 4)
        print(f"\n    [{lo:.4f}, {hi:.4f}]  mid={mid:.4f}  "
              f"iter={iteration}/{BINARY_SEARCH_MAX_ITERATIONS}  "
              f"({BINARY_SEARCH_TRIALS}회 시도, "
              f"≥{BINARY_SEARCH_SUCCESS_THRESHOLD}회 탐지 시 하향)")

        successes = 0
        for trial in range(1, BINARY_SEARCH_TRIALS + 1):
            row = _exp2_run(phase=2, trial=trial, cancel_rate=mid, rps=fixed_rps)
            if row["ids_alert"]:
                successes += 1
            if trial < BINARY_SEARCH_TRIALS:
                _cooldown()

        detected_mid = successes >= BINARY_SEARCH_SUCCESS_THRESHOLD
        direction = "하향 ↓" if detected_mid else "상향 ↑"
        print(f"    → {successes}/{BINARY_SEARCH_TRIALS}  {direction}")

        if detected_mid:
            threshold = mid
            hi = mid
        else:
            lo = mid

        _cooldown()

    print(f"\n  🎯 MODE A 탐지 임계치: {threshold:.4f}  ({threshold * 100:.2f}%)")
    print(f"  📁 {EXP2_CSV}")
    return threshold


# ── Experiment 3: mixed traffic ────────────────────────────────────────────────

def experiment_3(fixed_rps: int):
    print("\n" + "=" * 66)
    print(f"  실험 3 — 혼합 트래픽  (RPS={fixed_rps} + client_vm 정상 트래픽)")
    print(f"  cancel_rate: {EXP2_CANCEL_RATE_RANGE[0]}→{EXP2_CANCEL_RATE_RANGE[1]}"
          f"  step={EXP2_CANCEL_RATE_STEP}")
    print("=" * 66)

    for cr in _cancel_rate_points():
        print(f"\n  ▶  cancel_rate={cr:.2f}  RPS={fixed_rps}  +client_vm")
        m = single_run(cr, fixed_rps, with_client=True)
        row = {
            "experiment":             3,
            "cancel_rate":            cr,
            "rps":                    fixed_rps,
            "client_active":          True,
            "duration_sec":           EXPERIMENT_DURATION,
            **{k: m[k] for k in ("ids_alert", "ips_blocked",
                                  "victim_cpu_avg", "victim_cpu_max",
                                  "cpu_threshold_exceeded", "timestamp")},
        }
        append_csv(EXP3_CSV, EXP3_COLUMNS, row)
        _cooldown()

    print(f"\n  실험 3 완료.")
    print(f"  📁 {EXP3_CSV}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    sel = EXPERIMENT_SELECT

    print("=" * 66)
    print("  🚀 HTTP/2 Rapid Reset Orchestrator v2")
    sync_attacker_script()
    print(f"     실험 선택: {sel}  |  duration={EXPERIMENT_DURATION}s  "
          f"cooldown={COOLDOWN_BETWEEN_EXPERIMENTS}s")
    print(f"     IPS: 비활성화  |  CPU 임계치: {CPU_THRESHOLD}%")
    print("=" * 66)

    _print_timing()

    fixed_rps = EXP2_RPS  # default fallback

    if sel in ("1", "all"):
        fixed_rps = experiment_1()

    if sel in ("2", "all"):
        experiment_2(fixed_rps)

    if sel in ("3", "all"):
        experiment_3(fixed_rps)

    if sel not in ("1", "2", "3", "all"):
        print(f"  ❌ 알 수 없는 EXPERIMENT_SELECT={sel!r}")
        print("     config.py에서 '1', '2', '3', 'all' 중 하나로 설정하세요.")
        sys.exit(1)

    print("\n" + "=" * 66)
    print("  ✅  모든 실험 완료")
    if sel in ("1", "all"):
        print(f"  📁  실험 1: {EXP1_CSV}")
    if sel in ("2", "all"):
        print(f"  📁  실험 2: {EXP2_CSV}")
    if sel in ("3", "all"):
        print(f"  📁  실험 3: {EXP3_CSV}")
    print("=" * 66)


if __name__ == "__main__":
    main()
