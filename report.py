"""
report.py — Experiment result visualiser
=========================================
Reads experiment_log.csv and prints:
  1. Phase 1 summary table (MODE A vs B per cancel_rate)
  2. Phase 2 binary search walkthrough (MODE A)
  3. MODE A vs MODE B sensitivity comparison
  4. CPU interpretation with action hint

Usage:
  python report.py                         # reads default path from config.py
  python report.py results/custom.csv      # explicit path
"""

import csv
import os
import sys
from collections import defaultdict

from config import (
    BINARY_SEARCH_SUCCESS_THRESHOLD, BINARY_SEARCH_TRIALS,
    CANCEL_RATE_STEP, CPU_THRESHOLD, EXPERIMENT_LOG,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _bv(s) -> bool:
    return str(s).strip().lower() in ("true", "1", "yes")


def _fv(s) -> float:
    try:
        return float(s)
    except Exception:
        return 0.0


def _load(path: str) -> list:
    if not os.path.exists(path):
        print(f"❌  {path} 없음. orchestrator.py를 먼저 실행하세요.")
        sys.exit(1)
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _sep(char="=", width=70):
    print(char * width)


# ── Section 1: Phase 1 table ───────────────────────────────────────────────────

def print_phase1_table(rows: list):
    phase1 = [r for r in rows if r.get("phase", "1") == "1"]
    if not phase1:
        print("  Phase 1 데이터 없음.")
        return

    by_rate: dict = defaultdict(dict)
    for r in phase1:
        by_rate[round(_fv(r["cancel_rate"]), 4)][r["mode"]] = r

    _sep()
    print("  Phase 1 — Linear Scan Summary")
    _sep()
    header = f"  {'cancel_rate':>12}  {'MODE A IDS':>12}  {'MODE B IDS':>12}  {'CPU avg':>8}  {'CPU max':>8}"
    print(header)
    print("  " + "-" * 62)

    for cr in sorted(by_rate):
        modes = by_rate[cr]
        a = modes.get("A", {})
        b = modes.get("B", {})

        a_alert = _bv(a.get("ids_alert", "False"))
        b_alert = _bv(b.get("ids_alert", "False"))

        # CPU is shared (same attack); prefer row_a, fallback to row_b
        cpu_avg = _fv(a.get("victim_cpu_avg") or b.get("victim_cpu_avg", 0))
        cpu_max = _fv(a.get("victim_cpu_max") or b.get("victim_cpu_max", 0))

        a_str = "🚨 True " if a_alert else "   False"
        b_str = "🚨 True " if b_alert else "   False"
        cpu_flag = " ⚠️" if cpu_max >= CPU_THRESHOLD else "  "

        print(f"  {cr:>12.2f}  {a_str:>12}  {b_str:>12}  "
              f"{cpu_avg:>7.1f}%  {cpu_max:>7.1f}%{cpu_flag}")

    print()


# ── Section 2: Phase 2 walkthrough ────────────────────────────────────────────

def print_phase2_walkthrough(rows: list):
    phase2 = sorted(
        [r for r in rows if r.get("phase", "") == "2"],
        key=lambda r: r["timestamp"],
    )
    if not phase2:
        print("\n  Phase 2 데이터 없음.")
        return

    _sep()
    print("  Phase 2 — Binary Search Walkthrough  (MODE A)")
    _sep()
    print(f"  수렴 기준: {BINARY_SEARCH_TRIALS}회 중 {BINARY_SEARCH_SUCCESS_THRESHOLD}회 이상 탐지\n")

    # Group consecutive rows with the same cancel_rate into one iteration
    iterations: list[tuple] = []
    i = 0
    while i < len(phase2):
        cr = round(_fv(phase2[i]["cancel_rate"]), 4)
        group = []
        while i < len(phase2) and abs(_fv(phase2[i]["cancel_rate"]) - cr) < 1e-9:
            group.append(phase2[i])
            i += 1
        iterations.append((cr, group))

    final_threshold = None

    for idx, (cr, group) in enumerate(iterations):
        successes = sum(1 for r in group if _bv(r["ids_alert"]))
        total     = len(group)
        detected  = successes >= BINARY_SEARCH_SUCCESS_THRESHOLD

        # Direction hint
        if idx < len(iterations) - 1:
            next_cr = _fv(iterations[idx + 1][0])
            direction = "하향 조정 ↓" if next_cr < cr else "상향 조정 ↑"
        else:
            direction = "수렴 확정 ✅"

        flag = "🚨" if detected else "  "
        print(f"  {flag} {cr:.4f} ({cr*100:.2f}%)  →  "
              f"{successes}/{total} 탐지  →  {direction}")

        if direction == "수렴 확정 ✅":
            final_threshold = cr

    if final_threshold is not None:
        reason = (f"{BINARY_SEARCH_TRIALS}회 기준 "
                  f"{BINARY_SEARCH_SUCCESS_THRESHOLD}회 이상 탐지로 수렴")
        print(f"\n  최종 임계치: {final_threshold:.4f}  "
              f"({final_threshold * 100:.2f}%)  — {reason}")
    print()


# ── Section 3: MODE A vs B comparison ─────────────────────────────────────────

def print_mode_comparison(rows: list):
    phase1 = [r for r in rows if r.get("phase", "1") == "1"]

    a_hits = sorted({round(_fv(r["cancel_rate"]), 4)
                     for r in phase1 if r["mode"] == "A" and _bv(r["ids_alert"])})
    b_hits = sorted({round(_fv(r["cancel_rate"]), 4)
                     for r in phase1 if r["mode"] == "B" and _bv(r["ids_alert"])})

    _sep()
    print("  MODE A vs MODE B — Sensitivity Comparison")
    _sep()

    a_min = a_hits[0]  if a_hits else None
    b_min = b_hits[0]  if b_hits else None

    a_label = f"{a_min:.2f} ({a_min*100:.1f}%)" if a_min is not None else "미탐지"
    b_label = f"{b_min:.2f} ({b_min*100:.1f}%)" if b_min is not None else "미탐지"

    print(f"  MODE A (누적 200건 카운트 방식)    최초 탐지: {a_label}")
    print(f"  MODE B (슬라이딩 10초 윈도우 방식) 최초 탐지: {b_label}")
    print()

    if a_min is not None and b_min is not None:
        diff = round(abs(a_min - b_min) * 100, 1)
        if a_min < b_min:
            print(f"  해석: MODE A가 {diff}%p 더 낮은 cancel_rate에서 탐지 → MODE A가 더 민감합니다.")
            print(f"  이유: 누적 카운팅은 총량 기반이므로 낮은 취소율에서도 충분히 쌓이면 조기 탐지 가능.")
        elif b_min < a_min:
            print(f"  해석: MODE B가 {diff}%p 더 낮은 cancel_rate에서 탐지 → MODE B가 더 민감합니다.")
            print(f"  이유: 슬라이딩 윈도우는 최근 패턴만 평가하므로 급격한 취소 급증에 빠르게 반응.")
        else:
            print(f"  해석: 두 모드가 동일 cancel_rate({a_min:.2f})에서 탐지됨 — 임계치가 동일합니다.")
    elif a_min is not None:
        print(f"  해석: MODE A만 탐지. "
              f"MODE B 슬라이딩 윈도우(10s)에서 MIN_REQUESTS 미충족 또는 취소율 집계 시점 차이.")
    elif b_min is not None:
        print(f"  해석: MODE B만 탐지. "
              f"MODE A 누적 200건 도달 전 실험 종료됐을 가능성 — EXPERIMENT_DURATION 연장을 고려하세요.")
    else:
        print(f"  해석: 두 모드 모두 탐지 없음 — cancel_rate 범위 상향 또는 공격 강도 증가가 필요합니다.")

    print()


# ── Section 4: CPU interpretation ─────────────────────────────────────────────

def print_cpu_interpretation(rows: list):
    phase1 = [r for r in rows if r.get("phase", "1") == "1"]

    cpu_maxes = [_fv(r["victim_cpu_max"]) for r in phase1 if _fv(r["victim_cpu_max"]) > 0]

    _sep()
    print("  CPU 측정값 해석")
    _sep()

    if not cpu_maxes:
        print("  CPU 측정값 없음 — victim_monitor.py 실행 여부를 확인하세요.")
        print()
        return

    g_max = max(cpu_maxes)
    g_avg = sum(cpu_maxes) / len(cpu_maxes)

    print(f"  실험 전체  CPU max: {g_max:.1f}%  (평균 max: {g_avg:.1f}%)")
    print(f"  설정 임계치: {CPU_THRESHOLD}%")
    print()

    if g_max < CPU_THRESHOLD:
        print(f"  ⚠️  IPS 비활성화 상태에서도 CPU가 임계치에 도달하지 않았습니다.")
        print(f"     공격 강도(RPS, 스레드 수) 상향을 권장합니다.")
        print(f"     → attacker_multi.py 사용 또는 THREAD_COUNT 증가를 고려하세요.")
    else:
        print(f"  ✅  victim CPU가 임계치를 초과했습니다. 공격 성공으로 판단합니다.")
        exceeded = sorted({
            round(_fv(r["cancel_rate"]), 2)
            for r in phase1
            if _bv(r.get("cpu_threshold_exceeded", "False"))
        })
        if exceeded:
            print(f"     초과 발생 cancel_rate: {exceeded}")

    print()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else EXPERIMENT_LOG
    rows = _load(path)

    print()
    _sep("█")
    print("  Rapid Reset Lab — Experiment Report")
    print(f"  source: {path}  ({len(rows)} rows)")
    _sep("█")

    print_phase1_table(rows)
    print_phase2_walkthrough(rows)
    print_mode_comparison(rows)
    print_cpu_interpretation(rows)

    _sep()
    phase1_n = sum(1 for r in rows if r.get("phase", "1") == "1")
    phase2_n = sum(1 for r in rows if r.get("phase", "") == "2")
    print(f"  총 실험 행: {len(rows)}  (Phase 1: {phase1_n}  Phase 2: {phase2_n})")
    _sep()


if __name__ == "__main__":
    main()
