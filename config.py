# ── Experiment sweep ──────────────────────────────────────────────────────────
CANCEL_RATE_RANGE   = (0.5, 1.0)   # (min, max) inclusive
CANCEL_RATE_STEP    = 0.1
EXPERIMENT_DURATION = 20           # seconds per single run  (was 30)
COOLDOWN_BETWEEN_EXPERIMENTS = 15  # seconds between runs    (was 30)

# ── Detection ─────────────────────────────────────────────────────────────────
IDS_ALERT_KEYWORD = "[ALERT]"

# ── Victim CPU ────────────────────────────────────────────────────────────────
# Must match CPU_THRESHOLD constant in victim_monitor.py
CPU_THRESHOLD = 70.0               # percent

# ── Phase-2 binary search (MODE A only) ───────────────────────────────────────
BINARY_SEARCH_PRECISION        = 0.01
BINARY_SEARCH_TRIALS           = 2    # was 3
BINARY_SEARCH_SUCCESS_THRESHOLD = 1   # out of BINARY_SEARCH_TRIALS  (was 2)

# ── Container names ───────────────────────────────────────────────────────────
ATTACKER_SCRIPT     = "attacker_multi.py"   # switch to attacker_single.py for single-thread
ATTACKER_CONTAINER  = "attacker_vm_1"
VICTIM_CONTAINER    = "victim"
IDS_IPS_CONTAINER   = "ids_ips_vm"

# ── Result paths (host-side) ──────────────────────────────────────────────────
RESULTS_DIR              = "./results"
EXPERIMENT_LOG           = "./results/experiment_log.csv"
VICTIM_METRICS_FILE_HOST = "./results/victim_metrics.json"

# ── Container-side IDS log paths ──────────────────────────────────────────────
# Phase 1 dual: A and B write to separate files (same tshark traffic)
# Phase 2: MODE A only, writes to IDS_LOG_A
IDS_LOG_A = "/root/ids_a.log"
IDS_LOG_B = "/root/ids_b.log"

# ── tshark capture settings ───────────────────────────────────────────────────
TSHARK_IFACE = "eth0"
VICTIM_IP    = "192.168.20.10"

# ── CSV schema ────────────────────────────────────────────────────────────────
CSV_COLUMNS = [
    "phase", "trial",
    "cancel_rate", "mode", "duration_sec",
    "ids_alert", "ips_blocked",
    "victim_cpu_avg", "victim_cpu_max", "cpu_threshold_exceeded",
    "timestamp",
]
