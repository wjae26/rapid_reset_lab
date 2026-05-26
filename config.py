# ── Experiment selection ───────────────────────────────────────────────────────
# "1", "2", "3", or "all"
EXPERIMENT_SELECT = "all"

# ── Timing ────────────────────────────────────────────────────────────────────
EXPERIMENT_DURATION          = 15   # seconds per run
COOLDOWN_BETWEEN_EXPERIMENTS = 10   # seconds between runs

# ── Experiment 1: RPS sweep (cancel_rate=1.0 fixed) ───────────────────────────
# --rps N = N threads × 0.001s sleep. 300 threads → CPU ≈ 50-55% (기존 실측 기준)
EXP1_RPS_VALUES  = [50, 150, 250, 300]
EXP1_CANCEL_RATE = 1.0
EXP1_CSV         = "./results/exp1_rps_sweep.csv"

# ── Experiment 2: cancel_rate sweep (fixed RPS from exp1) ─────────────────────
# Auto-detected from exp1 (CPU ≈ 50%). Set manually when running exp2 standalone.
EXP2_RPS               = 300
EXP2_CANCEL_RATE_RANGE = (0.5, 1.0)
EXP2_CANCEL_RATE_STEP  = 0.1
EXP2_CSV               = "./results/exp2_cancel_sweep.csv"

# ── Experiment 3: mixed traffic (exp2 conditions + client_vm normal traffic) ───
EXP3_CSV      = "./results/exp3_mixed.csv"
CLIENT_SCRIPT = "client_normal_adjustable.py"

# ── CPU target for RPS baseline detection (exp1 → exp2) ───────────────────────
CPU_TARGET_FOR_EXP2 = 50.0   # percent

# ── Binary search (exp2 phase 2) ──────────────────────────────────────────────
BINARY_SEARCH_PRECISION         = 0.01
BINARY_SEARCH_TRIALS            = 2
BINARY_SEARCH_SUCCESS_THRESHOLD = 1
BINARY_SEARCH_MAX_ITERATIONS    = 4

# ── Detection ─────────────────────────────────────────────────────────────────
IDS_ALERT_KEYWORD = "[ALERT]"
CPU_THRESHOLD     = 70.0    # percent; must match victim_monitor.py

# ── Container names ───────────────────────────────────────────────────────────
ATTACKER_SCRIPT    = "attacker_multi.py"
ATTACKER_CONTAINER = "attacker_vm_1"
CLIENT_CONTAINER   = "client_vm"
VICTIM_CONTAINER   = "victim"
IDS_IPS_CONTAINER  = "ids_ips_vm"

# ── Result paths (host-side) ──────────────────────────────────────────────────
RESULTS_DIR              = "./results"
VICTIM_METRICS_FILE_HOST = "./results/victim_metrics.json"

# ── Container-side IDS log paths ──────────────────────────────────────────────
IDS_LOG_A = "/root/ids_a.log"
IDS_LOG_B = "/root/ids_b.log"

# ── tshark capture settings ───────────────────────────────────────────────────
TSHARK_IFACE = "eth0"
VICTIM_IP    = "192.168.20.10"

# ── CSV schemas ───────────────────────────────────────────────────────────────
EXP1_COLUMNS = [
    "experiment", "rps", "cancel_rate", "duration_sec",
    "ids_alert", "ips_blocked",
    "victim_cpu_avg", "victim_cpu_max", "cpu_threshold_exceeded",
    "timestamp",
]
EXP2_COLUMNS = [
    "experiment", "phase", "trial", "cancel_rate", "rps", "duration_sec",
    "ids_alert", "ips_blocked",
    "victim_cpu_avg", "victim_cpu_max", "cpu_threshold_exceeded",
    "timestamp",
]
EXP3_COLUMNS = [
    "experiment", "cancel_rate", "rps", "client_active", "duration_sec",
    "ids_alert", "ips_blocked",
    "victim_cpu_avg", "victim_cpu_max", "cpu_threshold_exceeded",
    "timestamp",
]

# ── Legacy aliases (report.py compatibility) ───────────────────────────────────
EXPERIMENT_LOG    = "./results/experiment_log.csv"
CANCEL_RATE_RANGE = EXP2_CANCEL_RATE_RANGE
CANCEL_RATE_STEP  = EXP2_CANCEL_RATE_STEP
CSV_COLUMNS = [
    "phase", "trial", "cancel_rate", "mode", "duration_sec",
    "ids_alert", "ips_blocked",
    "victim_cpu_avg", "victim_cpu_max", "cpu_threshold_exceeded",
    "timestamp",
]
