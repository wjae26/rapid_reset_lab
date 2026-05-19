import sys
import re
import time
from collections import defaultdict, deque

# ── MODE B: Sliding-window detector ──────────────────────────────────────────
# Maintains a per-IP sliding time window.
# RST count is tracked as a running integer so evaluation is O(1) per event,
# not O(window-size) — necessary for high-traffic scenarios (attacker_multi.py).

WINDOW_DURATION       = 10.0    # seconds
MIN_REQUESTS          = 10      # minimum events in window before evaluation
CANCEL_RATE_THRESHOLD = 90.0    # percent
ALERT_COOLDOWN        = 5.0     # seconds between repeated alerts per IP
MAX_EVENTS_PER_IP     = 20_000  # deque size cap: prevents memory explosion at
                                 # high traffic (300+ threads × 1ms = ~300k ev/s)

# traffic[ip]   = deque of (timestamp: float, is_rst: bool)
# rst_count[ip] = running count of RST entries currently in the deque
traffic   = defaultdict(deque)
rst_count = defaultdict(int)
last_alert_time = defaultdict(float)

print("🚀 [IDS ENGINE - MODE B] Sliding Window Detection Started.")
print(f"   Window={WINDOW_DURATION}s  MinReq={MIN_REQUESTS}  "
      f"Threshold={CANCEL_RATE_THRESHOLD}%  MaxEvents/IP={MAX_EVENTS_PER_IP}")
sys.stdout.flush()


def _evict(ip: str, now: float):
    """Remove entries older than WINDOW_DURATION and enforce size cap."""
    dq = traffic[ip]

    # Time-based eviction
    while dq and now - dq[0][0] > WINDOW_DURATION:
        _, was_rst = dq.popleft()
        if was_rst:
            rst_count[ip] -= 1

    # Size cap — evict oldest entries when deque grows too large
    while len(dq) > MAX_EVENTS_PER_IP:
        _, was_rst = dq.popleft()
        if was_rst:
            rst_count[ip] -= 1


for line in sys.stdin:
    try:
        c = line.strip()
        if not c or "," not in c:
            continue

        ip, data = c.split(",", 1)
        ip   = ip.strip()
        norm = data.replace("\\,", " ").replace(",", " ")

        h = len(re.findall(r"\b1\b", norm))
        r = len(re.findall(r"\b3\b", norm))

        now = time.time()
        dq  = traffic[ip]

        for _ in range(h):
            dq.append((now, False))
        for _ in range(r):
            dq.append((now, True))
            rst_count[ip] += 1

        _evict(ip, now)

        total = len(dq)
        if total < MIN_REQUESTS:
            continue

        rate = (rst_count[ip] / total) * 100

        if rate >= CANCEL_RATE_THRESHOLD:
            if now - last_alert_time[ip] >= ALERT_COOLDOWN:
                print(
                    f"🚨 [ALERT] Rapid Reset Attack Detected! "
                    f"IP: {ip} | Cancel Rate: {rate:.1f}% | Window Req: {total}"
                )
                sys.stdout.flush()
                last_alert_time[ip] = now

    except Exception:
        pass
