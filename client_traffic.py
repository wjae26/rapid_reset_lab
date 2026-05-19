import socket
import time
import sys
import random
import h2.connection
import h2.config

# 대상 서버 정보
TARGET_IP = '192.168.20.10'
TARGET_PORT = 80

print(f'✅ [Client] 정상 트래픽 시뮬레이션 시작 (대상: {TARGET_IP})')
print('이 스크립트는 h2 라이브러리를 사용하여 순수 HTTP/2 HEADERS만 전송합니다.')

while True:
    try:
        # 소켓 연결
        raw_socket = socket.create_connection((TARGET_IP, TARGET_PORT))
        # HTTP/2 연결 설정
        config = h2.config.H2Configuration(client_side=True)
        h2_conn = h2.connection.H2Connection(config=config)
        h2_conn.initiate_connection()
        raw_socket.sendall(h2_conn.data_to_send())
        
        stream_id = 1
        while True:
            # HTTP/2 HEADERS 생성
            headers = [
                (':method', 'GET'),
                (':authority', TARGET_IP),
                (':scheme', 'http'),
                (':path', '/'),
                ('user-agent', 'Normal-Client-H2')
            ]
            
            # 요청 전송 (RST_STREAM 없이 HEADERS만)
            h2_conn.send_headers(stream_id, headers, end_stream=True)
            raw_socket.sendall(h2_conn.data_to_send())
            
            print(f"🌐 [Normal Traffic] Request Sent (Stream ID: {stream_id})")
            
            stream_id += 2
            # 1~3초 간격으로 요청
            time.sleep(random.uniform(1.0, 3.0))
            
            # 연결 유지 상태 확인 및 데이터 수신 (필요 시)
            # data = raw_socket.recv(4096)
            
    except Exception as e:
        print(f"❌ [Connection Error] {e}. Retrying in 2 seconds...")
        time.sleep(2)
    except KeyboardInterrupt:
        print("\n👋 [Client] 프로그램을 종료합니다.")
        break
