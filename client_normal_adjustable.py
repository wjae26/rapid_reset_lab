import time
import socket
import sys
import random
import h2.connection
import h2.errors

VICTIM_IP = "192.168.20.10"
VICTIM_PORT = 80

# 인자값으로 취소율 조절 (기본값 0.1 = 10%)
CANCEL_RATE = float(sys.argv[1]) if len(sys.argv) > 1 else 0.1

def send_adjustable_traffic():
    print(f"✅ [Client] 가변 정상 트래픽 시뮬레이션 시작 (대상: {VICTIM_IP})")
    print(f"설정된 취소율(Cancel Rate): {CANCEL_RATE * 100:.1f}%")
    print("정상적인 요청 사이에 설정된 확률로 취소(RST_STREAM)를 섞어 보냅니다.")

    while True:
        try:
            # SSL 없이 평문 TCP 연결 사용
            sock = socket.create_connection((VICTIM_IP, VICTIM_PORT), timeout=5)
            
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # 한 연결에서 여러 번의 요청 수행 (정상적인 Keep-Alive 동작 모사)
            for _ in range(random.randint(5, 15)):
                stream_id = conn.get_next_available_stream_id()
                headers = [
                    (':method', 'GET'),
                    (':authority', VICTIM_IP),
                    (':scheme', 'http'),
                    (':path', '/'),
                    ('user-agent', 'Adjustable-Normal-Client'),
                ]
                
                # 설정된 확률에 따라 취소 수행
                is_cancelled = random.random() < CANCEL_RATE
                
                if is_cancelled:
                    conn.send_headers(stream_id, headers)
                    # RST_STREAM 전송 (Error Code: CANCEL)
                    conn.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
                    print(f"↪️ [Adjustable Traffic] Request Cancelled | Stream ID: {stream_id}")
                else:
                    conn.send_headers(stream_id, headers, end_stream=True)
                    print(f"🌐 [Adjustable Traffic] Request Completed | Stream ID: {stream_id}")
                
                sock.sendall(conn.data_to_send())
                # 인간의 행동과 유사하게 간격을 둠 (0.5~2초)
                time.sleep(random.uniform(0.5, 2.0))

            conn.close_connection()
            sock.sendall(conn.data_to_send())
            sock.close()

        except Exception as e:
            print(f"❌ [Adjustable Traffic] Connection Issue: {e}")
            time.sleep(2)
        
        # 다음 세션까지 대기
        time.sleep(random.uniform(2.0, 5.0))

if __name__ == "__main__":
    try:
        send_adjustable_traffic()
    except KeyboardInterrupt:
        print("\n👋 [Client] 시뮬레이션을 종료합니다.")
