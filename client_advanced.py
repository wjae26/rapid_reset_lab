import time
import socket
import ssl
import random
import h2.connection
import h2.errors

VICTIM_IP = "192.168.20.10"
VICTIM_PORT = 80

def send_advanced_traffic():
    print(f"✅ [Client] 고급 정상 트래픽 시뮬레이션 시작 (대상: {VICTIM_IP})")
    print("정상적인 요청 사이에 '뒤로가기'와 같은 간헐적인 취소(RST_STREAM)를 섞어 보냅니다.")

    while True:
        try:
            # SSL 없이 평문 TCP 연결 사용
            sock = socket.create_connection((VICTIM_IP, VICTIM_PORT))
            
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # 한 연결에서 여러 번의 요청 수행
            for _ in range(random.randint(3, 7)):
                stream_id = conn.get_next_available_stream_id()
                headers = [
                    (':method', 'GET'),
                    (':authority', VICTIM_IP),
                    (':scheme', 'https'),
                    (':path', '/'),
                    ('user-agent', 'Advanced-Normal-Client'),
                ]
                
                # 약 10~15% 확률로 사용자 취소 발생
                is_cancelled = random.random() < 0.15
                
                if is_cancelled:
                    conn.send_headers(stream_id, headers)
                    # 바로 RST_STREAM 전송 (Error Code: CANCEL)
                    conn.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
                    print(f"↪️ [Advanced Traffic] User Cancelled (Back Button) | Stream ID: {stream_id}")
                else:
                    conn.send_headers(stream_id, headers, end_stream=True)
                    print(f"🌐 [Advanced Traffic] Request Completed | Stream ID: {stream_id}")
                
                sock.sendall(conn.data_to_send())
                # 인간의 행동과 유사하게 간격을 둠
                time.sleep(random.uniform(0.8, 2.5))

            conn.close_connection()
            sock.sendall(conn.data_to_send())
            sock.close()

        except Exception as e:
            print(f"❌ [Advanced Traffic] Connection Issue: {e}")
        
        # 다음 세션까지 대기
        time.sleep(random.uniform(3.0, 6.0))

if __name__ == "__main__":
    try:
        send_advanced_traffic()
    except KeyboardInterrupt:
        print("\n👋 [Client] 고급 시뮬레이션을 종료합니다.")
