import time
import socket
import ssl
import random
import h2.connection
import h2.errors

VICTIM_IP = "192.168.20.10"
VICTIM_PORT = 80

def send_burst_traffic():
    print(f"🖼️ [Client] 대용량 리소스 페이지 접속 시뮬레이션 (대상: {VICTIM_IP})")
    print("페이지 로딩 중 '뒤로가기'를 눌러 수십 개의 스트림이 동시에 취소되는 상황을 재현합니다.")

    while True:
        try:
            # SSL 없이 평문 TCP 연결 사용
            sock = socket.create_connection((VICTIM_IP, VICTIM_PORT))
            
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # 1. 페이지 접속 (메인 HTML 로드)
            main_id = conn.get_next_available_stream_id()
            conn.send_headers(main_id, [(':method', 'GET'), (':path', '/')], end_stream=True)
            sock.sendall(conn.data_to_send())
            print(f"📄 [Burst Traffic] Main HTML Loading...")
            time.sleep(0.5)

            # 2. 이미지/리소스 대량 요청 (40~60개)
            resource_ids = []
            print(f"📸 [Burst Traffic] Requesting 50+ Images/Assets...")
            for _ in range(random.randint(40, 60)):
                sid = conn.get_next_available_stream_id()
                conn.send_headers(sid, [(':method', 'GET'), (':path', f'/img_{sid}.png')], end_stream=True)
                resource_ids.append(sid)
            sock.sendall(conn.data_to_send())

            # 3. 로딩 중 사용자 이탈 (뒤로가기 클릭!)
            time.sleep(0.2)
            print(f"⏹️ [Burst Traffic] USER HIT BACK BUTTON! Cancelling all streams...")
            for sid in resource_ids:
                conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
            sock.sendall(conn.data_to_send())
            print(f"✅ [Burst Traffic] {len(resource_ids)} streams cancelled at once.")

            conn.close_connection()
            sock.sendall(conn.data_to_send())
            sock.close()

        except Exception as e:
            print(f"❌ [Burst Traffic] Error: {e}")
        
        time.sleep(random.uniform(5.0, 10.0))

if __name__ == "__main__":
    try:
        send_burst_traffic()
    except KeyboardInterrupt:
        print("\n👋 [Client] 시뮬레이션을 종료합니다.")
