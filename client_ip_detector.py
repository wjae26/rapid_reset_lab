import subprocess
import sys
import time

# 탐지 대상 IP (Client VM)
TARGET_IP = "192.168.10.30"

def monitor_client_only():
    print(f"🚀 [Victim] Monitoring EXCLUSIVELY for Client VM ({TARGET_IP})")
    print("이 스크립트는 다른 모든 IP를 필터링하고 192.168.10.30의 트래픽만 표시합니다.")
    print("----------------------------------------------------------------")
    print(f"{'TIME':<10} | {'SOURCE IP':<15} | {'H2 TYPE':<10}")
    print("-" * 40)

    # tshark 필터에서 아예 TARGET_IP만 잡도록 설정
    cmd = [
        "tshark", "-i", "any", "-l", "-n",
        "-d", "tcp.port==80,http2",
        "-T", "fields",
        "-e", "ip.src", "-e", "http2.type",
        "-Y", f"http2 and ip.src == {TARGET_IP}"
    ]

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        for line in process.stdout:
            line = line.strip()
            if not line: continue
            
            parts = line.split('\t')
            if len(parts) < 2: continue
            
            src_ip = parts[0]
            h2_types = parts[1]
            
            # 2중 체크: 타겟 IP가 아니면 무시
            if src_ip != TARGET_IP:
                continue

            current_time = time.strftime("%H:%M:%S")
            
            # HEADERS(1) 또는 RST_STREAM(3) 등이 있는지 확인
            type_list = h2_types.split(',')
            for t in type_list:
                if t == '1':
                    type_name = "HEADERS"
                elif t == '3':
                    type_name = "RST_STREAM"
                else:
                    continue # 다른 패킷 타입은 무시 (필요시 제거 가능)
                
                print(f"{current_time:<10} | {src_ip:<15} | {type_name:<10}")
                
    except KeyboardInterrupt:
        print("\n👋 모니터링을 종료합니다.")
        process.terminate()
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        if 'process' in locals():
            process.terminate()

if __name__ == "__main__":
    monitor_client_only()
