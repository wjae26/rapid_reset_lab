import subprocess, sys, re, time
from collections import defaultdict

# 실시간 통계 저장
stats = defaultdict(lambda: {'headers': 0, 'resets': 0})

print("📊 [Victim Monitor] Incoming HTTP/2 Rapid Reset Traffic Monitoring...")
print("서버로 유입되는 HEADERS와 RST_STREAM 패킷을 분석합니다. (Ctrl+C로 종료)")

# tshark를 사용하여 서버(Port 80)로 들어오는 HTTP/2 패킷 캡처
cmd = [
    "tshark", "-i", "any", "-l", "-n",
    "-d", "tcp.port==80,http2",
    "-T", "fields",
    "-e", "ip.src", "-e", "http2.type",
    "-Y", "http2 and tcp.dstport == 80"
]

# tshark 실행
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

try:
    for line in process.stdout:
        line = line.strip()
        if not line: continue
        parts = line.split('\t')
        if len(parts) < 2: continue
        
        src_ip = parts[0]
        types = parts[1].split(',')
        
        for t in types:
            if t == '1': # HEADERS (요청)
                stats[src_ip]['headers'] += 1
            elif t == '3': # RST_STREAM (취소)
                stats[src_ip]['resets'] += 1
        
        h = stats[src_ip]['headers']
        r = stats[src_ip]['resets']
        
        # 100개 단위로 통계 출력
        if h >= 100:
            rate = (r / h) * 100
            print(f"📈 [VICTIM VIEW] Attacker: {src_ip} | Total Req: {h} | Resets: {r} | Cancel Rate: {rate:.1f}%")
            # 누적 통계 초기화 (실시간 변화 확인용)
            stats[src_ip]['headers'] = 0
            stats[src_ip]['resets'] = 0
except KeyboardInterrupt:
    print("\n👋 모니터링을 종료합니다.")
    process.terminate()
except Exception as e:
    print(f"❌ 오류 발생: {e}")
    process.terminate()
