import subprocess, re, time, os

LOG_FILE = "/root/ids.log"
blocked_ips = set()

print("🛡️ [IPS MODE] 차단기 가동 중... 로그를 모니터링합니다.")

# 로그 파일이 생성될 때까지 대기
while not os.path.exists(LOG_FILE):
    time.sleep(1)

with open(LOG_FILE, "r") as f:
    # 파일의 끝으로 이동
    f.seek(0, 2)
    
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
            
        if "[ALERT]" in line:
            match = re.search(r"IP: ([\d\.]+)", line)
            if match:
                ip = match.group(1)
                if ip not in blocked_ips:
                    print(f"🚫 [IPS ACTION] 공격 감지됨! IP {ip}를 차단합니다.")
                    try:
                        subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
                        blocked_ips.add(ip)
                        print(f"✅ [IPS ACTION] IP {ip} 차단 완료.")
                    except Exception as e:
                        print(f"❌ [IPS ACTION] 차단 실패: {e}")
