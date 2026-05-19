import sys, re, time
from collections import defaultdict

traffic_ledger = defaultdict(lambda: {'req_count': 0, 'rst_count': 0})
last_alert_time = defaultdict(float)

print('🚀 [IDS ENGINE] Real-time Traffic Profiling Started...')
sys.stdout.flush()

for line in sys.stdin:
    try:
        c = line.strip()
        if not c or ',' not in c: continue
        
        ip, data = c.split(',', 1)
        ip = ip.strip()
        
        # tshark uses '\,' to escape commas when multiple frames are in one packet.
        norm = data.replace('\\,', ' ').replace(',', ' ')
        
        # Look for type 1 (HEADERS) and type 3 (RST_STREAM)
        h = len(re.findall(r'\b1\b', norm))
        r = len(re.findall(r'\b3\b', norm))
        
        if h > 0: traffic_ledger[ip]['req_count'] += h
        if r > 0: traffic_ledger[ip]['rst_count'] += r
        
        req = traffic_ledger[ip]['req_count']
        rst = traffic_ledger[ip]['rst_count']
        
        # 공격 탐지 임계치 설정
        # req >= 200: 일반적인 대형 페이지 로드(이미지 100개 등)보다 높은 수치로 설정하여 오탐 방지
        # Rapid Reset 공격은 보통 초당 수천~수만 건의 요청이 발생함
        if req >= 200:
            rate = (rst / req) * 100
            if rate >= 90.0:  # 공격은 거의 100%에 수렴하므로 기준을 상향
                cur = time.time()
                if cur - last_alert_time[ip] >= 5.0:
                    print(f'🚨 [ALERT] Rapid Reset Attack Detected! IP: {ip} | Cancel Rate: {rate:.1f}% | Req Count: {req}')
                    sys.stdout.flush()
                    last_alert_time[ip] = cur
            # Reset counters after evaluation
            traffic_ledger[ip]['req_count'] = 0
            traffic_ledger[ip]['rst_count'] = 0
    except Exception:
        pass
