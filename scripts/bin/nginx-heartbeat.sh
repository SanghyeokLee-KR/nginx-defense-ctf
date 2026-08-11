#!/usr/bin/env bash
#
# nginx-heartbeat.sh: 정기 생존보고 (5분)
#
#   역할 : systemd timer가 5분마다 호출. 로컬 nginx + 백엔드 3대 + NLB + 워치독
#          상태를 한 번에 점검해 Teams 'NGINX 모니터링방'(sig=9Ck)으로 종합 보고.
#   호출 : nginx-heartbeat.timer (OnUnitActiveSec=5min)
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용. (webhook URL은 공개용 마스킹)
WEBHOOK="<REDACTED_WEBHOOK_URL>"
NEEDLE="NginX를 살려라"
HN=$(hostname)
TS=$(TZ='Asia/Seoul' date '+%Y-%m-%d %H:%M:%S')

# 로컬 + 3대 백엔드 + NLB 상태 점검
check() { curl -s -m 3 "http://$1/" 2>/dev/null | grep -q "$NEEDLE" && echo "🟢 정상" || echo "🔴 응답없음"; }
LOCAL=$(systemctl is-active nginx 2>/dev/null)
N1=$(check "X.X.X.X (#1)")
N2=$(check "X.X.X.X (#2)")
N3=$(check "X.X.X.X (#3)")
NLB=$(check "X.X.X.X (NLB-EIP)")
WD=$(systemctl is-active nginx-wd-a 2>/dev/null)

curl -s -m 5 -X POST "$WEBHOOK" -H "Content-Type: application/json" -d @- << JSON >/dev/null 2>&1
{
  "type": "AdaptiveCard",
  "\$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "version": "1.4",
  "body": [
    { "type": "TextBlock", "text": "💓 정기 생존보고", "weight": "Bolder", "size": "Medium", "color": "Good" },
    { "type": "TextBlock", "text": "전 시스템 상태 점검 (5분 주기)", "wrap": true, "size": "Small", "spacing": "None" },
    { "type": "FactSet", "facts": [
      { "title": "📤 제출IP(NLB)", "value": "${NLB}" },
      { "title": "1️⃣ #1 attack", "value": "${N1}" },
      { "title": "2️⃣ #2 svc", "value": "${N2}" },
      { "title": "3️⃣ #3 svc", "value": "${N3}" },
      { "title": "🛡️ watchdog", "value": "${WD}" },
      { "title": "🕐 시각", "value": "${TS}" }
    ]}
  ]
}
JSON
