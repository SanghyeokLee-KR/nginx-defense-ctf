#!/usr/bin/env bash
#
# nginx-status-alert.sh: nginx 다운/복구 Teams 알림
#
#   역할 : 2초마다 본문을 확인해 상태가 바뀌는 순간(다운/복구)에만 Power
#          Automate webhook으로 Teams 'NGINX 모니터링방'에 AdaptiveCard 발사.
#          복구 시 다운 지속시간(초)도 함께 보고.
#   주기 : 2초 루프
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용. (webhook URL은 공개용 마스킹)
WEBHOOK="<REDACTED_WEBHOOK_URL>"
NEEDLE="NginX를 살려라"
HN=$(hostname)
STATE="up"
DOWN_AT=0
send() {
  local title="$1" color="$2" emoji="$3" extra="$4"
  local ts=$(TZ='Asia/Seoul' date '+%H:%M:%S')
  curl -s -m 5 -X POST "$WEBHOOK" -H "Content-Type: application/json" -d @- << JSON >/dev/null 2>&1
{
  "type": "AdaptiveCard",
  "\$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "version": "1.4",
  "body": [
    { "type": "TextBlock", "text": "${emoji} ${title}", "weight": "Bolder", "size": "Large", "color": "${color}" },
    { "type": "FactSet", "facts": [
      { "title": "💻 서버", "value": "${HN}" },
      { "title": "🕐 시각", "value": "${ts}" }${extra}
    ]}
  ]
}
JSON
}
while true; do
  body=$(curl -s -m 3 http://127.0.0.1:80/ 2>/dev/null)
  if printf '%s' "$body" | grep -q "$NEEDLE"; then
    if [ "$STATE" = "down" ]; then
      now=$(date +%s); dur=$((now - DOWN_AT))
      send "nginx 복구 완료" "Good" "🟢" ", { \"title\": \"⏱️ 복구시간\", \"value\": \"${dur}초\" }"
      STATE="up"
    fi
  else
    if [ "$STATE" = "up" ]; then
      DOWN_AT=$(date +%s)
      send "nginx 다운 감지!" "Attention" "🔴" ""
      STATE="down"
    fi
  fi
  sleep 2
done
