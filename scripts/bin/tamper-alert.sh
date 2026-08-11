#!/usr/bin/env bash
#
# tamper-alert.sh: index.html 변조 감지 알림
#
#   역할 : 2초마다 응답 h1을 검사해, 기대 문구가 사라지면(변조) Teams로
#          변조 감지 AdaptiveCard를 발사한다. 감지된 h1과 시각(KST)을 함께 보고.
#   주기 : 2초 루프
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용. (webhook URL은 공개용 마스킹)
WEBHOOK="<REDACTED_WEBHOOK_URL>"
NEEDLE="<h1>NginX를 살려라</h1>"
HN=$(hostname)
STATE="ok"
while true; do
  body=$(curl -s -m 3 http://127.0.0.1:80/ 2>/dev/null)
  if printf '%s' "$body" | grep -qF "$NEEDLE"; then
    if [ "$STATE" = "bad" ]; then STATE="ok"; fi
  else
    if [ "$STATE" = "ok" ]; then
      STATE="bad"
      h1=$(printf '%s' "$body" | grep -oP '<h1>[^<]*</h1>' | head -1 | sed 's/[<>]//g')
      [ -z "$h1" ] && h1="(h1 없음/응답이상)"
      TS=$(TZ='Asia/Seoul' date '+%Y-%m-%d %H:%M:%S')
      curl -s -m 5 -X POST "$WEBHOOK" -H "Content-Type: application/json" -d @- << JSON >/dev/null 2>&1
{
  "type": "AdaptiveCard",
  "\$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "version": "1.4",
  "body": [
    { "type": "Container", "style": "attention", "bleed": true, "items": [
      { "type": "TextBlock", "text": "🚨 index.html 변조 감지 🚨", "weight": "Bolder", "size": "Large", "color": "Attention" } ] },
    { "type": "TextBlock", "text": "#1 서버의 h1이 변조되었습니다!", "weight": "Bolder", "wrap": true, "spacing": "Medium" },
    { "type": "FactSet", "facts": [
      { "title": "🖥️ 서버", "value": "${HN} (#1)" },
      { "title": "📄 감지된 h1", "value": "${h1}" },
      { "title": "🕐 시각(KST)", "value": "${TS}" } ] },
    { "type": "TextBlock", "text": "자동복구가 작동 중이며, NLB가 #1을 격리합니다.", "wrap": true, "size": "Small", "color": "Attention", "spacing": "Small" }
  ]
}
JSON
    fi
  fi
  sleep 2
done
