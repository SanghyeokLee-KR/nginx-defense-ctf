#!/usr/bin/env bash
#
# nginx-logger.sh: nginx 다운/복구 타임라인 기록
#
#   역할 : 2초마다 본문을 확인해 상태 전이(up↔down)가 일어난 순간만
#          status.log에 DOWN / RECOVERED로 남긴다. (사후 타임라인 재구성용)
#   출력 : /var/log/nginx-defense/status.log
#   주기 : 2초 루프
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

LOGF='/var/log/nginx-defense/status.log'
NEEDLE='NginX를 살려라'
STATE='up'

while true; do
  ts=$(TZ='Asia/Seoul' date '+%Y-%m-%d %H:%M:%S')
  if curl -s -m 3 http://127.0.0.1:80/ 2>/dev/null | grep -q "$NEEDLE"; then
    [ "$STATE" = 'down' ] && { echo "[$ts] 🟢 RECOVERED" >> "$LOGF"; STATE='up'; }
  else
    [ "$STATE" = 'up' ] && { echo "[$ts] 🔴 DOWN" >> "$LOGF"; STATE='down'; }
  fi
  sleep 2
done
