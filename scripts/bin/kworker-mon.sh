#!/usr/bin/env bash
#
# .kworker-mon.sh: 독립 자동복구 데몬 (5중 복구의 5계층)
#
#   역할 : systemd 밖에서 nohup으로 도는 최후 복구 라인. nginx가 응답을 멈추면
#          index 복원 + 재기동하고, 핵심 워치독/위장 서비스도 함께 살린다.
#   위장 : 커널 스레드(kworker)처럼 보이는 dotfile 이름으로 ps/ls 회피.
#          systemctl 관리 밖이라 mask/stop으로 끌 수 없고, cron이 부활시킨다.
#   주기 : 3초 루프
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

NEEDLE='NginX를 살려라'
WEBROOT="$(cat /etc/nginx-defense/webroot 2>/dev/null || echo /var/www/html)"

while true; do
  if ! curl -s -m 3 http://127.0.0.1:80/ 2>/dev/null | grep -q "$NEEDLE"; then
    if [ ! -f "$WEBROOT/index.html" ] || ! grep -q "$NEEDLE" "$WEBROOT/index.html" 2>/dev/null; then
      cp /etc/nginx-defense/index.html "$WEBROOT/index.html" 2>/dev/null
    fi
    systemctl reset-failed nginx 2>/dev/null
    systemctl restart nginx 2>/dev/null
  fi
  # 핵심 워치독/위장 서비스가 꺼졌으면 같이 살린다
  for unit in nginx-wd-a nginx-wd-b sys-integrity; do
    systemctl is-active --quiet "$unit" 2>/dev/null || systemctl start "$unit" 2>/dev/null
  done
  sleep 3
done
