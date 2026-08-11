#!/usr/bin/env bash
#
# healthz-checker.sh: 헬스체크 자가격리
#
#   역할 : 2초마다 응답 h1을 검사해, 정상이면 health/ok 유지·오염이면 ok 삭제.
#          ok가 사라지면 nginx /healthz가 503 → 타겟그룹이 #1을 자동 제외 →
#          NLB가 정상 백엔드(#2/#3)로 우회. "오염되면 차라리 빠진다"는 페일오버.
#   메모: ok 파일은 일부러 immutable 처리하지 않는다: 잠그면 오염된 페이지가
#          채점봇에 그대로 노출되는 자폭이 되므로.
#   주기 : 2초 루프
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

NEEDLE='<h1>NginX를 살려라</h1>'

while true; do
  if curl -s -m 3 http://127.0.0.1:80/ 2>/dev/null | grep -qF "$NEEDLE"; then
    [ -f /var/www/health/ok ] || echo "healthy" > /var/www/health/ok   # 정상 → ok 보장
  else
    rm -f /var/www/health/ok 2>/dev/null                               # 오염 → ok 제거(503 유발)
  fi
  sleep 2
done
