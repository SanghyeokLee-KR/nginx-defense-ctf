#!/usr/bin/env bash
#
# fw-guard.sh: 80포트 방화벽 가드
#
#   역할 : iptables INPUT 체인에 80포트를 막는 DROP/REJECT 규칙이 생기면 즉시
#          제거하고, ACCEPT 규칙이 없으면 맨 앞에 추가한다.
#          (포트 차단 대응: '공격자 차단'이 아니라 '우리 80을 살려두기'가 목적)
#   주기 : 3초 루프
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

while true; do
  # INPUT 체인에 남아있는 80 차단(DROP/REJECT) 규칙을 전부 제거
  while sudo iptables -L INPUT -n --line-numbers 2>/dev/null | grep -E "DROP|REJECT" | grep -q "dpt:80"; do
    line=$(sudo iptables -L INPUT -n --line-numbers 2>/dev/null | grep -E "DROP|REJECT" | grep "dpt:80" | head -1 | awk '{print $1}')
    [ -n "$line" ] && sudo iptables -D INPUT "$line" 2>/dev/null
  done
  # 80 허용 규칙이 없으면 맨 앞(1번)에 추가
  sudo iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null \
    || sudo iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT 2>/dev/null
  sleep 3
done
