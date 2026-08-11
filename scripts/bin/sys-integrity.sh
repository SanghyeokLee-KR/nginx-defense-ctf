#!/usr/bin/env bash
#
# sys-integrity.sh: 워치독 무결성 보장기 (위장 서비스)
#
#   역할 : 10초마다 워치독 A·B가 enable+active 상태인지 확인하고, 빠졌으면
#          되살린다. '시스템 무결성 점검'처럼 보이는 이름으로 위장한 4계층.
#   주기 : 10초 루프
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

while true; do
  for unit in nginx-wd-a nginx-wd-b; do
    systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl enable "$unit" 2>/dev/null
    systemctl is-active  --quiet "$unit" 2>/dev/null || systemctl start  "$unit" 2>/dev/null
  done
  sleep 10
done
