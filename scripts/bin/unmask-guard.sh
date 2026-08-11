#!/usr/bin/env bash
#
# unmask-guard.sh: systemctl mask 대응 가드
#
#   역할 : 공격자가 `systemctl mask <unit>` 으로 방어 서비스를 영구 차단하면
#          3초 내로 unmask 후 재기동한다. (3차 공격 '부팅 경로 차단' 대응 라인)
#   대상 : nginx 본체 + 워치독·보호 모니터 서비스군 (자기 유닛 svc-health 포함)
#   주기 : 3초 루프
#   참고: svc-health(이 데몬 자신)가 mask되면 스스로는 못 푼다. cron의
#          nginx-cron-guard.sh가 같은 unit 집합을 독립적으로 unmask해 자기 보호 공백을 메운다.
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

UNITS='nginx nginx-wd-a nginx-wd-b sys-integrity net-status-mon kworker-mon net-filter-mon svc-health cmdmon healthz-mon content-mon sysmon'

while true; do
  for unit in $UNITS; do
    # masked(= 유닛이 /dev/null로 막힌 상태)면 풀고 다시 띄운다
    if systemctl is-enabled "$unit" 2>/dev/null | grep -q masked; then
      systemctl unmask "$unit" 2>/dev/null
      systemctl start  "$unit" 2>/dev/null
    fi
  done
  sleep 3
done
