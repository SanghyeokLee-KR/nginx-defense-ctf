#!/usr/bin/env bash
#
# kworker-guard.sh: 독립 데몬(.kworker-mon) 부활기
#
#   역할 : cron(1분)이 호출. 위장 데몬 .kworker-mon 이 죽어 있으면 nohup으로
#          다시 띄운다. systemd 밖에서 도는 복구 라인이라 systemctl로 못 끈다.
#   호출: crontab, * * * * * /usr/local/bin/.kworker-guard.sh
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

pgrep -f '\.kworker-mon\.sh' >/dev/null 2>&1 \
  || nohup /usr/local/bin/.kworker-mon.sh >/dev/null 2>&1 &
