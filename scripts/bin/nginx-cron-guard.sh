#!/usr/bin/env bash
#
# nginx-cron-guard.sh: cron 기반 독립 복구 라인 (5중 복구의 3계층)
#
#   역할 : cron(1분)이 호출하는 1회성 점검. index 복원 → nginx 본문검증/재기동
#          → 워치독 enable 보장 → 방어 unit mask 백스톱 unmask → 전체 crontab 자가복원.
#   호출: crontab, * * * * * /usr/local/bin/nginx-cron-guard.sh
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

WEBROOT="$(cat /etc/nginx-defense/webroot 2>/dev/null || echo /var/www/html)"
NEEDLE='<h1>NginX를 살려라</h1>'   # healthz-checker·watchdog 와 동일 기준으로 통일

# index.html이 사라졌거나 변조됐으면 원본 복원
if [ ! -f "$WEBROOT/index.html" ] || ! grep -qF "$NEEDLE" "$WEBROOT/index.html" 2>/dev/null; then
  cp /etc/nginx-defense/index.html "$WEBROOT/index.html" 2>/dev/null
fi

# 본문이 안 뜨면 재기동: flock 으로 직렬화(watchdog A·B 와 동시 restart 방지)
curl -s -m 3 http://127.0.0.1:80/ 2>/dev/null | grep -qF "$NEEDLE" \
  || flock -w 5 /run/nginx-defense.lock \
       sh -c 'systemctl reset-failed nginx 2>/dev/null; systemctl restart nginx 2>/dev/null'

# 워치독 A·B, sys-integrity가 꺼졌으면 enable+start (재부팅 후에도 보장)
systemctl is-active --quiet nginx-wd-a || systemctl enable --now nginx-wd-a 2>/dev/null
systemctl is-active --quiet nginx-wd-b || systemctl enable --now nginx-wd-b 2>/dev/null
systemctl is-active --quiet sys-integrity || systemctl enable --now sys-integrity 2>/dev/null

# mask 백스톱: svc-health(unmask-guard 자신)가 mask되면 스스로 못 푸므로,
# cron이 독립적으로 전체 방어 unit을 unmask한다(자기 보호 공백 보강).
for unit in nginx nginx-wd-a nginx-wd-b sys-integrity svc-health cmdmon healthz-mon \
            content-mon net-status-mon net-filter-mon kworker-mon sysmon; do
  systemctl is-enabled "$unit" 2>/dev/null | grep -q masked \
    && { systemctl unmask "$unit" 2>/dev/null; systemctl start "$unit" 2>/dev/null; }
done

# cron 자가복원: 한 줄이 아니라 '전체 crontab'을 복원한다(crontab -r 대응).
# 마스터 사본의 기대 작업 중 하나라도 빠지면 전체를 재설치.
CRONSRC=/etc/nginx-defense/root.crontab
if [ -f "$CRONSRC" ]; then
  for job in kworker-guard nginx-cron-guard conn-history cmdmon healthz-mon; do
    crontab -l 2>/dev/null | grep -q "$job" || { crontab "$CRONSRC"; break; }
  done
fi
