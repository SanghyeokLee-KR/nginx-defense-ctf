#!/usr/bin/env bash
#
# nginx-watchdog.sh: nginx 가용성 워치독 (A/B 상호 복구)
#
#   역할 : 5중 복구의 2계층. '프로세스 생존'이 아니라 '응답 본문(h1)'으로
#          판정해, 살아있지만 페이지가 오염·응답불가인 경우까지 잡는다.
#   동작 : 5초마다 ─ 본문검증 → index 복원 → 80포트 탈취자/좀비 제거
#          → systemd override(Restart=always) 보장 → 재기동 → 짝 워치독 복구
#   사용 : nginx-watchdog.sh <self-unit> <peer-unit>
#          예) nginx-watchdog.sh nginx-wd-a nginx-wd-b
#
#   ── NginX 살려라 A/D CTF · 교육용·방어 전용 ─────────────────────────────
#   권한이 부여된 경기 박스 안에서 우리 팀 nginx 가용성 유지가 목적.
#   set -e 는 의도적으로 미사용: 이 데몬은 curl/grep 실패(=nginx 다운, 바로
#   그 복구 대상 상황)에도 절대 죽으면 안 된다.
#
#   판정 기준(NEEDLE)은 healthz-checker.sh·nginx-cron-guard.sh 와 동일하게
#   '<h1>NginX를 살려라</h1>' 로 통일한다. 데몬마다 '정상' 정의가 갈리면
#   한쪽은 격리시키고 한쪽은 정상으로 보는 분열이 생긴다.

NEEDLE='<h1>NginX를 살려라</h1>'
WEBROOT="$(cat /etc/nginx-defense/webroot 2>/dev/null || echo /var/www/html)"
SELF="${1:-}"; PEER="${2:-}"

# nginx가 기대한 페이지를 실제로 서빙 중인가 (응답 본문으로 판정)
http_ok() { curl -s -m 3 http://127.0.0.1:80/ 2>/dev/null | grep -qF "$NEEDLE"; }

# 복구 임계구역 직렬화: watchdog A·B·cron이 동시에 restart 하면 충돌하므로
# flock 으로 한 번에 하나만 재기동하게 한다(최대 5초 대기 후 양보).
recover_nginx() {
  flock -w 5 /run/nginx-defense.lock \
    sh -c 'systemctl reset-failed nginx 2>/dev/null; systemctl restart nginx 2>/dev/null'
}

while true; do
  if ! http_ok; then
    # index.html이 사라졌거나 변조됐으면 원본으로 복원
    if [ ! -f "$WEBROOT/index.html" ] || ! grep -qF "$NEEDLE" "$WEBROOT/index.html" 2>/dev/null; then
      cp /etc/nginx-defense/index.html "$WEBROOT/index.html" 2>/dev/null
    fi

    # 80포트를 nginx가 아닌 프로세스(apache 등)나 좀비가 점유 중이면 제거.
    # NOTE: PID 기반 kill 은 읽기→kill 사이 PID 재사용(TOCTOU) 위험이 있다.
    #       실무에선 cgroup/유닛 단위로 다루는 것이 안전하다(한계 문서 참고).
    port_pid=$(ss -ltnp 2>/dev/null | grep ':80 ' | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$port_pid" ] && ! ps -p "$port_pid" -o comm= 2>/dev/null | grep -q nginx; then
      if ps -p "$port_pid" -o state= 2>/dev/null | grep -q Z; then
        ppid=$(ps -p "$port_pid" -o ppid= 2>/dev/null | tr -d ' ')   # 좀비는 부모를 거둔다
        [ -n "$ppid" ] && [ "$ppid" -gt 1 ] 2>/dev/null && kill -9 "$ppid" 2>/dev/null
      else
        kill -9 "$port_pid" 2>/dev/null
      fi
    fi

    # systemd override가 지워졌으면 재생성 (StartLimit 는 [Unit] 섹션에 둔다)
    if [ ! -f /etc/systemd/system/nginx.service.d/override.conf ]; then
      mkdir -p /etc/systemd/system/nginx.service.d
      printf '[Unit]\nStartLimitIntervalSec=60\nStartLimitBurst=20\n[Service]\nRestart=always\nRestartSec=2\n' \
        > /etc/systemd/system/nginx.service.d/override.conf
      systemctl daemon-reload
    fi

    recover_nginx   # mask/실패 상태 해제 + 재기동 (flock 직렬화)
  fi

  # 짝 워치독이 꺼졌으면 되살린다 (A↔B 상호 복구)
  if [ -n "$PEER" ] && ! systemctl is-active --quiet "$PEER"; then
    systemctl reset-failed "$PEER" 2>/dev/null; systemctl start "$PEER" 2>/dev/null
  fi
  sleep 5
done
