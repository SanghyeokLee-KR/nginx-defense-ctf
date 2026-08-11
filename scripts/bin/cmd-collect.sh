#!/usr/bin/env bash
#
# cmd-collect.sh: 공격자 명령 수집기 (경량)
#
#   역할 : 1초마다 auditd 로그(execve, auid=1000=사람 명령)를 파싱해 대시보드용
#          cmds.json을 생성. pts→SSH IP 매핑으로 '누가' 친 명령인지까지 표시.
#   특징 : ausearch 전체스캔 대신 audit.log를 tail+awk(event-ID 짝짓기)로 파싱해
#          부하를 낮췄고, 데몬 노이즈는 필터링. webhook 노출 명령은 가린다.
#   출력 : /var/www/html/cmds.json (1초 갱신)
#
#   ── 한계 / 운영 주의 ───────────────────────────────────────────────
#   · 의존성: gawk. 3-인자 match($0,/re/,arr) 는 gawk 전용 문법으로, 우분투
#     기본 awk(mawk) 환경에서는 동작하지 않는다. 배포 시 gawk 필요(apt install gawk).
#   · cmds.json 은 대시보드 데모용으로 웹루트에 노출된다. 실무에서는 감시 결과를
#     공개 웹루트에 두면 안 된다. 별도 포트+인증 뒤에 두거나 외부 수집기로 보낼 것.
#   · audit.log 는 감시 대상 박스 위에 있어 root 공격자가 정지/삭제할 수 있다.
#     중앙 로그(원격 syslog/CloudWatch)가 실무 해법이다.
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.
OUT="/var/www/html/cmds.json"
TMP="/tmp/cmds.tmp"

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r\t'; }

name_of() {
  local ip="$1" n
  { [ -z "$ip" ] || [ "$ip" = "?" ]; } && { echo "알수없음"; return; }
  n=$(grep -F "${ip}=" /etc/nginx-defense/ip_names 2>/dev/null | head -1 | cut -d= -f2)
  if [ -n "$n" ]; then echo "$n"; else echo "교수님"; fi
}
who_of() {
  local ip="$1"
  { [ -z "$ip" ] || [ "$ip" = "?" ]; } && { echo "unknown"; return; }
  grep -qF "${ip}=" /etc/nginx-defense/ip_names 2>/dev/null && echo "us" || echo "attacker"
}

# pts→IP 맵은 매초 다시 만들면 무거우니 2초마다 한 번만 갱신
LASTMAP=0
build_map() {
  > /tmp/cc_pid2ip
  while read -r line; do
    rip=$(echo "$line" | grep -oP '\s\K[0-9.]+(?=:[0-9]+\s+users)')
    [ -z "$rip" ] && continue
    for p in $(echo "$line" | grep -oP 'pid=\K[0-9]+'); do echo "$p $rip"; done
  done < <(sudo ss -tnp 2>/dev/null | grep ':22 ' | grep ESTAB) > /tmp/cc_pid2ip
  > /tmp/cc_tty2ip
  while read -r spid pts; do
    rip=$(grep -E "^$spid " /tmp/cc_pid2ip 2>/dev/null | awk '{print $2}' | head -1)
    [ -n "$rip" ] && echo "pts$pts $rip" >> /tmp/cc_tty2ip
  done < <(ps -eo pid=,args= 2>/dev/null | grep 'sshd-session: ubuntu@pts/' | grep -v grep | awk '{ pid=$1; for(i=1;i<=NF;i++){ if($i ~ /@pts\//){ n=$i; sub(/.*@pts\//,"",n); print pid" "n } } }')
}
ip_of_tty() {
  local t="$1" ip
  ip=$(grep -E "^${t} " /tmp/cc_tty2ip 2>/dev/null | awk '{print $2}' | head -1)
  echo "$ip"
}

build_map
while true; do
  NOW=$(date +%s)
  if [ $((NOW - LASTMAP)) -ge 2 ]; then build_map; LASTMAP=$NOW; fi

  CMDS=""
  # 경량화: ausearch 전체스캔 대신 audit.log 최근 줄만 tail → awk 입력 대폭 감소
  CMDLIST=$(sudo tail -n 400 /var/log/audit/audit.log 2>/dev/null | awk '
    match($0,/audit\(([0-9.]+:[0-9]+)\)/,m){ id=m[1] }
    /type=EXECVE/ {
      cmd=""
      for(i=1;i<=NF;i++){ if($i ~ /^a[0-9]+=/){ v=$i; sub(/^a[0-9]+=/,"",v); gsub(/"/,"",v); cmd=cmd (cmd==""?"":" ") v } }
      CMD[id]=cmd
    }
    /type=SYSCALL/ && /key="attacker_cmd"/ {
      au="x"; tt="none"
      if(match($0,/auid=[0-9]+/)) au=substr($0,RSTART+5,RLENGTH-5)
      if(match($0,/tty=[^ ]+/)) tt=substr($0,RSTART+4,RLENGTH-4)
      SC[id]=au"\t"tt
    }
    END{
      for(k in SC){
        split(SC[k],a,"\t")
        if(a[1]=="1000" && k in CMD) print a[2]"\t"CMD[k]
      }
    }
  ' | tail -30)
  while IFS=$'\t' read -r tty cmd; do
    [ -z "$cmd" ] && continue
    case "$cmd" in
      *"tr -d"*|*"paste -sd"*|*"is-active"*|*"is-enabled"*|"sleep "*|*"ausearch"*|*"unix_chkpwd"*|*"systemd-executor"*|*"cmd-alert"*|*"-watch"*) continue ;;
      "sed "*|"sed-e"*|"awk "*|"tr "*|"sort"*|"paste"*|"comm"*|"diff "*|"cut "*|"grep -q"*|"grep -oP"*|"grep -E"*|"grep --color"*|"date "*|"date+"*|"getent"*|"head"*|"tail"*|"wc "*|"base64"*|"xxd"*|"cat /etc/nginx-defense"*) continue ;;
      "curl -s -m 3 http://127.0.0.1"*|"curl -s -m 5"*) continue ;;
      *"command-not-found"*|*"advise-snap"*|*"snapd"*|"realpath "*|*"/snap/"*) continue ;;
    esac
    case "$cmd" in
      *" "[0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]*) continue ;;
    esac
    case "$cmd" in *"powerplatform"*|*"powerautomate"*|*"webhook"*|*"hooks."*) cmd="[알림 전송]" ;; esac
    CMD_IP=$(ip_of_tty "$tty")
    nm=$(name_of "$CMD_IP"); wo=$(who_of "$CMD_IP")
    c=$(json_escape "$cmd"); ipe=$(json_escape "${CMD_IP:-?}"); nme=$(json_escape "$nm"); tte=$(json_escape "$tty")
    CMDS="${CMDS}${CMDS:+,}{\"ip\":\"$ipe\",\"name\":\"$nme\",\"who\":\"$wo\",\"tty\":\"$tte\",\"cmd\":\"$c\"}"
  done <<< "$CMDLIST"

  # 접속 세션도 가볍게 같이 (대시보드 접속자 배지/사운드용)
  CONN=$(awk '{print $2}' /tmp/cc_pid2ip 2>/dev/null | grep -v '^172\.31\.' | sort -u)
  SESS=""; SESSIONS=0
  while read -r sip; do
    [ -z "$sip" ] && continue
    SESSIONS=$((SESSIONS+1)); snm=$(name_of "$sip")
    SESS="${SESS}${SESS:+, }${snm}(${sip})"
  done < <(echo "$CONN")
  [ -z "$SESS" ] && SESS="없음"

  printf '{"t":"%s","sessions":%s,"session_names":"%s","commands":[%s]}' \
    "$(TZ='Asia/Seoul' date '+%H:%M:%S')" "$SESSIONS" "$(json_escape "$SESS")" "$CMDS" > "$TMP"
  mv "$TMP" "$OUT"
  sleep 1
done
