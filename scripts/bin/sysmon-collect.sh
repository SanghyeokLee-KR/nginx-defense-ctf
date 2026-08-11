#!/usr/bin/env bash
#
# sysmon-collect.sh: 시스템·방어 상태 종합 수집기
#
#   역할 : ~3초마다 nginx/포트80/immutable/좀비/세션/신규계정/웹파일 변경/CPU·
#          메모리·디스크/방어 데몬 상태 + 공격자 명령을 한 번에 모아 sysmon.json
#          으로 출력. 대시보드의 메인 데이터 소스.
#   기준 : 최초 1회 사용자/웹파일 baseline을 떠두고 이후 diff로 변화 감지.
#   출력 : /var/www/html/sysmon.json
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.
OUT="/var/www/html/sysmon.json"
TMP="/tmp/sysmon.tmp"
SIG="NginX를 살려라"
BASE_DIR="/etc/nginx-defense/baseline"
mkdir -p "$BASE_DIR"
[ -f "$BASE_DIR/users" ] || getent passwd | awk -F: '{print $1}' | sort > "$BASE_DIR/users"
[ -f "$BASE_DIR/webfiles" ] || ls -1 /var/www/html 2>/dev/null | grep -v '^sysmon.json$' | sort > "$BASE_DIR/webfiles"

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

while true; do
  TS=$(TZ='Asia/Seoul' date '+%Y-%m-%d %H:%M:%S')

  # ===== pts → IP 맵 (가볍게: ss 1회 + ps 1회) =====
  > /tmp/sm_pid2ip
  while read -r line; do
    rip=$(echo "$line" | grep -oP '\s\K[0-9.]+(?=:[0-9]+\s+users)')
    [ -z "$rip" ] && continue
    for p in $(echo "$line" | grep -oP 'pid=\K[0-9]+'); do echo "$p $rip"; done
  done < <(sudo ss -tnp 2>/dev/null | grep ':22 ' | grep ESTAB) > /tmp/sm_pid2ip
  > /tmp/sm_tty2ip
  while read -r spid pts; do
    rip=$(grep -E "^$spid " /tmp/sm_pid2ip 2>/dev/null | awk '{print $2}' | head -1)
    [ -n "$rip" ] && echo "pts$pts $rip" >> /tmp/sm_tty2ip
  done < <(ps -eo pid=,args= 2>/dev/null | grep 'sshd-session: ubuntu@pts/' | grep -v grep | awk '{ pid=$1; for(i=1;i<=NF;i++){ if($i ~ /@pts\//){ n=$i; sub(/.*@pts\//,"",n); print pid" "n } } }')

  ip_of_tty() {
    local t="$1" ip
    ip=$(grep -E "^${t} " /tmp/sm_tty2ip 2>/dev/null | awk '{print $2}' | head -1)
    echo "$ip"
  }

  CONN=$(awk '{print $2}' /tmp/sm_pid2ip 2>/dev/null | grep -v '^172\.31\.' | sort -u)
  SESS=""; SESSIONS=0
  while read -r sip; do
    [ -z "$sip" ] && continue
    SESSIONS=$((SESSIONS+1)); snm=$(name_of "$sip")
    SESS="${SESS}${SESS:+, }${snm}(${sip})"
  done < <(echo "$CONN")
  [ -z "$SESS" ] && SESS="없음"

  CMDS=""
  CMDLIST=$(sudo ausearch -k attacker_cmd -ts recent 2>/dev/null | awk '
    /^type=EXECVE/ {
      cmd=""
      for(i=1;i<=NF;i++){ if($i ~ /^a[0-9]+=/){ v=$i; sub(/^a[0-9]+=/,"",v); gsub(/"/,"",v); cmd=cmd (cmd==""?"":" ") v } }
      EX[NR]=cmd; LAST=NR
    }
    /^type=SYSCALL/ {
      au="x"; tt="none"
      if(match($0,/auid=[0-9]+/)) au=substr($0,RSTART+5,RLENGTH-5)
      if(match($0,/tty=[^ ]+/)) tt=substr($0,RSTART+4,RLENGTH-4)
      if(au=="1000" && LAST in EX){ print tt"\t"EX[LAST]; delete EX[LAST] }
    }
  ' | tail -30)
  while IFS=$'\t' read -r tty cmd; do
    [ -z "$cmd" ] && continue
    case "$cmd" in
      *"is-active"*|*"is-enabled"*|"sleep "*|*"ausearch"*|*"unix_chkpwd"*|*"systemd-executor"*|*"cmd-alert"*|*"-watch"*) continue ;;
      "sed "*|"sed-e"*|"awk "*|"tr "*|"sort"*|"paste"*|"comm"*|"diff "*|"cut "*|"grep -q"*|"grep -oP"*|"grep -E"*|"grep --color"*|"date "*|"date+"*|"getent"*|"head"*|"tail"*|"wc "*|"base64"*|"xxd"*|"cat /etc/nginx-defense"*) continue ;;
      "curl -s -m 3 http://127.0.0.1"*|"curl -s -m 5"*) continue ;;
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

  NGINX=$(systemctl is-active nginx 2>/dev/null)
  DAEMONS=""
  for svc in nginx-wd-a nginx-wd-b sys-integrity kworker-mon net-filter-mon svc-health healthz-mon content-mon net-status-mon; do
    st=$(systemctl is-active $svc 2>/dev/null)
    DAEMONS="${DAEMONS}${DAEMONS:+,}{\"name\":\"$svc\",\"state\":\"$st\"}"
  done
  PORT80=$(ss -ltnp 2>/dev/null | grep ':80 ' | grep -oP 'users:\(\("\K[^"]+' | head -1)
  [ -z "$PORT80" ] && PORT80="없음"
  PORT80_OK="yes"; [ "$PORT80" != "nginx" ] && [ "$PORT80" != "없음" ] && PORT80_OK="no"
  IMM_INDEX="no"; lsattr /var/www/html/index.html 2>/dev/null | grep -q 'i' && IMM_INDEX="yes"
  IMM_CONF="no"; lsattr /etc/nginx/sites-available/default 2>/dev/null | grep -q 'i' && IMM_CONF="yes"
  CRON_OURS="no"; sudo crontab -l 2>/dev/null | grep -qE 'kworker|cron-guard' && CRON_OURS="yes"
  CRON_SUSPECT=$(sudo crontab -l 2>/dev/null | grep -vE 'kworker|cron-guard|conn-history|cmdmon|healthz-mon|^#|^$' | head -3 | while IFS= read -r l; do json_escape "$l"; echo; done | grep -v '^$' | paste -sd '|' -)
  [ -z "$CRON_SUSPECT" ] && CRON_SUSPECT="없음"
  BODY=$(curl -s -m 3 http://127.0.0.1/ 2>/dev/null)
  PAGE_OK="no"; printf '%s' "$BODY" | grep -qF "$SIG" && PAGE_OK="yes"
  H1=$(printf '%s' "$BODY" | grep -oP '<h1>\K[^<]*' | head -1)
  [ -z "$H1" ] && H1="(없음)"
  ZOMBIE=$(ps -eo stat 2>/dev/null | grep -c '^Z')
  getent passwd | awk -F: '{print $1}' | sort > /tmp/users_now
  NEW_USERS=$(comm -13 "$BASE_DIR/users" /tmp/users_now 2>/dev/null | paste -sd ',' -)
  [ -z "$NEW_USERS" ] && NEW_USERS="없음"
  ls -1 /var/www/html 2>/dev/null | grep -v '^sysmon.json$' | sort > /tmp/webfiles_now
  FILE_CHANGE=$(comm -3 "$BASE_DIR/webfiles" /tmp/webfiles_now 2>/dev/null | sed 's/^\t/+/; s/^/변경: /' | head -5 | while IFS= read -r l; do json_escape "$l"; echo; done | grep -v '^$' | paste -sd '|' -)
  [ -z "$FILE_CHANGE" ] && FILE_CHANGE="없음"
  SUSPECT_PROC=$(ps -eo args 2>/dev/null | grep -E 'http\.server|nc -l|ncat|socat' | grep -v grep | head -3 | while IFS= read -r l; do json_escape "$l"; echo; done | grep -v '^$' | paste -sd '|' -)
  [ -z "$SUSPECT_PROC" ] && SUSPECT_PROC="없음"

  read -r _ u1 n1 s1 i1 w1 q1 sq1 _ < /proc/stat
  T1=$((u1+n1+s1+i1+w1+q1+sq1)); IDLE1=$((i1+w1))
  sleep 0.3
  read -r _ u2 n2 s2 i2 w2 q2 sq2 _ < /proc/stat
  T2=$((u2+n2+s2+i2+w2+q2+sq2)); IDLE2=$((i2+w2))
  DT=$((T2-T1)); DIDLE=$((IDLE2-IDLE1))
  CPU=0; [ "$DT" -gt 0 ] && CPU=$(( (100*(DT-DIDLE)) / DT ))
  MEMTOTAL=$(awk '/MemTotal/{print $2}' /proc/meminfo)
  MEMAVAIL=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
  MEM=0; [ "$MEMTOTAL" -gt 0 ] && MEM=$(( (100*(MEMTOTAL-MEMAVAIL)) / MEMTOTAL ))
  LOAD1=$(awk '{print $1}' /proc/loadavg)
  LOAD5=$(awk '{print $2}' /proc/loadavg)
  NCPU=$(nproc 2>/dev/null || echo 1)
  DISK=$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
  [ -z "$DISK" ] && DISK=0
  TOP3=$(ps -eo pcpu=,comm= --sort=-pcpu 2>/dev/null | grep -vE 'sysmon-collect|^ *0\.0' | head -3 | while read -r pc cm; do printf '{"cpu":"%s","name":"%s"}' "$pc" "$(json_escape "$cm")"; echo ","; done | paste -sd '' - | sed 's/,$//')
  [ -z "$TOP3" ] && TOP3=""

  cat > "$TMP" << JSON
{
  "time": "$TS",
  "page_ok": "$PAGE_OK",
  "h1": "$(json_escape "$H1")",
  "nginx": "$NGINX",
  "port80_user": "$(json_escape "$PORT80")",
  "port80_ok": "$PORT80_OK",
  "immutable_index": "$IMM_INDEX",
  "immutable_conf": "$IMM_CONF",
  "cron_ours": "$CRON_OURS",
  "cron_suspect": "$(json_escape "$CRON_SUSPECT")",
  "zombie": $ZOMBIE,
  "new_users": "$(json_escape "$NEW_USERS")",
  "file_change": "$(json_escape "$FILE_CHANGE")",
  "sessions": $SESSIONS,
  "session_names": "$(json_escape "$SESS")",
  "suspect_proc": "$(json_escape "$SUSPECT_PROC")",
  "cpu": $CPU,
  "mem": $MEM,
  "load1": "$LOAD1",
  "load5": "$LOAD5",
  "ncpu": $NCPU,
  "disk": $DISK,
  "top3": [$TOP3],
  "daemons": [$DAEMONS],
  "commands": [$CMDS]
}
JSON
  mv "$TMP" "$OUT"
  sleep 2.7
done
