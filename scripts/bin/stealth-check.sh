#!/usr/bin/env bash
#
# stealth-check.sh: 침투 흔적 종합 스캔 (수동 점검)
#
#   역할 : 교수님(어태커)의 침투 흔적을 10개 섹션으로 한 번에 점검한다.
#          우리 방어 시스템(nginx-defense·sysmon·cmdmon 등)은 '정상(OK)'으로,
#          그 외 의심스러운 것만 [!]로 강조한다.
#   점검 : ① 최근변경 파일 ② 크론 ③ systemd ④ 자동실행 백도어 ⑤ nginx 설정
#          ⑥ 계정/SSH키 ⑦ 네트워크 ⑧ 프로세스 ⑨ immutable 잠금 ⑩ 방어 데몬 생존
#   사용 : sudo bash stealth-check.sh
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;36m'; N='\033[0m'
hr(){ echo -e "${B}========================================================${N}"; }
sec(){ echo -e "\n${B}### $1${N}"; }
ok(){ echo -e "  ${G}[OK]${N} $1"; }
warn(){ echo -e "  ${Y}[?]${N} $1"; }
bad(){ echo -e "  ${R}[!] $1${N}"; }

# 우리 것으로 인정하는 패턴
OURS='nginx-defense|sysmon|cmdmon|cmd-collect|cmd-alert|cmd-monitor|kworker|cron-guard|nginx-wd|sys-integrity|net-filter|svc-health|healthz|content-mon|net-status|tamper|unmask|fw-guard|nginx-logger|nginx-status|survival|restore-defense|attacker.rules|stealth-check'

hr; echo -e "${B}  5조 스텔스 점검 · $(TZ=Asia/Seoul date '+%Y-%m-%d %H:%M:%S')${N}"; hr

# ── 1. 최근 변경된 설정/스크립트 (우리 것 제외) ──
sec "1. 최근 2시간 내 수정된 파일 (설정·실행경로)"
FOUND=$(sudo find /etc /usr/local/bin /usr/bin /var/spool/cron /var/www -type f -mmin -120 2>/dev/null | grep -vE "$OURS" | grep -vE 'cmds.json|sysmon.json|audit\.log|/var/www/health/ok')
if [ -z "$FOUND" ]; then ok "최근 변경된 의심 파일 없음"; else echo "$FOUND" | while read -r f; do bad "$f"; done; fi

# ── 2. 크론 (전체 사용자 + 시스템) ──
sec "2. 크론 작업"
for u in root ubuntu www-data; do
  C=$(sudo crontab -l -u $u 2>/dev/null | grep -vE '^#|^$' | grep -vE "$OURS")
  [ -n "$C" ] && echo "$C" | while read -r l; do bad "[$u 크론] $l"; done
done
SYSCRON=$(sudo find /etc/cron.d /etc/cron.hourly /etc/cron.daily -type f -mmin -1440 2>/dev/null | grep -vE 'placeholder|e2scrub|popularity|apt-compat|dpkg|man-db|update-notifier|logrotate|sysstat')
[ -n "$SYSCRON" ] && echo "$SYSCRON" | while read -r f; do warn "최근 시스템 크론 파일: $f"; done
[ -z "$SYSCRON" ] && ok "시스템 크론 정상"
OURCRON=$(sudo crontab -l 2>/dev/null | grep -cE "$OURS")
ok "우리 크론 $OURCRON개 정상 동작 중"

# ── 3. systemd 서비스 (우리 것·OS기본 제외, 최근 추가만) ──
sec "3. systemd 서비스"
# OS 기본 서비스 화이트리스트 (정상적으로 enable된 것들)
SYSBASE='auditd|audit-rules|nginx|apparmor|blk-availability|cloud-config|cloud-final|cloud-init|console-setup|dmesg|ec2-instance|finalrd|grub|hibinit|keyboard-setup|lvm2|ModemManager|netplan|open-iscsi|open-vm|pollinate|secureboot|setvtrgb|sysstat|ua-reboot|ubuntu-advantage|ufw|vgauth|ssh|cron|systemd|networkd|resolved|chrony|dbus|getty|multipath|snapd|amazon|polkit|udisks|rsyslog|fwupd|irqbalance|acpid|unattended|apport|e2scrub|qemu|atd|emergency|rescue|serial|user@'
SVC=$(sudo find /etc/systemd/system /lib/systemd/system -name '*.service' -mmin -1440 2>/dev/null | grep -vE "$OURS" | grep -vE "$SYSBASE")
if [ -z "$SVC" ]; then ok "최근 추가된 의심 서비스 없음 (우리것·OS기본 외)"; else echo "$SVC" | while read -r s; do bad "$s"; done; fi
# 우리 데몬 enable 확인
ENA_OURS=$(systemctl list-unit-files --state=enabled --type=service 2>/dev/null | awk '{print $1}' | grep -cE "$OURS")
ok "우리 방어 서비스 $ENA_OURS개 enabled"
# 우리것도 OS기본도 아닌 enabled 서비스만 (진짜 의심)
ENA=$(systemctl list-unit-files --state=enabled --type=service 2>/dev/null | awk '{print $1}' | grep -vE "$OURS" | grep -ivE "$SYSBASE|UNIT|^[0-9]+$")
[ -n "$ENA" ] && echo "$ENA" | while read -r s; do [ -n "$s" ] && bad "낯선 enabled 서비스: $s"; done
[ -z "$ENA" ] && ok "enabled 서비스 전부 정상 (OS기본·우리것)"

# ── 4. 자동실행 백도어 위치 ──
sec "4. 자동실행 / 라이브러리 주입"
# ld.so.preload (악성 .so 주입 - 가장 위험)
if [ -s /etc/ld.so.preload ]; then bad "ld.so.preload 비어있지 않음! $(cat /etc/ld.so.preload)"; else ok "ld.so.preload 비어있음 (정상)"; fi
# rc.local
if [ -f /etc/rc.local ]; then RC=$(grep -vE '^#|^$|exit 0|^/bin/sh' /etc/rc.local); [ -n "$RC" ] && echo "$RC" | while read -r l; do warn "rc.local: $l"; done || ok "rc.local 정상"; else ok "rc.local 없음"; fi
# profile.d 중 우리것/기본것 외
PROF=$(ls /etc/profile.d/ 2>/dev/null | grep -vE "$OURS" | grep -vE 'locale|systemd|cloud|apps-bin|bash_completion|debuginfod|gawk|01-|Z99|vte')
[ -n "$PROF" ] && echo "$PROF" | while read -r p; do warn "profile.d: $p"; done
[ -z "$PROF" ] && ok "profile.d 정상 (우리 cmd-monitor 포함)"
# bashrc/profile 끝에 수상한 줄 (Ubuntu 기본 lesspipe/dircolors는 제외)
for f in /root/.bashrc /home/ubuntu/.bashrc /etc/bash.bashrc; do
  SUS=$(sudo grep -nE 'curl|wget|nc |bash -i|/dev/tcp|base64 -d|eval' "$f" 2>/dev/null | grep -vE "$OURS" | grep -vE 'lesspipe|dircolors')
  [ -n "$SUS" ] && echo "$SUS" | while read -r l; do bad "$f: $l"; done
done
[ -z "$(for f in /root/.bashrc /home/ubuntu/.bashrc /etc/bash.bashrc; do sudo grep -nE 'curl|wget|nc |bash -i|/dev/tcp|base64 -d|eval' "$f" 2>/dev/null | grep -vE "$OURS" | grep -vE 'lesspipe|dircolors'; done)" ] && ok "bashrc/profile 정상 (기본 설정만)"

# ── 5. nginx 설정 무결성 ──
sec "5. nginx 설정"
# root 경로, proxy_pass, return 301/302, rewrite 점검
NGINX=$(sudo nginx -T 2>/dev/null)
echo "$NGINX" | grep -iE 'proxy_pass|return 30|rewrite .*http' | grep -v '#' | while read -r l; do warn "리다이렉트/프록시: $l"; done
ROOTS=$(echo "$NGINX" | grep -E '^\s*root ' | grep -v '#' | sort -u)
echo "$ROOTS" | while read -r r; do
  case "$r" in *"/var/www/html"*|*"/var/www/health"*) ok "root 정상: $(echo $r|xargs)" ;; *) bad "낯선 root: $(echo $r|xargs)" ;; esac
done
# index.html h1 확인
H1=$(curl -s -m 3 http://127.0.0.1/ 2>/dev/null | grep -oP '<h1>\K[^<]*' | head -1)
[ "$H1" = "NginX를 살려라" ] && ok "index.html 정상 (h1: $H1)" || bad "index.html h1 변조 의심: '$H1'"

# ── 6. 계정 / SSH 키 ──
sec "6. 계정 · SSH 접근"
UID0=$(awk -F: '$3==0{print $1}' /etc/passwd | grep -v '^root$')
[ -n "$UID0" ] && echo "$UID0" | while read -r u; do bad "root 권한(uid=0) 계정: $u"; done || ok "uid=0은 root만 (정상)"
SHELLUSERS=$(awk -F: '$7 ~ /(bash|sh)$/ && $3>=1000 && $1!="ubuntu"{print $1}' /etc/passwd)
[ -n "$SHELLUSERS" ] && echo "$SHELLUSERS" | while read -r u; do bad "셸 가진 새 사용자: $u"; done || ok "셸 사용자는 ubuntu만 (정상)"
for kf in /root/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys; do
  N=$(sudo grep -cE '^(ssh-|ecdsa|sk-)' "$kf" 2>/dev/null)
  N=${N:-0}
  case "$kf" in *root*) owner="root" ;; *) owner="ubuntu" ;; esac
  if [ "$N" -eq 0 ]; then :;
  elif [ "$N" -le 1 ]; then ok "$owner SSH키 ${N}개 (정상)";
  else warn "$owner SSH키 ${N}개 (예상보다 많음: 확인)"; fi
done

# ── 7. 네트워크: 수상한 리스닝/연결 ──
sec "7. 네트워크 (리스닝 포트 · 외부연결)"
LISTEN=$(sudo ss -ltnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oE '[0-9]+$' | sort -un)
for p in $LISTEN; do
  case "$p" in
    22|80) ok "리스닝 :$p (정상)" ;;
    53|68|323|5355|631) ok "리스닝 :$p (시스템 서비스)" ;;
    *) WHO=$(sudo ss -ltnp 2>/dev/null | grep ":$p " | grep -oP 'users:\(\("\K[^"]+' | head -1); bad "낯선 리스닝 포트 :$p ($WHO)" ;;
  esac
done
# 외부로 나가는 수상한 연결 (역쉘 등)
OUT=$(sudo ss -tnp state established 2>/dev/null | grep -vE '127.0.0.1|172.31.|:22 ' | grep -oP 'users:\(\("\K[^"]+' | sort -u | grep -vE 'curl|nginx')
[ -n "$OUT" ] && echo "$OUT" | while read -r o; do warn "외부 연결 프로세스: $o"; done
[ -z "$OUT" ] && ok "수상한 외부 연결 없음"

# ── 8. 수상한 프로세스 ──
sec "8. 실행 중 프로세스"
SUS=$(ps -eo user,pid,args 2>/dev/null | grep -vE 'grep|'"$OURS" | grep -iE 'nc -l|ncat|socat|/dev/tcp|bash -i|python.*-c|perl.*-e|http\.server|miner|xmrig|/tmp/\.|/dev/shm/' )
[ -n "$SUS" ] && echo "$SUS" | while read -r l; do bad "$l"; done || ok "수상한 프로세스 없음"
# /tmp, /dev/shm 실행파일
TMPEXE=$(find /tmp /dev/shm /var/tmp -maxdepth 2 -type f -executable -mmin -1440 2>/dev/null | grep -vE "$OURS")
[ -n "$TMPEXE" ] && echo "$TMPEXE" | while read -r f; do bad "임시디렉토리 실행파일: $f"; done || ok "/tmp·/dev/shm 실행파일 없음"

# ── 9. immutable 잠금 상태 (우리 방어) ──
sec "9. 방어 잠금 상태 (우리 것 - 풀려있으면 경고)"
for f in /var/www/html/index.html /etc/nginx/sites-available/default /usr/sbin/nginx; do
  if lsattr "$f" 2>/dev/null | grep -q 'i'; then ok "잠김(immutable): $f"; else bad "잠금 풀림! $f"; fi
done

# ── 10. 방어 데몬 생존 ──
sec "10. 방어 데몬 생존"
DOWN=0
for svc in nginx nginx-wd-a nginx-wd-b sys-integrity kworker-mon net-filter-mon svc-health healthz-mon content-mon net-status-mon sysmon cmdmon; do
  st=$(systemctl is-active $svc 2>/dev/null)
  [ "$st" != "active" ] && { bad "$svc = $st"; DOWN=$((DOWN+1)); }
done
[ "$DOWN" -eq 0 ] && ok "방어 데몬 전부 active"

hr
echo -e "${B}  점검 완료. ${R}[!]${B} 빨강이 있으면 교수님 침투 의심 → 내용 확인 후 대응${N}"
echo -e "${B}  ${Y}[?]${B} 노랑은 '확인 필요'(대부분 정상일 수 있음)${N}"
hr
