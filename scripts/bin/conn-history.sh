#!/usr/bin/env bash
#
# conn-history.sh: SSH 접속 이력 수집 (v2)
#
#   역할 : journalctl SSH 로그(Accepted publickey 등)를 파싱해 접속/종료
#          타임라인을 만들고, ip_names로 이름을 붙여 대시보드용 JSON으로 출력.
#          기준시점(conn-since) 이후만 "지금부터 새로 쌓기".
#   출력 : /var/www/html/c-9f3k2x.json  (호출: cron 1분)
#
#   NginX 살려라 A/D CTF · 교육용·방어 전용.
OUT="/var/www/html/c-9f3k2x.json"
NAMES="/etc/nginx-defense/ip_names"

json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r\t'; }
name_of(){
  local n; n=$(grep -F "${1}=" "$NAMES" 2>/dev/null | head -1 | cut -d= -f2)
  [ -n "$n" ] && echo "$n" || echo "교수님"
}
who_of(){ grep -qF "${1}=" "$NAMES" 2>/dev/null && echo "us" || echo "attacker"; }

LOG=$(sudo journalctl -u ssh --no-pager 2>/dev/null)

# 기준 시점(있으면) 이후 접속만: "지금부터 새로 쌓기"
SINCE_FILE="/var/lib/nginx-defense/conn-since"
SINCE_E=0
[ -f "$SINCE_FILE" ] && SINCE_E=$(cat "$SINCE_FILE" 2>/dev/null)
[ -z "$SINCE_E" ] && SINCE_E=0

ITEMS=$(echo "$LOG" | awk -v since="$SINCE_E" '
  function epoch(s,   cmd,e){ cmd="date -d \""s"\" +%s 2>/dev/null"; cmd|getline e; close(cmd); return e }
  /Accepted publickey/ {
    ip=""; port=""
    for(i=1;i<=NF;i++){ if($i=="from"){ip=$(i+1)} if($i=="port"){port=$(i+1)} }
    t=$1" "$2" "$3
    if(ip!="" && ip !~ /^172\.31\./ && epoch(t) >= since) print "IN\t" t "\t" ip "\t" port
  }
  /Connection closed by/ {
    ip=""; port=""
    for(i=1;i<=NF;i++){ if($i=="by"){ip=$(i+1)} if($i=="port"){port=$(i+1)} }
    if(ip!="" && ip !~ /^172\.31\./) print "OUT\t" $1" "$2" "$3 "\t" ip "\t" port
  }
  /Disconnected from user/ {
    ip=""; port=""
    for(i=1;i<=NF;i++){ if($i=="ubuntu" && (i+1)<=NF){ip=$(i+1)} if($i=="port"){port=$(i+1)} }
    if(ip ~ /^[0-9]+\./ && ip !~ /^172\.31\./) print "OUT\t" $1" "$2" "$3 "\t" ip "\t" port
  }
')

HIST=$(echo "$ITEMS" | awk -F'\t' '
  function epoch(s,   cmd,e){ cmd="date -d \""s"\" +%s 2>/dev/null"; cmd|getline e; close(cmd); return e }
  {
    ev=$1; t=$2; ip=$3; port=$4; key=ip"_"port
    if(ev=="IN"){ if(!(key in seen)){ order[++n]=key; seen[key]=1 } rec_ip[key]=ip; rec_in[key]=t; inE[key]=epoch(t) }
    if(ev=="OUT"){ outE[key]=epoch(t); outT[key]=t; has_out[key]=1 }
  }
  END{
    for(i=n;i>=1;i--){
      k=order[i]; ip=rec_ip[k]; tin=rec_in[k]; tout="-"
      if(k in has_out && outE[k]>=inE[k]){ dur=outE[k]-inE[k]; st="closed"; tout=outT[k] } else { dur=-1; st="active" }
      if(dur<0){ durs="접속중" }
      else if(dur<60){ durs=dur"초" }
      else if(dur<3600){ durs=int(dur/60)"분" }
      else { durs=int(dur/3600)"시간"int((dur%3600)/60)"분" }
      print ip "\t" tin "\t" st "\t" durs "\t" tout
    }
  }
')

ARR=""
while IFS=$'\t' read -r ip tin st durs tout; do
  [ -z "$ip" ] && continue
  nm=$(name_of "$ip"); wo=$(who_of "$ip")
  ipe=$(json_escape "$ip"); nme=$(json_escape "$nm"); tine=$(json_escape "$tin"); durse=$(json_escape "$durs"); toute=$(json_escape "$tout")
  ARR="${ARR}${ARR:+,}{\"ip\":\"$ipe\",\"name\":\"$nme\",\"who\":\"$wo\",\"time\":\"$tine\",\"out\":\"$toute\",\"state\":\"$st\",\"dur\":\"$durse\"}"
done <<< "$HIST"

printf '{"t":"%s","history":[%s]}' "$(TZ=Asia/Seoul date '+%H:%M:%S')" "$ARR" > "$OUT" 2>/dev/null
chmod 666 "$OUT" 2>/dev/null
