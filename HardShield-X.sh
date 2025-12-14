#!/usr/bin/env bash
# HardShield-X
# All-in-one hardening & DDoS mitigation panel
# Features: bilingual menu (Thai/English), Smart Status Dashboard, nft-monitor (full trace),
# Auto-Mitigation modes (Safe/Aggressive/Extreme), ipset + fail2ban integration, UFW + nftables,
# Service checks (10 items), attack logs, universal (works on any IP: local or VPS)
# Target: Ubuntu 18.04 - 22.04

set -euo pipefail
IFS=$'\n\t'

### ---------------- CONFIG ----------------
BACKUP_DIR="/root/HardShieldX_backups_$(date +%s)"
mkdir -p "$BACKUP_DIR"

ATTACK_LOG="/var/log/attack-detect.log"
NFT_LOG="/var/log/nft-ddos.log"
:>"$ATTACK_LOG" || true
:>"$NFT_LOG" || true

IPSET_NAME="blacklist_attacker"
EMERGENCY_SSH_PORT=22

# fail2ban defaults
DEFAULT_FAIL2BAN_BANTIME=3600
DEFAULT_FAIL2BAN_FINDTIME=600
DEFAULT_FAIL2BAN_MAXRETRY=5

# Auto-mitigation defaults (Safe)
AUTOMIT_BANTIME=600
SYN_PER_IP_THRESHOLD=200
UDP_PER_IP_THRESHOLD=2000
NEWCONN_PER_IP_THRESHOLD=200
AUTOMIT_POLL_SEC=5

# nft monitor cron rotation: clear every minute to limit disk usage
CRON_CLEAR_NFT="*/1 * * * * root : > $NFT_LOG"

### ---------------- UTILITIES ----------------
color(){ case "$1" in red) echo -e "\e[31m$2\e[0m";; green) echo -e "\e[32m$2\e[0m";; yellow) echo -e "\e[33m$2\e[0m";; blue) echo -e "\e[34m$2\e[0m";; *) echo "$2";; esac }
pause(){ read -rp "Press Enter / กด Enter ..." _; }
backup_file(){ local f="$1"; [ -f "$f" ] && cp -a "$f" "$BACKUP_DIR/$(basename "$f").$(date +%s).bk"; }
require_root
  # Auto-detect ports before applying/installing anything
  auto_detect_ports || true(){ [ "$EUID" -ne 0 ] && { color red "โปรดรันด้วย root (sudo)"; exit 2; } }

safe_command_install(){ # install a list of packages non interactively
  local pkgs=("$@")
  apt update -y >/dev/null 2>&1 || true
  for p in "${pkgs[@]}"; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt -y install "$p" >/dev/null 2>&1 || true
    fi
  done
}

### ---------------- SERVICE CHECK & DASHBOARD ----------------
show_status(){
  require_root
  echo "==============================="
  echo "   HardShield-X Monitor Status"
  echo "==============================="

  # Smart Load Detection
  syn=$(ss -tn state syn-recv 2>/dev/null | wc -l || echo 0)
  udp=$(ss -u -a 2>/dev/null | wc -l || echo 0)
  ct=$( (conntrack -C 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) || echo 0 )

  # Smart Level
  status_text="Safe"
  status_emoji="🟢"
  bg="\e[42m"
  if [ "$syn" -gt 2000 ] || [ "$udp" -gt 50000 ] || [ "$ct" -gt 350000 ]; then
    status_text="Under Heavy Attack"
    status_emoji="🔥"
    bg="\e[41m"
  elif [ "$syn" -gt 800 ] || [ "$udp" -gt 20000 ] || [ "$ct" -gt 250000 ]; then
    status_text="Under Medium Attack"
    status_emoji="🟠"
    bg="\e[43m"
  elif [ "$syn" -gt 500 ] || [ "$udp" -gt 10000 ] || [ "$ct" -gt 200000 ]; then
    status_text="Attacked"
    status_emoji="🔴"
    bg="\e[41m"
  fi

  # display banner with background
  echo -e "${bg} Server : ${status_text} ${status_emoji} \e[0m"
  echo "Server Load → SYN: ${syn} | UDP: ${udp} | CT: ${ct}"
  echo "==============================="

  # Service checks (10 items)
  chk(){ command -v "$1" >/dev/null 2>&1 && echo "[ON]" || echo "[OFF]"; }
  svc_active(){ systemctl is-active "$1" >/dev/null 2>&1 && echo "[ON]" || echo "[OFF]"; }
  svc_color(){ [[ $1 == "[ON]" ]] && color green "$1" || color red "$1"; }

  s_ufw=$(svc_active ufw)
  s_nft=$(svc_active nftables)
  s_ipset=$(chk ipset)
  s_fail2ban=$(svc_active fail2ban)
  s_conntrack=$(chk conntrack)
  s_lsof=$(chk lsof)
  s_nettools=$(chk netstat)
  s_tcpdump=$(chk tcpdump)
  s_nftmon=$(svc_active nft-monitor)
  s_cron=$(svc_active cron)

  printf "UFW        : %s   nftables     : %s\n" "$(svc_color $s_ufw)" "$(svc_color $s_nft)"
  printf "ipset      : %s   fail2ban     : %s\n" "$(svc_color $s_ipset)" "$(svc_color $s_fail2ban)"
  printf "conntrack  : %s   lsof         : %s\n" "$(svc_color $s_conntrack)" "$(svc_color $s_lsof)"
  printf "net-tools  : %s   tcpdump      : %s\n" "$(svc_color $s_nettools)" "$(svc_color $s_tcpdump)"
  printf "monitor    : %s   cron         : %s\n" "$(svc_color $s_nftmon)" "$(svc_color $s_cron)"

  echo "-------------------------------"
  echo "Status: ✔ Installed"
  echo "==============================="
}

### ---------------- DEPENDENCIES INSTALLER ----------------
ensure_base_packages(){
  require_root
  safe_command_install ufw nftables ipset fail2ban conntrack net-tools tcpdump lsof cron curl wget
  # enable services if present
  systemctl enable --now nftables || true
  systemctl enable --now cron || true
  ipset_setup || true
  configure_fail2ban || true
}

### ---------------- NFT MONITOR (full trace) ----------------
NFT_MONITOR_SCRIPT="/usr/local/bin/nft-monitor.sh"
NFT_MONITOR_SERVICE="/etc/systemd/system/nft-monitor.service"

install_nft_monitor(){
  require_root
  cat > "$NFT_MONITOR_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# nft monitor trace loop
while true; do
  nft monitor trace >> /var/log/nft-ddos.log 2>&1
  sleep 0.2
done
EOF
  chmod +x "$NFT_MONITOR_SCRIPT"

  cat > "$NFT_MONITOR_SERVICE" <<EOF
[Unit]
Description=NFT Full Trace Monitor
After=network.target nftables.service

[Service]
ExecStart=$NFT_MONITOR_SCRIPT
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload || true
  systemctl enable --now nft-monitor.service || true
  # ensure cron clears the file every minute to limit disk usage
  if ! grep -q "nft-ddos.log" /etc/crontab 2>/dev/null; then
    echo "$CRON_CLEAR_NFT" >> /etc/crontab
  fi
  touch "$NFT_LOG" || true
  color green "nft monitor installed and started"
}

### ---------------- IPSET helpers ----------------
ipset_setup(){
  if ! command -v ipset >/dev/null 2>&1; then apt -y install ipset >/dev/null 2>&1 || true; fi
  if ! ipset list -n | grep -q "^$IPSET_NAME$" 2>/dev/null; then
    ipset create "$IPSET_NAME" hash:ip family inet hashsize 1024 maxelem 200000
    color green "ipset $IPSET_NAME created"
  fi
}
ipset_add(){ local ip=$1; local t=${2:-$AUTOMIT_BANTIME}; ipset add "$IPSET_NAME" "$ip" timeout "$t" 2>/dev/null || true; color yellow "ipset add $ip"; }
ipset_del(){ local ip=$1; ipset del "$IPSET_NAME" "$ip" 2>/dev/null || true; color yellow "ipset del $ip"; }
ipset_list(){ ipset list "$IPSET_NAME" 2>/dev/null || echo "no ipset $IPSET_NAME"; }

### ---------------- FAIL2BAN config ----------------
configure_fail2ban(){
  backup_file /etc/fail2ban/jail.local || true
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = $DEFAULT_FAIL2BAN_BANTIME
findtime = $DEFAULT_FAIL2BAN_FINDTIME
maxretry = $DEFAULT_FAIL2BAN_MAXRETRY
banaction = iptables-ipset-proto

[sshd]
enabled = true
port = $EMERGENCY_SSH_PORT
logpath = /var/log/auth.log
maxretry = $DEFAULT_FAIL2BAN_MAXRETRY
EOF
  if [ ! -f /etc/fail2ban/action.d/iptables-ipset-proto.conf ]; then
    cat > /etc/fail2ban/action.d/iptables-ipset-proto.conf <<'ACT'
[Definition]
actionstart = <iptables> -N f2b-<name>
<iptables> -A INPUT -p <protocol> -m set --match-set <ipset> src -j DROP
actionstop = <iptables> -D INPUT -p <protocol> -m set --match-set <ipset> src -j DROP || true
<iptables> -F f2b-<name> || true
<iptables> -X f2b-<name> || true
actionban = /sbin/ipset add <ipset> <ip> timeout %(_bantime)s
actionunban = /sbin/ipset del <ipset> <ip> || true

[Init]
protocol = tcp
ipset = $IPSET_NAME
iptables = /sbin/iptables
ACT
  fi
  systemctl enable --now fail2ban || true
  systemctl restart fail2ban || true
  color green "fail2ban configured"
}

### ---------------- SYSCTL HARDEN ----------------
apply_sysctl(){
  backup_file /etc/sysctl.d/99-harden.conf || true
  cat > /etc/sysctl.d/99-harden.conf <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fin_timeout = 15
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.netfilter.nf_conntrack_max = 262144
EOF
  sysctl --system || true
  color green "sysctl applied"
}

### ---------------- NFT TEMPLATE builder ----------------
NFT_CONF="/etc/nftables.conf"
ALLOWED_TCP=()
ALLOWED_UDP=()

build_nft(){
  backup_file "$NFT_CONF"
  cat > "$NFT_CONF" <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    tcp flags & syn == syn limit rate 100/second counter accept
EOF
  for p in "${ALLOWED_TCP[@]:-}"; do
    [[ -z "$p" ]] && continue
    echo "    tcp dport $p accept" >> "$NFT_CONF"
  done
  for p in "${ALLOWED_UDP[@]:-}"; do
    [[ -z "$p" ]] && continue
    echo "    udp dport $p accept" >> "$NFT_CONF"
  done
  cat >> "$NFT_CONF" <<'EOF'
    ct state new limit rate 50/second counter accept
    counter log prefix "NFT-DROP: " drop
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
}

apply_nft(){
  systemctl enable --now nftables || true
  nft flush ruleset || true
  build_nft
  nft -f "$NFT_CONF" || nft list ruleset
}

### ---------------- DETECTION ----------------
# Detect listening ports (legacy) and a universal auto-detect + prepare function
detect_services(){
  DETECTED_TCP_PORTS=()
  DETECTED_UDP_PORTS=()
  mapfile -t sslines < <(ss -tunlp 2>/dev/null || ss -tunlpH 2>/dev/null)
  for ln in "${sslines[@]}"; do
    if [[ "$ln" =~ :([0-9]+) ]]; then
      DETECTED_TCP_PORTS+=("${BASH_REMATCH[1]}")
    fi
  done
  mapfile -t udplines < <(ss -unlp 2>/dev/null || ss -unlpH 2>/dev/null)
  for ln in "${udplines[@]}"; do
    if [[ "$ln" =~ :([0-9]+) ]]; then DETECTED_UDP_PORTS+=("${BASH_REMATCH[1]}"); fi
  done
  DETECTED_TCP_PORTS=( $(printf "%s
" "${DETECTED_TCP_PORTS[@]}" | sort -n -u) )
  DETECTED_UDP_PORTS=( $(printf "%s
" "${DETECTED_UDP_PORTS[@]}" | sort -n -u) )
  color green "Detected TCP: ${DETECTED_TCP_PORTS[*]}"
}

# New universal auto-detect (recommended) -- scans active/listening ports and fills ALLOWED arrays
auto_detect_ports(){
  ALLOWED_TCP=()
  ALLOWED_UDP=()
  # TCP listening ports
  mapfile -t ALLOWED_TCP < <(ss -tulnp 2>/dev/null | awk '/LISTEN/ {print $5}' | sed 's/.*://g' | grep -E '^[0-9]+$' | sort -n -u)
  # UDP ports (may include many ephemeral sockets) -- keep ones commonly bound
  mapfile -t ALLOWED_UDP < <(ss -u -a 2>/dev/null | awk '{print $5}' | sed 's/.*://g' | grep -E '^[0-9]+$' | sort -n -u)
  # filter empty
  ALLOWED_TCP=( $(printf "%s
" "${ALLOWED_TCP[@]:-}" | grep -E '^[0-9]+$' | sort -n -u) )
  ALLOWED_UDP=( $(printf "%s
" "${ALLOWED_UDP[@]:-}" | grep -E '^[0-9]+$' | sort -n -u) )
  color green "Auto-detected TCP: ${ALLOWED_TCP[*]}"
  color green "Auto-detected UDP: ${ALLOWED_UDP[*]}"
}

# Convert detected lists (detect_services) into ALLOWED lists and apply nft rules
prepare_allowed_lists_from_detect(){
  # prefer auto_detect_ports if available
  if [ -n "${ALLOWED_TCP+x}" ] && [ ${#ALLOWED_TCP[@]} -gt 0 ]; then
    : # already have ALLOWED_TCP set by auto_detect_ports
  else
    detect_services || true
    ALLOWED_TCP=("${DETECTED_TCP_PORTS[@]:-}")
    ALLOWED_UDP=("${DETECTED_UDP_PORTS[@]:-}")
  fi
  # dedupe and sort
  ALLOWED_TCP=( $(printf "%s
" "${ALLOWED_TCP[@]:-}" | grep -E '^[0-9]+$' | sort -n -u) )
  ALLOWED_UDP=( $(printf "%s
" "${ALLOWED_UDP[@]:-}" | grep -E '^[0-9]+$' | sort -n -u) )
  color green "Prepared ALLOWED_TCP: ${ALLOWED_TCP[*]}"
  color green "Prepared ALLOWED_UDP: ${ALLOWED_UDP[*]}"
  # apply nft rules automatically after preparing lists
  apply_nft || true
}

### ---------------- AUTO MITIGATION (Safe/Aggressive/Extreme) ----------------
AUTOMIT_SCRIPT="/usr/local/bin/auto-mitigation.sh"
AUTOMIT_SERVICE="/etc/systemd/system/auto-mitigation.service"
SAFELIST_DIR="/etc/HardShieldX"
SAFELIST_FILE="$SAFELIST_DIR/safelist.txt"

install_auto_mitigation(){
  require_root
  mkdir -p "$SAFELIST_DIR"
  touch "$SAFELIST_FILE"
  cat > "$AUTOMIT_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Read thresholds from environment if set (script will be invoked from the main script)
SYN_THR=${SYN_PER_IP_THRESHOLD:-200}
UDP_THR=${UDP_PER_IP_THRESHOLD:-2000}
NEW_THR=${NEWCONN_PER_IP_THRESHOLD:-200}
BANTIME=${AUTOMIT_BANTIME:-600}
IPSET_NAME="${IPSET_NAME:-blacklist_attacker}"
SAFELIST_FILE="${SAFELIST_FILE:-/etc/HardShieldX/safelist.txt}"
ATTACK_LOG="${ATTACK_LOG:-/var/log/attack-detect.log}"

in_safelist(){ local ip=$1; grep -Fxq "$ip" "$SAFELIST_FILE" 2>/dev/null && return 0 || return 1; }

while true; do
  tmp_safe="/tmp/hh_safe.$$"
  ss -tn state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E -v '^$' | sort -u > "$tmp_safe"
  if [ -f "$SAFELIST_FILE" ]; then cat "$SAFELIST_FILE" >> "$tmp_safe"; sort -u -o "$tmp_safe" "$tmp_safe"; fi

  # SYN
  ss -tn state syn-recv 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E -v '^$' | sort | uniq -c | while read -r cnt ip; do
    cnt=${cnt:-0}
    if [ "$cnt" -ge "$SYN_THR" ]; then
      if ! grep -Fxq "$ip" "$tmp_safe" 2>/dev/null; then
        ipset add "$IPSET_NAME" "$ip" timeout "$BANTIME" 2>/dev/null || true
        echo "$(date '+%F %T') MITIGATE SYN $ip count=$cnt" >> "$ATTACK_LOG"
      fi
    fi
  done

  # NEWCONN (approx)
  ss -tn state syn-recv 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E -v '^$' | sort | uniq -c | while read -r cnt ip; do
    cnt=${cnt:-0}
    if [ "$cnt" -ge "$NEW_THR" ]; then
      if ! grep -Fxq "$ip" "$tmp_safe" 2>/dev/null; then
        ipset add "$IPSET_NAME" "$ip" timeout "$BANTIME" 2>/dev/null || true
        echo "$(date '+%F %T') MITIGATE NEWCONN $ip count=$cnt" >> "$ATTACK_LOG"
      fi
    fi
  done

  # UDP
  ss -u -a 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E -v '^$' | sort | uniq -c | while read -r cnt ip; do
    cnt=${cnt:-0}
    if [ "$cnt" -ge "$UDP_THR" ]; then
      if ! grep -Fxq "$ip" "$tmp_safe" 2>/dev/null; then
        ipset add "$IPSET_NAME" "$ip" timeout "$BANTIME" 2>/dev/null || true
        echo "$(date '+%F %T') MITIGATE UDP $ip count=$cnt" >> "$ATTACK_LOG"
      fi
    fi
  done

  rm -f "$tmp_safe" || true
  sleep ${AUTOMIT_POLL_SEC:-5}
done
EOF
  chmod +x "$AUTOMIT_SCRIPT"

  cat > "$AUTOMIT_SERVICE" <<EOF
[Unit]
Description=HardShield-X Auto-Mitigation
After=network.target nft-monitor.service ipset.service

[Service]
ExecStart=$AUTOMIT_SCRIPT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload || true
  systemctl enable --now auto-mitigation.service || true
  color green "Auto-Mitigation installed & started"
}

### ---------------- MENUS (partial; backup/menu functions above) ----------------
menu_firewall(){
  while true; do
    clear; color blue "== Firewall Manager / ไฟร์วอลล์ =="
    echo "1) Toggle UFW on/off  |  เปิด/ปิด UFW"
    echo "2) Show UFW rules  |  แสดงกฎ UFW"
    echo "3) Add port to UFW  |  เพิ่มพอร์ตใน UFW"
    echo "4) Delete port from UFW  |  ลบพอร์ต"
    echo "5) Reset UFW  |  รีเซ็ต UFW"
    echo "6) Show nftables rules  |  แสดงกฎ nftables"
    echo "7) Reload nftables  |  โหลด nft ใหม่"
    echo "8) Add ALLOWED TCP port (nft)  |  เพิ่มพอร์ตใน ALLOWED"
    echo "9) Apply combined UFW+nft  |  ใช้กฎทั้งหมด"
    echo "0) Back  |  ย้อนกลับ"
    read -rp "เลือก: " fwopt
    case "$fwopt" in
      1) read -rp "on/off: " v; if [[ $v == "on" ]]; then ufw_enable; else ufw_disable; fi; pause;;
      2) ufw_status; pause;;
      3) read -rp "Port (e.g. 8080): " p; read -rp "proto (tcp/udp): " proto; ufw_allow "$p" "$proto"; pause;;
      4) read -rp "Port to delete: " p; read -rp "proto: " proto; ufw_delete "$p" "$proto"; pause;;
      5) read -rp "Confirm reset (yes): " c; if [[ $c == "yes" ]]; then ufw_reset; fi; pause;;
      6) nft list ruleset || true; pause;;
      7) apply_nft; pause;;
      8) read -rp "Port to add to ALLOWED_TCP: " p; ALLOWED_TCP+=("$p"); apply_nft; pause;;
      9) apply_ufw_and_nft; pause;;
      0) break;;
    esac
  done
}

menu_hardening(){
  while true; do
    clear; color blue "== Hardening Settings / ตั้งค่าความปลอดภัย =="
    echo "1) Apply sysctl hardening  |  เปิด sysctl hardening"
    echo "2) Tune SYN rate (nft template)  |  ตั้งค่า SYN rate"
    echo "3) UDP protection note  |  ตั้งค่า UDP"
    echo "4) Per-IP conn rate limit  |  ตั้ง rate-limit ต่อ IP"
    echo "5) Show current sysctl  |  ดูค่า sysctl"
    echo "0) Back  |  ย้อนกลับ"
    read -rp "เลือก: " ho
    case "$ho" in
      1) apply_sysctl; pause;;
      2) read -rp "Enter rate (e.g. 100/second): " r; sed -i "s/limit rate [0-9]\+\/second/limit rate $r/" "$NFT_CONF" 2>/dev/null || true; nft -f "$NFT_CONF" || true; pause;;
      3) echo "Use Firewall Manager -> Add UDP ports or restrict ranges"; pause;;
      4) echo "Edit nft template via Firewall Manager -> Add port and tune rate limits"; pause;;
      5) sysctl -a | egrep 'tcp_syncookies|tcp_max_syn_backlog|nf_conntrack_max|rp_filter' || true; pause;;
      0) break;;
    esac
  done
}

menu_ipset(){
  while true; do
    clear; color blue "== IPSet Manager =="
    echo "1) Add IP to blacklist  |  เพิ่ม IP เข้า blacklist"
    echo "2) Remove IP from blacklist  |  ลบ IP"
    echo "3) Show blacklist  |  ดู blacklist"
    echo "4) Flush blacklist  |  ล้างทั้งหมด"
    echo "0) Back  |  ย้อนกลับ"
    read -rp "เลือก: " io
    case "$io" in
      1) read -rp "IP to add: " ip; read -rp "timeout sec (default $AUTOMIT_BANTIME): " t; t=${t:-$AUTOMIT_BANTIME}; ipset_add "$ip" "$t"; pause;;
      2) read -rp "IP to del: " ip; ipset_del "$ip"; pause;;
      3) ipset_list; pause;;
      4) ipset destroy "$IPSET_NAME" 2>/dev/null || true; ipset create "$IPSET_NAME" hash:ip; pause;;
      0) break;;
    esac
  done
}

menu_logs(){
  while true; do
    clear; color blue "== Logs & Monitor =="
    echo "1) Tail attack log  |  ดู log การโดนยิง"
    echo "2) Tail nft-ddos log  |  ดู nft monitor"
    echo "3) Show top IPs by connections  |  สรุป IP"
    echo "4) Check SYN / UDP / Conntrack now  |  ตรวจตอนนี้"
    echo "0) Back  |  ย้อนกลับ"
    read -rp "เลือก: " lo
    case "$lo" in
      1) tail -n 200 "$ATTACK_LOG" || echo "no attack log"; pause;;
      2) tail -n 200 "$NFT_LOG" || echo "no nft log"; pause;;
      3) ss -tn | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -n 50; pause;;
      4) echo "SYN:"; ss -tn state syn-recv | wc -l; echo "UDP sockets:"; ss -u -a | wc -l; echo "Conntrack:"; (conntrack -C 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0); pause;;
      0) break;;
    esac
  done
}

menu_ports(){
  while true; do
    clear; color blue "== Ports & Services =="
    echo "1) Show listening ports"
    echo "2) Kill process by port"
    echo "3) Auto-detect and add to ALLOWED lists"
    echo "0) Back"
    read -rp "เลือก: " po
    case "$po" in
      1) ss -tunlp || true; pause;;
      2) read -rp "Port to kill: " p; pid=$(lsof -i :$p -t || true); if [ -n "$pid" ]; then kill -9 $pid || true; color yellow "killed $pid"; else echo "no process"; fi; pause;;
      3) detect_services; prepare_allowed_lists_from_detect; color green "Auto-detected ports added"; pause;;
      0) break;;
    esac
  done
}

menu_xray3xui(){
  while true; do
    clear; color blue "== Xray / 3X-UI Tools =="
    echo "1) Auto-detect Xray/V2Ray ports"
    echo "2) Add detected ports to ALLOWED"
    echo "0) Back"
    read -rp "เลือก: " xr
    case "$xr" in
      1) detect_services; pause;;
      2) prepare_allowed_lists_from_detect; apply_ufw_and_nft; pause;;
      0) break;;
    esac
  done
}

menu_givpn(){
  while true; do
    clear; color blue "== GIVPN Tools =="
    echo "1) Scan common configs for ports"
    echo "2) Apply firewall for GIVPN"
    echo "0) Back"
    read -rp "เลือก: " gi
    case "$gi" in
      1) grep -R "listen" /etc/nginx /etc/squid* /etc/stunnel* 2>/dev/null || echo "no common configs"; pause;;
      2) apply_ufw_and_nft; pause;;
      0) break;;
    esac
  done
}

menu_backup(){
  while true; do
    clear; color blue "== Backup & Restore =="
    echo "1) Backup configs to $BACKUP_DIR"
    echo "2) List backups"
    echo "3) Restore latest backup"
    echo "0) Back"
    read -rp "เลือก: " b
    case "$b" in
      1) mkdir -p "$BACKUP_DIR"; cp -a /etc/ufw /etc/nftables.conf /etc/fail2ban /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true; color green "backup completed to $BACKUP_DIR"; pause;;
      2) ls -lah "$BACKUP_DIR" || echo "no backups"; pause;;
      3) echo "Restore manually by copying files from $BACKUP_DIR"; pause;;
      0) break;;
    esac
  done
}

### ---------------- DASHBOARD PRO MODE & MAIN MENU (full) ----------------
main_menu(){
  require_root
  ensure_base_packages || true
  install_nft_monitor || true
  install_auto_mitigation || true
  while true; do
    clear
    show_status
    echo "Service Status:\n"
    printf "UFW:%-5s nftables:%-5s ipset:%-5s fail2ban:%-5s conntrack:%-5s\n" "$(command -v ufw >/dev/null && echo ON || echo OFF)" "$(systemctl is-active nftables >/dev/null && echo ON || echo OFF)" "$(command -v ipset >/dev/null && echo ON || echo OFF)" "$(systemctl is-active fail2ban >/dev/null && echo ON || echo OFF)" "$(command -v conntrack >/dev/null && echo ON || echo OFF)"
    printf "lsof:%-5s net-tools:%-5s tcpdump:%-5s monitor:%-5s cron:%-5s\n" "$(command -v lsof >/dev/null && echo ON || echo OFF)" "$(command -v netstat >/dev/null && echo ON || echo OFF)" "$(command -v tcpdump >/dev/null && echo ON || echo OFF)" "$(systemctl is-active nft-monitor >/dev/null && echo ON || echo OFF)" "$(systemctl is-active cron >/dev/null && echo ON || echo OFF)"
    echo "==============================="
    echo "1) Firewall Manager"
    echo "2) Auto-Mitigation Modes"
    echo "3) Ports & Services"
    echo "4) System Hardening"
    echo "5) Logs & Monitoring"
    echo "6) Xray / 3X-UI"
    echo "7) GIVPN Tools"
    echo "8) IPSet Manager"
    echo "9) Backup & Restore"
    echo "0) Exit"
    echo "==============================="
    read -rp "เลือกเมนู: " mm
    case "$mm" in
      1) menu_firewall;;
      2) menu_mitigation;;
      3) menu_ports;;
      4) menu_hardening;;
      5) menu_logs;;
      6) menu_xray3xui;;
      7) menu_givpn;;
      8) menu_ipset;;
      9) menu_backup;;
      0) echo "Exiting..."; exit 0;;
      *) echo "เลือกไม่ถูกต้อง"; pause;;
    esac
  done
}

# start
main_menu

