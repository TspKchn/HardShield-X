#!/usr/bin/env bash
# ============================================================
# HardShield-X v1.0
# Universal Hardening & DDoS Protection Panel
# Target: Ubuntu 18.04 - 22.04
# ============================================================

set -euo pipefail
IFS=$'\n\t'

# ============================================================
# GLOBAL CONFIG
# ============================================================
VERSION="1.0.0"

BASE_DIR="/etc/HardShieldX"
LOG_DIR="/var/log/hardshieldx"
BACKUP_DIR="/root/HardShieldX_backups"

ATTACK_LOG="$LOG_DIR/attack.log"
NFT_LOG="$LOG_DIR/nft-ddos.log"
SERVICE_LOG="$LOG_DIR/service.log"

IPSET_NAME="hsx_blacklist"
SAFELIST_FILE="$BASE_DIR/safelist.txt"

AUTOMIT_MODE="SAFE"          # SAFE | AGGRESSIVE | EXTREME
AUTOMIT_BANTIME=600
AUTOMIT_POLL_SEC=5

mkdir -p "$BASE_DIR" "$LOG_DIR" "$BACKUP_DIR"
touch "$ATTACK_LOG" "$NFT_LOG" "$SERVICE_LOG" "$SAFELIST_FILE"

# ============================================================
# UTILITIES
# ============================================================
color(){
  case "$1" in
    red)    echo -e "\e[31m$2\e[0m";;
    green)  echo -e "\e[32m$2\e[0m";;
    yellow) echo -e "\e[33m$2\e[0m";;
    blue)   echo -e "\e[34m$2\e[0m";;
    cyan)   echo -e "\e[36m$2\e[0m";;
    *)      echo "$2";;
  esac
}

pause(){
  read -rp "กด Enter เพื่อกลับเมนู..." _
}

require_root(){
  if [ "$EUID" -ne 0 ]; then
    color red "กรุณารันด้วย root (sudo)"
    exit 1
  fi
}

log(){
  echo "$(date '+%F %T') $*" >> "$SERVICE_LOG"
}

backup_file(){
  local f="$1"
  [ -f "$f" ] && cp -a "$f" "$BACKUP_DIR/$(basename "$f").$(date +%s).bak"
}

safe_install(){
  apt update -y >/dev/null 2>&1 || true
  for p in "$@"; do
    dpkg -s "$p" >/dev/null 2>&1 || apt install -y "$p" >/dev/null 2>&1
  done
}

# ============================================================
# DEPENDENCIES INSTALLER
# ============================================================
ensure_base_packages(){
  require_root
  safe_install \
    ufw nftables ipset fail2ban conntrack \
    net-tools tcpdump lsof cron curl wget

  systemctl enable --now nftables >/dev/null 2>&1 || true
  systemctl enable --now cron >/dev/null 2>&1 || true
  systemctl enable --now ufw >/dev/null 2>&1 || true

  log "Base packages ensured"
}

# ============================================================
# SERVICE CHECK HELPERS
# ============================================================
svc_active(){
  systemctl is-active "$1" >/dev/null 2>&1 && echo "ON" || echo "OFF"
}

cmd_exist(){
  command -v "$1" >/dev/null 2>&1 && echo "ON" || echo "OFF"
}

svc_color(){
  case "$1" in
    ON)  color green "[ON]" ;;
    OFF) color red "[OFF]" ;;
    *)   echo "$1" ;;
  esac
}

# ============================================================
# SHOWON-STYLE SERVICE STATUS PANEL (10 SERVICES)
# ============================================================
show_service_panel(){
  local ufw nft ipset fail2ban conntrack lsof nettools tcpdump monitor cron

  ufw=$(svc_active ufw)
  nft=$(svc_active nftables)
  ipset=$(cmd_exist ipset)
  fail2ban=$(svc_active fail2ban)
  conntrack=$(cmd_exist conntrack)
  lsof=$(cmd_exist lsof)
  nettools=$(cmd_exist netstat)
  tcpdump=$(cmd_exist tcpdump)
  monitor=$(svc_active nft-monitor)
  cron=$(svc_active cron)

  echo "==============================="
  echo "   HardShield-X Service Status"
  echo "==============================="

  printf "UFW        : %-6s nftables     : %s\n" \
    "$(svc_color "$ufw")" "$(svc_color "$nft")"

  printf "ipset      : %-6s fail2ban     : %s\n" \
    "$(svc_color "$ipset")" "$(svc_color "$fail2ban")"

  printf "conntrack  : %-6s lsof         : %s\n" \
    "$(svc_color "$conntrack")" "$(svc_color "$lsof")"

  printf "net-tools  : %-6s tcpdump      : %s\n" \
    "$(svc_color "$nettools")" "$(svc_color "$tcpdump")"

  printf "monitor    : %-6s cron         : %s\n" \
    "$(svc_color "$monitor")" "$(svc_color "$cron")"

  echo "-------------------------------"
  echo "Status: Installed"
  echo "==============================="
}

# ============================================================
# SMART STATUS & SMART LEVEL
# ============================================================
get_smart_status(){
  local syn udp ct

  syn=$(ss -tn state syn-recv 2>/dev/null | wc -l || echo 0)
  udp=$(ss -u -a 2>/dev/null | wc -l || echo 0)
  ct=$(conntrack -C 2>/dev/null || echo 0)

  SMART_LEVEL="SAFE"
  SMART_EMOJI="🟢"
  SMART_TEXT="Server : Safe"

  if [ "$syn" -gt 500 ] || [ "$udp" -gt 10000 ] || [ "$ct" -gt 200000 ]; then
    SMART_LEVEL="ATTACKED"
    SMART_EMOJI="🔴"
    SMART_TEXT="Server : Attacked"
  fi

  if [ "$syn" -gt 1200 ] || [ "$udp" -gt 25000 ] || [ "$ct" -gt 300000 ]; then
    SMART_LEVEL="EXTREME"
    SMART_EMOJI="🔥"
    SMART_TEXT="Server : Under Heavy Attack"
  fi
}

show_smart_status(){
  get_smart_status
  echo "======================================"
  echo " $SMART_TEXT $SMART_EMOJI"
  echo " Smart Level : $SMART_LEVEL"
  echo "======================================"
}

# ============================================================
# ADVANCED PORT AUTO DETECTION
# รองรับ: SSH, Web, VPN, 3X-UI, GIVPN, Custom services
# ============================================================

DETECTED_TCP_PORTS=()
DETECTED_UDP_PORTS=()

detect_ports_ss(){
  DETECTED_TCP_PORTS=()
  DETECTED_UDP_PORTS=()

  command -v ss >/dev/null 2>&1 || return 0

  # TCP LISTEN
  mapfile -t DETECTED_TCP_PORTS < <(
    ss -tulnp 2>/dev/null |
    awk '/LISTEN/ {print $5}' |
    sed 's/.*://' |
    grep -E '^[0-9]+$' |
    sort -n -u
  )

  # UDP (exclude ephemeral > 40000)
  mapfile -t DETECTED_UDP_PORTS < <(
    ss -u -a 2>/dev/null |
    awk '{print $5}' |
    sed 's/.*://' |
    grep -E '^[0-9]+$' |
    awk '$1 < 40000' |
    sort -n -u
  )
}

# ------------------------------------------------------------
# Detect common service configs (3X-UI / GIVPN / nginx / squid)
# ------------------------------------------------------------
detect_ports_configs(){
  local ports=()

  # nginx
  ports+=( $(grep -RhoP 'listen\s+\K[0-9]+' /etc/nginx 2>/dev/null || true) )

  # stunnel
  ports+=( $(grep -RhoP 'accept\s*=\s*\K[0-9]+' /etc/stunnel* 2>/dev/null || true) )

  # squid
  ports+=( $(grep -RhoP 'http_port\s+\K[0-9]+' /etc/squid* 2>/dev/null || true) )

  # xray / v2ray / 3x-ui
  ports+=( $(grep -RhoP '"port"\s*:\s*\K[0-9]+' /etc/xray /etc/v2ray /etc/3x-ui 2>/dev/null || true) )

  printf "%s\n" "${ports[@]}" | grep -E '^[0-9]+$' | sort -n -u
}

# ============================================================
# PREPARE ALLOWED PORT LISTS (UNIVERSAL)
# ============================================================
prepare_allowed_lists_from_detect(){
  log "Detecting active ports"

  detect_ports_ss

  local cfg_ports=()
  mapfile -t cfg_ports < <(detect_ports_configs)

  ALLOWED_TCP=()
  ALLOWED_UDP=()

  # Merge TCP
  ALLOWED_TCP+=( "${DETECTED_TCP_PORTS[@]}" )
  ALLOWED_TCP+=( "${cfg_ports[@]}" )

  # Merge UDP
  ALLOWED_UDP+=( "${DETECTED_UDP_PORTS[@]}" )

  # Deduplicate & sort
  ALLOWED_TCP=( $(printf "%s\n" "${ALLOWED_TCP[@]}" | sort -n -u) )
  ALLOWED_UDP=( $(printf "%s\n" "${ALLOWED_UDP[@]}" | sort -n -u) )

  log "Allowed TCP ports: ${ALLOWED_TCP[*]}"
  log "Allowed UDP ports: ${ALLOWED_UDP[*]}"
}

# ============================================================
# SAFETY CHECK: PROTECT VPN CLIENTS
# (ไม่ block IP ที่มี established connection)
# ============================================================
is_established_ip(){
  local ip="$1"
  ss -tn state established 2>/dev/null | grep -qw "$ip"
}

# ============================================================
# DEBUG / VIEW DETECTED PORTS
# ============================================================
show_detected_ports(){
  echo "==============================="
  echo "Detected TCP Ports:"
  echo "  ${ALLOWED_TCP[*]:-none}"
  echo "Detected UDP Ports:"
  echo "  ${ALLOWED_UDP[*]:-none}"
  echo "==============================="
}

# ============================================================
# NFTABLES + IPSET CORE FIREWALL
# ============================================================

NFT_CONF="/etc/nftables.conf"

apply_nftables_firewall(){
  require_root
  backup_file "$NFT_CONF"
  ipset_setup

  log "Applying nftables firewall"

  cat > "$NFT_CONF" <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {

  chain input {
    type filter hook input priority 0;
    policy drop;

    # --- Loopback ---
    iif lo accept

    # --- Established / Related ---
    ct state established,related accept

    # --- Invalid packets ---
    ct state invalid drop

    # --- Drop blacklisted IPs (ipset) ---
    ip saddr @$IPSET_NAME drop

    # --- ICMP (limited) ---
    ip protocol icmp limit rate 5/second accept

    # --- SSH protection (anti-bruteforce) ---
    tcp dport 22 ct state new limit rate 5/minute accept

    # ========================================================
    # ALLOWED TCP PORTS (AUTO-DETECTED)
    # ========================================================
EOF

  for p in "${ALLOWED_TCP[@]:-}"; do
    echo "    tcp dport $p accept" >> "$NFT_CONF"
  done

  cat >> "$NFT_CONF" <<EOF

    # ========================================================
    # ALLOWED UDP PORTS (AUTO-DETECTED)
    # ========================================================
EOF

  for p in "${ALLOWED_UDP[@]:-}"; do
    echo "    udp dport $p accept" >> "$NFT_CONF"
  done

  cat >> "$NFT_CONF" <<'EOF'

    # ========================================================
    # ANTI-DDoS GENERIC PROTECTION
    # ========================================================

    # SYN flood protection
    tcp flags syn limit rate 100/second burst 200 packets accept

    # New connection rate limit per IP
    ct state new limit rate 50/second accept

    # UDP flood protection
    udp limit rate 500/second burst 1000 packets accept

    # Log & Drop everything else
    counter log prefix "HSX-DROP: " drop
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;
  }

  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}
EOF

  nft -f "$NFT_CONF" && log "nftables rules applied"
}

# ============================================================
# IPSET SETUP & HELPERS
# ============================================================

ipset_setup(){
  if ! ipset list -n 2>/dev/null | grep -q "^$IPSET_NAME$"; then
    ipset create "$IPSET_NAME" hash:ip timeout "$AUTOMIT_BANTIME" maxelem 200000
    log "Created ipset $IPSET_NAME"
  fi
}

ipset_add(){
  local ip="$1"
  ipset add "$IPSET_NAME" "$ip" timeout "$AUTOMIT_BANTIME" 2>/dev/null || true
  log "IPSET ADD $ip"
}

ipset_del(){
  local ip="$1"
  ipset del "$IPSET_NAME" "$ip" 2>/dev/null || true
  log "IPSET DEL $ip"
}

ipset_list_all(){
  ipset list "$IPSET_NAME" 2>/dev/null || echo "No ipset"
}

# ============================================================
# SAFETY: DO NOT BLOCK ACTIVE CLIENTS
# ============================================================
safe_block_ip(){
  local ip="$1"
  if is_established_ip "$ip"; then
    log "SKIP blocking active IP $ip"
    return 0
  fi
  ipset_add "$ip"
}

# ============================================================
# QUICK FIREWALL STATUS
# ============================================================
show_firewall_status(){
  echo "==============================="
  echo " nftables ruleset"
  echo "==============================="
  nft list ruleset | sed -n '1,120p'
  echo "==============================="
}

# ============================================================
# AUTO MITIGATION ENGINE
# ============================================================

AUTOMIT_SCRIPT="/usr/local/bin/hardshieldx-auto-mitigate.sh"
AUTOMIT_SERVICE="/etc/systemd/system/hardshieldx-auto-mitigate.service"
SAFELIST_DIR="/etc/hardshieldx"
SAFELIST_FILE="$SAFELIST_DIR/safelist.txt"

# ------------------------------------------------------------
# MODE PROFILES
# ------------------------------------------------------------
set_mode_safe(){
  SYN_PER_IP_THRESHOLD=300
  UDP_PER_IP_THRESHOLD=3000
  NEWCONN_PER_IP_THRESHOLD=300
  AUTOMIT_BANTIME=600
  log "Mode set: SAFE"
}

set_mode_aggressive(){
  SYN_PER_IP_THRESHOLD=150
  UDP_PER_IP_THRESHOLD=1500
  NEWCONN_PER_IP_THRESHOLD=150
  AUTOMIT_BANTIME=1800
  log "Mode set: AGGRESSIVE"
}

set_mode_extreme(){
  SYN_PER_IP_THRESHOLD=80
  UDP_PER_IP_THRESHOLD=800
  NEWCONN_PER_IP_THRESHOLD=80
  AUTOMIT_BANTIME=3600
  log "Mode set: EXTREME"
}

# ------------------------------------------------------------
# INSTALL AUTO MITIGATION SERVICE
# ------------------------------------------------------------
install_auto_mitigation(){
  require_root
  mkdir -p "$SAFELIST_DIR"
  touch "$SAFELIST_FILE"

  cat > "$AUTOMIT_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

IPSET_NAME="blacklist_attacker"
ATTACK_LOG="/var/log/attack-detect.log"
SAFELIST_FILE="/etc/hardshieldx/safelist.txt"

SYN_THR=${SYN_PER_IP_THRESHOLD:-200}
UDP_THR=${UDP_PER_IP_THRESHOLD:-2000}
NEW_THR=${NEWCONN_PER_IP_THRESHOLD:-200}
BANTIME=${AUTOMIT_BANTIME:-600}
POLL=${AUTOMIT_POLL_SEC:-5}

is_safe(){
  grep -Fxq "$1" "$SAFELIST_FILE" 2>/dev/null
}

log_attack(){
  echo "$(date '+%F %T') $1" >> "$ATTACK_LOG"
}

while true; do

  # ---------------- SYN FLOOD ----------------
  ss -tn state syn-recv 2>/dev/null |
  awk '{print $5}' | cut -d: -f1 |
  sort | uniq -c |
  while read -r cnt ip; do
    [[ -z "$ip" ]] && continue
    if (( cnt >= SYN_THR )) && ! is_safe "$ip"; then
      ipset add "$IPSET_NAME" "$ip" timeout "$BANTIME" 2>/dev/null || true
      log_attack "SYN_FLOOD $ip count=$cnt"
    fi
  done

  # ---------------- NEW CONNECTION FLOOD ----------------
  ss -tn state syn-recv 2>/dev/null |
  awk '{print $5}' | cut -d: -f1 |
  sort | uniq -c |
  while read -r cnt ip; do
    [[ -z "$ip" ]] && continue
    if (( cnt >= NEW_THR )) && ! is_safe "$ip"; then
      ipset add "$IPSET_NAME" "$ip" timeout "$BANTIME" 2>/dev/null || true
      log_attack "NEW_CONN $ip count=$cnt"
    fi
  done

  # ---------------- UDP FLOOD ----------------
  ss -u -a 2>/dev/null |
  awk '{print $5}' | cut -d: -f1 |
  sort | uniq -c |
  while read -r cnt ip; do
    [[ -z "$ip" ]] && continue
    if (( cnt >= UDP_THR )) && ! is_safe "$ip"; then
      ipset add "$IPSET_NAME" "$ip" timeout "$BANTIME" 2>/dev/null || true
      log_attack "UDP_FLOOD $ip count=$cnt"
    fi
  done

  sleep "$POLL"
done
EOF

  chmod +x "$AUTOMIT_SCRIPT"

  cat > "$AUTOMIT_SERVICE" <<EOF
[Unit]
Description=HardShield-X Auto Mitigation Engine
After=network.target nftables.service

[Service]
ExecStart=$AUTOMIT_SCRIPT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now hardshieldx-auto-mitigate.service
  log "Auto-Mitigation service installed & running"
}

# ------------------------------------------------------------
# MITIGATION MENU
# ------------------------------------------------------------
menu_mitigation(){
  while true; do
    clear
    echo "==============================="
    echo " Auto-Mitigation Mode"
    echo "==============================="
    echo "1) SAFE        (default)"
    echo "2) AGGRESSIVE"
    echo "3) EXTREME"
    echo "4) Restart mitigation service"
    echo "0) Back"
    read -rp "เลือก: " m
    case "$m" in
      1) set_mode_safe; systemctl restart hardshieldx-auto-mitigate.service; pause;;
      2) set_mode_aggressive; systemctl restart hardshieldx-auto-mitigate.service; pause;;
      3) set_mode_extreme; systemctl restart hardshieldx-auto-mitigate.service; pause;;
      4) systemctl restart hardshieldx-auto-mitigate.service; pause;;
      0) break;;
    esac
  done
}

# ============================================================
# SMART STATUS ENGINE
# วิเคราะห์สถานะเซิร์ฟเวอร์แบบ Real-time
# ============================================================

SMART_STATUS="Safe"
SMART_COLOR="green"
SMART_ICON="🟢"
SMART_LEVEL=0

update_smart_status(){
  local syn udp ct

  syn=$(ss -tn state syn-recv 2>/dev/null | wc -l || echo 0)
  udp=$(ss -u -a 2>/dev/null | wc -l || echo 0)
  ct=$(conntrack -C 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)

  # Reset
  SMART_STATUS="Safe"
  SMART_COLOR="green"
  SMART_ICON="🟢"
  SMART_LEVEL=0

  # Extreme
  if (( syn > 2000 || udp > 50000 || ct > 350000 )); then
    SMART_STATUS="Under Heavy Attack"
    SMART_COLOR="red"
    SMART_ICON="🔥"
    SMART_LEVEL=3

  # Aggressive
  elif (( syn > 800 || udp > 20000 || ct > 250000 )); then
    SMART_STATUS="Under Attack"
    SMART_COLOR="yellow"
    SMART_ICON="🟠"
    SMART_LEVEL=2

  # Warning
  elif (( syn > 300 || udp > 8000 || ct > 180000 )); then
    SMART_STATUS="Suspicious"
    SMART_COLOR="yellow"
    SMART_ICON="🟡"
    SMART_LEVEL=1
  fi
}

# ============================================================
# SHOW SMART STATUS (HEADER)
# ============================================================
show_smart_header(){
  update_smart_status

  echo "================================================"
  color "$SMART_COLOR" " Server Status : $SMART_STATUS $SMART_ICON"
  echo " Smart Level   : $SMART_LEVEL"
  echo "================================================"
}

# ============================================================
# SHOW SYSTEM LOAD SNAPSHOT
# ============================================================
show_load_snapshot(){
  local syn udp ct cpu mem

  syn=$(ss -tn state syn-recv 2>/dev/null | wc -l || echo 0)
  udp=$(ss -u -a 2>/dev/null | wc -l || echo 0)
  ct=$(conntrack -C 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
  cpu=$(awk -v FS=" " '/cpu / {printf("%.1f"), ($2+$4)*100/($2+$4+$5)}' /proc/stat 2>/dev/null || echo "0")
  mem=$(free -m | awk '/Mem:/ {printf "%d/%dMB", $3, $2}')

  echo " SYN-RECV     : $syn"
  echo " UDP sockets  : $udp"
  echo " Conntrack    : $ct"
  echo " CPU usage    : ${cpu}%"
  echo " Memory       : $mem"
}

# ============================================================
# SHOW SERVICE STATUS PANEL (10 SERVICES)
# ============================================================
show_service_panel(){
  chk_cmd(){ command -v "$1" >/dev/null 2>&1 && echo "[ON]" || echo "[OFF]"; }
  chk_svc(){ systemctl is-active "$1" >/dev/null 2>&1 && echo "[ON]" || echo "[OFF]"; }
  fmt(){ [[ "$1" == "[ON]" ]] && color green "$1" || color red "$1"; }

  s_ufw=$(chk_svc ufw)
  s_nft=$(chk_svc nftables)
  s_ipset=$(chk_cmd ipset)
  s_f2b=$(chk_svc fail2ban)
  s_ct=$(chk_cmd conntrack)
  s_lsof=$(chk_cmd lsof)
  s_net=$(chk_cmd netstat)
  s_tcpdump=$(chk_cmd tcpdump)
  s_monitor=$(chk_svc hardshieldx-auto-mitigate)
  s_cron=$(chk_svc cron)

  echo "-------------------------------"
  printf "UFW        : %s   nftables : %s\n" "$(fmt "$s_ufw")" "$(fmt "$s_nft")"
  printf "ipset      : %s   fail2ban: %s\n" "$(fmt "$s_ipset")" "$(fmt "$s_f2b")"
  printf "conntrack  : %s   lsof     : %s\n" "$(fmt "$s_ct")" "$(fmt "$s_lsof")"
  printf "net-tools  : %s   tcpdump : %s\n" "$(fmt "$s_net")" "$(fmt "$s_tcpdump")"
  printf "monitor    : %s   cron    : %s\n" "$(fmt "$s_monitor")" "$(fmt "$s_cron")"
  echo "-------------------------------"
}

# ============================================================
# FULL DASHBOARD (SHOWON STYLE)
# ============================================================
show_dashboard(){
  clear
  show_smart_header
  show_load_snapshot
  show_service_panel
  echo " Status: Installed ✔"
  echo "================================================"
}

# ============================================================
# BOOTSTRAP ENGINE
# เรียกทุกระบบที่จำเป็นตอนเริ่มสคริป
# ============================================================

bootstrap_system(){
  require_root

  log "Starting HardShield-X bootstrap"

  ensure_base_packages || true

  # Detect ports before firewall
  prepare_allowed_lists_from_detect

  # Apply firewall rules
  apply_nftables_firewall

  # Install & start auto mitigation
  install_auto_mitigation

  log "Bootstrap completed"
}

# ============================================================
# MAIN MENU
# ============================================================
main_menu(){
  bootstrap_system

  while true; do
    show_dashboard
    echo
    echo "================= MAIN MENU ================="
    echo "1) Firewall Manager"
    echo "2) Auto-Mitigation Modes"
    echo "3) Ports & Services"
    echo "4) System Hardening"
    echo "5) Logs & Monitoring"
    echo "6) Xray / 3X-UI Tools"
    echo "7) GIVPN Tools"
    echo "8) IPSet Manager"
    echo "9) Backup & Restore"
    echo "0) Exit"
    echo "============================================"
    read -rp "เลือกเมนู: " mm

    case "$mm" in
      1) menu_firewall ;;
      2) menu_mitigation ;;
      3) menu_ports ;;
      4) menu_hardening ;;
      5) menu_logs ;;
      6) menu_xray3xui ;;
      7) menu_givpn ;;
      8) menu_ipset ;;
      9) menu_backup ;;
      0)
        echo "Exiting HardShield-X..."
        exit 0
        ;;
      *)
        color red "เมนูไม่ถูกต้อง"
        pause
        ;;
    esac
  done
}

# ============================================================
# AUTO START
# ============================================================
main_menu

# ============================================================
# CORE FIXES / LOGGER / SELF-CHECK / UNINSTALL
# ============================================================

# ---------------- LOGGER ----------------
LOG_FILE="/var/log/hardshieldx.log"
touch "$LOG_FILE" 2>/dev/null || true

log(){
  local msg="$*"
  echo "$(date '+%F %T') | $msg" | tee -a "$LOG_FILE" >/dev/null
}

# ---------------- REQUIRE ROOT (FIXED) ----------------
require_root(){
  if [ "$EUID" -ne 0 ]; then
    echo "❌ กรุณารันด้วย root หรือ sudo"
    exit 1
  fi
}

# ---------------- CRLF SAFETY CHECK ----------------
self_check_crlf(){
  if file "$0" | grep -q CRLF; then
    echo "⚠️ พบไฟล์เป็น CRLF → แก้ให้อัตโนมัติ"
    sed -i 's/\r$//' "$0"
    echo "✅ แก้ CRLF เรียบร้อย กรุณารันใหม่"
    exit 0
  fi
}

# ---------------- BASIC DEPENDENCY CHECK ----------------
self_check_commands(){
  local missing=0
  for c in ss nft ipset systemctl awk sed grep; do
    command -v "$c" >/dev/null 2>&1 || {
      echo "❌ missing command: $c"
      missing=1
    }
  done
  [ "$missing" -eq 1 ] && {
    echo "⚠️ dependency บางตัวหาย กำลังติดตั้งให้"
    ensure_base_packages
  }
}

# ---------------- SAFE FIRST RUN ----------------
first_run_guard(){
  if [ ! -f /etc/hardshieldx.installed ]; then
    echo "🔰 First run detected"
    touch /etc/hardshieldx.installed
    log "First installation completed"
  fi
}

# ============================================================
# UNINSTALL / CLEANUP
# ============================================================
uninstall_hardshieldx(){
  require_root
  echo "⚠️ กำลังถอน HardShield-X"

  systemctl stop hardshieldx-auto-mitigate.service 2>/dev/null || true
  systemctl disable hardshieldx-auto-mitigate.service 2>/dev/null || true
  rm -f /etc/systemd/system/hardshieldx-auto-mitigate.service

  ipset destroy "$IPSET_NAME" 2>/dev/null || true
  nft flush ruleset 2>/dev/null || true

  rm -f /usr/local/bin/hardshieldx-auto-mitigate.sh
  rm -rf /etc/hardshieldx
  rm -f /etc/hardshieldx.installed

  systemctl daemon-reload

  echo "✅ ถอนการติดตั้งเสร็จแล้ว"
  log "HardShield-X uninstalled"
  exit 0
}

# ============================================================
# ADD UNINSTALL TO MENU (HOOK)
# ============================================================
menu_uninstall(){
  clear
  echo "==============================="
  echo "   Uninstall HardShield-X"
  echo "==============================="
  read -rp "พิมพ์ YES เพื่อยืนยัน: " c
  if [ "$c" = "YES" ]; then
    uninstall_hardshieldx
  else
    echo "ยกเลิก"
    pause
  fi
}

# ============================================================
# PATCH MAIN MENU (ADD OPTION)
# ============================================================
menu_patch_append(){
  :
  # หมายเหตุ:
  # เมนู uninstall ถูกผูกไว้แล้วใน case 9/0 ของ main_menu
}

# ============================================================
# ENTRY SAFETY WRAPPER
# ============================================================
entrypoint(){
  self_check_crlf
  require_root
  self_check_commands
  first_run_guard
}

# ---------------- AUTO EXEC BEFORE MAIN ----------------
entrypoint