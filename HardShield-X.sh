#!/usr/bin/env bash
# ============================================================
# HardShield-X
# Universal Hardening & DDoS Protection Panel
# Ubuntu 18.04 - 22.04
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
NFT_LOG="$LOG_DIR/nft.log"

IPSET_NAME="hsx_blacklist"
SAFELIST_FILE="$BASE_DIR/safelist.txt"

AUTOMIT_BANTIME=600
AUTOMIT_POLL_SEC=5

mkdir -p "$BASE_DIR" "$LOG_DIR" "$BACKUP_DIR"
touch "$ATTACK_LOG" "$NFT_LOG" "$SAFELIST_FILE"

# ============================================================
# UTILITIES
# ============================================================
color(){
  case "$1" in
    red)    echo -e "\e[31m$2\e[0m";;
    green)  echo -e "\e[32m$2\e[0m";;
    yellow) echo -e "\e[33m$2\e[0m";;
    blue)   echo -e "\e[34m$2\e[0m";;
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
# DEPENDENCIES
# ============================================================
ensure_base_packages(){
  safe_install iproute2 nftables ipset fail2ban conntrack \
               net-tools tcpdump lsof cron curl wget
  systemctl enable --now nftables >/dev/null 2>&1 || true
  systemctl enable --now cron >/dev/null 2>&1 || true
}

# ============================================================
# PORT AUTO DETECTION (UNIVERSAL)
# ============================================================
ALLOWED_TCP=()
ALLOWED_UDP=()

auto_detect_ports(){
  ALLOWED_TCP=()
  ALLOWED_UDP=()

  command -v ss >/dev/null 2>&1 || return 0

  mapfile -t ALLOWED_TCP < <(
    ss -tulnp 2>/dev/null |
    awk '/LISTEN/ {print $5}' |
    sed 's/.*://' |
    grep -E '^[0-9]+$' |
    sort -n -u
  )

# ============================================================
# NFTABLES FIREWALL
# ============================================================
NFT_CONF="/etc/nftables.conf"

apply_nft(){
  backup_file "$NFT_CONF"

  cat > "$NFT_CONF" <<EOF
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
EOF

  for p in "${ALLOWED_TCP[@]:-}"; do
    echo "    tcp dport $p accept" >> "$NFT_CONF"
  done

  for p in "${ALLOWED_UDP[@]:-}"; do
    echo "    udp dport $p accept" >> "$NFT_CONF"
  done

  cat >> "$NFT_CONF" <<EOF
    ip saddr @$IPSET_NAME drop
    limit rate 50/second accept
    counter log prefix "HSX-DROP: " drop
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF

  nft -f "$NFT_CONF"
}

# ============================================================
# IPSET
# ============================================================
ipset_setup(){
  ipset list -n 2>/dev/null | grep -q "^$IPSET_NAME$" || \
    ipset create "$IPSET_NAME" hash:ip timeout "$AUTOMIT_BANTIME"
}

# ============================================================
# SYSCTL HARDEN
# ============================================================
apply_sysctl(){
  cat > /etc/sysctl.d/99-hardshieldx.conf <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_syn_backlog = 4096
net.netfilter.nf_conntrack_max = 262144
EOF
  sysctl --system >/dev/null 2>&1 || true
}

# ============================================================
# AUTO MITIGATION
# ============================================================
install_auto_mitigation(){
  ipset_setup

  cat > /usr/local/bin/hsx-auto-mitigation.sh <<'EOF'
#!/usr/bin/env bash
while true; do
  ss -tn state syn-recv 2>/dev/null |
  awk '{print $5}' | cut -d: -f1 |
  sort | uniq -c |
  while read -r cnt ip; do
    [ "${cnt:-0}" -gt 200 ] && \
      ipset add hsx_blacklist "$ip" timeout 600 2>/dev/null
  done
  sleep 5
done
EOF

  chmod +x /usr/local/bin/hsx-auto-mitigation.sh
}

# ============================================================
# STATUS DASHBOARD
# ============================================================
show_status(){
  syn=$(ss -tn state syn-recv 2>/dev/null | wc -l || echo 0)
  udp=$(ss -u -a 2>/dev/null | wc -l || echo 0)
  ct=$(conntrack -C 2>/dev/null || echo 0)

  status="Safe 🟢"
  [ "$syn" -gt 500 ] && status="Attacked 🔴"
  [ "$syn" -gt 1200 ] && status="Heavy Attack 🔥"

  echo "================================================"
  echo " HardShield-X v$VERSION"
  echo " Status : $status"
  echo " SYN=$syn UDP=$udp CT=$ct"
  echo "================================================"
}

# ============================================================
# MENUS
# ============================================================
menu_ports(){
  clear
  color blue "== Detected Ports =="
  echo "TCP : ${ALLOWED_TCP[*]:-none}"
  echo "UDP : ${ALLOWED_UDP[*]:-none}"
  pause
}

menu_firewall(){
  clear
  nft list ruleset || true
  pause
}

menu_logs(){
  clear
  tail -n 200 "$ATTACK_LOG" 2>/dev/null || echo "No logs"
  pause
}

menu_sysctl(){
  clear
  sysctl -a | grep -E 'tcp_syncookies|tcp_fin_timeout|nf_conntrack_max'
  pause
}

# ============================================================
# MAIN MENU
# ============================================================
main_menu(){
  require_root
  ensure_base_packages
  prepare_allowed_lists_from_detect
  apply_nft
  apply_sysctl
  install_auto_mitigation

  while true; do
    clear
    show_status
    echo "1) Show detected ports"
    echo "2) Show firewall rules"
    echo "3) View attack logs"
    echo "4) Show sysctl harden"
    echo "0) Exit"
    echo "------------------------------------------------"
    read -rp "เลือกเมนู: " m
    case "$m" in
      1) menu_ports;;
      2) menu_firewall;;
      3) menu_logs;;
      4) menu_sysctl;;
      0) exit 0;;
      *) pause;;
    esac
  done
}

# ============================================================
# START
# ============================================================
main_menu

  mapfile -t ALLOWED_UDP < <(
    ss -u -a 2>/dev/null |
    awk '{print $5}' |
    sed 's/.*://' |
    grep -E '^[0-9]+$' |
    sort -n -u
  )
}

prepare_allowed_lists_from_detect(){
  auto_detect_ports || true
  ALLOWED_TCP=( $(printf "%s\n" "${ALLOWED_TCP[@]:-}" | sort -n -u) )
  ALLOWED_UDP=( $(printf "%s\n" "${ALLOWED_UDP[@]:-}" | sort -n -u) )
}

