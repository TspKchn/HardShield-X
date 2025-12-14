#!/usr/bin/env bash
# ============================================================
# HardShield-X : Universal Hardening & DDoS Protection Script
# Target : Ubuntu 18.04 - 22.04
# ============================================================

# ===== AUTO FIX CRLF (Windows line ending) =====
if grep -q $'\r' "$0"; then
  echo "[HardShield-X] CRLF detected, auto-fixing..."
  sed -i 's/\r$//' "$0"
  chmod +x "$0"
  exec bash "$0" "$@"
fi
# ===== END CRLF FIX =====

set -euo pipefail
IFS=$'\n\t'

# ============================================================
# CONFIG
# ============================================================
BACKUP_DIR="/root/HardShieldX_backups"
ATTACK_LOG="/var/log/attack-detect.log"
NFT_LOG="/var/log/nft-ddos.log"

IPSET_NAME="blacklist_attacker"
AUTOMIT_BANTIME=600
SYN_PER_IP_THRESHOLD=200
UDP_PER_IP_THRESHOLD=2000
AUTOMIT_POLL_SEC=5

mkdir -p "$BACKUP_DIR"
touch "$ATTACK_LOG" "$NFT_LOG"

# ============================================================
# UTILS
# ============================================================
color(){
  case "$1" in
    red) echo -e "\e[31m$2\e[0m";;
    green) echo -e "\e[32m$2\e[0m";;
    yellow) echo -e "\e[33m$2\e[0m";;
    blue) echo -e "\e[34m$2\e[0m";;
    *) echo "$2";;
  esac
}

pause(){ read -rp "กด Enter เพื่อกลับเมนู..." _; }

require_root(){
  if [ "$EUID" -ne 0 ]; then
    color red "โปรดรันด้วย root (sudo)"
    exit 1
  fi
}

require_cmd(){
  command -v "$1" >/dev/null 2>&1
}

# ============================================================
# INSTALL BASE PACKAGES
# ============================================================
ensure_base_packages(){
  color blue "[INFO] Installing base packages..."
  apt update -y >/dev/null 2>&1 || true
  apt install -y \
    iproute2 ufw nftables ipset fail2ban \
    conntrack net-tools tcpdump lsof cron curl wget \
    >/dev/null 2>&1 || true
}

# ============================================================
# AUTO DETECT PORTS (UNIVERSAL)
# ============================================================
ALLOWED_TCP=()
ALLOWED_UDP=()

auto_detect_ports(){
  if ! require_cmd ss; then
    color yellow "[WARN] ss not found, skip auto-detect ports"
    return 0
  fi

  ALLOWED_TCP=()
  ALLOWED_UDP=()

  mapfile -t ALLOWED_TCP < <(
    ss -tulnp 2>/dev/null \
    | awk '/LISTEN/ {print $5}' \
    | sed 's/.*://g' \
    | grep -E '^[0-9]+$' \
    | sort -n -u
  )

  mapfile -t ALLOWED_UDP < <(
    ss -u -a 2>/dev/null \
    | awk '{print $5}' \
    | sed 's/.*://g' \
    | grep -E '^[0-9]+$' \
    | sort -n -u
  )

  color green "[AUTO] TCP Ports : ${ALLOWED_TCP[*]:-none}"
  color green "[AUTO] UDP Ports : ${ALLOWED_UDP[*]:-none}"
}

prepare_allowed_lists_from_detect(){
  auto_detect_ports || true
  apply_nft || true
}

# ============================================================
# NFTABLES
# ============================================================
NFT_CONF="/etc/nftables.conf"

apply_nft(){
  color blue "[INFO] Applying nftables rules..."

  cat > "$NFT_CONF" <<EOF
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    tcp flags & syn == syn limit rate 100/second accept
EOF

  for p in "${ALLOWED_TCP[@]}"; do
    echo "    tcp dport $p accept" >> "$NFT_CONF"
  done

  for p in "${ALLOWED_UDP[@]}"; do
    echo "    udp dport $p accept" >> "$NFT_CONF"
  done

  cat >> "$NFT_CONF" <<EOF
    ct state new limit rate 50/second accept
    counter log prefix "NFT-DROP: " drop
  }
}
EOF

  systemctl enable --now nftables >/dev/null 2>&1 || true
  nft -f "$NFT_CONF" >/dev/null 2>&1 || true
}

# ============================================================
# IPSET
# ============================================================
ipset_setup(){
  if ! ipset list -n | grep -q "^$IPSET_NAME$"; then
    ipset create "$IPSET_NAME" hash:ip timeout "$AUTOMIT_BANTIME"
  fi
}

# ============================================================
# AUTO MITIGATION (DDOS)
# ============================================================
install_auto_mitigation(){
  cat > /usr/local/bin/auto-mitigation.sh <<EOF
#!/usr/bin/env bash
while true; do
  ss -tn state syn-recv | awk '{print \$5}' | cut -d: -f1 | sort | uniq -c | \
  while read c ip; do
    if [ "\$c" -ge "$SYN_PER_IP_THRESHOLD" ]; then
      ipset add $IPSET_NAME \$ip timeout $AUTOMIT_BANTIME 2>/dev/null
      echo "\$(date) BLOCK SYN \$ip \$c" >> $ATTACK_LOG
    fi
  done
  sleep $AUTOMIT_POLL_SEC
done
EOF

  chmod +x /usr/local/bin/auto-mitigation.sh

  cat > /etc/systemd/system/auto-mitigation.service <<EOF
[Unit]
Description=HardShield-X Auto Mitigation
After=network.target

[Service]
ExecStart=/usr/local/bin/auto-mitigation.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reexec
  systemctl enable --now auto-mitigation
}

# ============================================================
# DASHBOARD
# ============================================================
show_status(){
  syn=$(ss -tn state syn-recv | wc -l || echo 0)
  udp=$(ss -u -a | wc -l || echo 0)
  ct=$(conntrack -C 2>/dev/null || echo 0)

  status="Safe 🟢"
  [ "$syn" -gt 500 ] && status="Attacked 🔴"
  [ "$syn" -gt 1500 ] && status="Heavy Attack 🔥"

  clear
  echo "==============================="
  echo " HardShield-X Status Dashboard "
  echo "==============================="
  echo "Server : $status"
  echo "SYN:$syn | UDP:$udp | CT:$ct"
  echo "==============================="
}

# ============================================================
# MAIN MENU
# ============================================================
main_menu(){
  require_root
  ensure_base_packages
  ipset_setup
  prepare_allowed_lists_from_detect
  install_auto_mitigation

  while true; do
    show_status
    echo "1) Reload Firewall"
    echo "2) Show Ports"
    echo "0) Exit"
    read -rp "เลือก: " m
    case "$m" in
      1) prepare_allowed_lists_from_detect; pause;;
      2) ss -tulnp; pause;;
      0) exit 0;;
    esac
  done
}

# ============================================================
# START
# ============================================================
main_menu