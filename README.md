# HardShield-X

**HardShield-X** คือสคริปต์ป้องกันเซิร์ฟเวอร์ขั้นสูงแบบ All-in-One สำหรับ Ubuntu 18.04–22.04 ที่รวมระบบ **Firewall + DDoS Protection + Auto‑Mitigation + Monitoring Dashboard** ไว้ในตัวเดียว

ออกแบบมาเพื่อใช้งานร่วมกับ:

* 3X‑UI / Xray / V2Ray
* GIVPN / WebSocket / TLS
* VPS ทั่วไป และ LAN IP (Universal Mode)

---

# 🚀 ฟีเจอร์หลัก

### 🛡 Smart Status Dashboard (Real-time Attack Detection)

* ตรวจจับ SYN Flood, UDP Flood, Conntrack Flood
* แสดงสถานะแบบสี:

  * Safe 🟢
  * Attacked 🔴
  * Medium Attack 🟠
  * Heavy Attack 🔥

---

### 🔥 Auto-Mitigation (3 โหมด)

* Safe Mode (ค่าแนะนำ)
* Aggressive Mode
* Extreme Mode (โหมดโหดสุด)
* บล็อก IP อัตโนมัติด้วย **ipset blacklist**
* มี Safelist ป้องกันไม่ให้บล็อก IP จาก Client VPN

---

### 👁 nft-monitor (Full Kernel Trace)

* เก็บ Log จาก nftables แบบ Real-time
* มี Systemd Service + Auto Restart
* มี Cron เคลียร์ log ทุก 1 นาที (ป้องกันกินพื้นที่)

---

### 🔐 Firewall Manager (UFW + nftables)

* ผสาน UFW + nftables ให้ทำงานร่วมกัน
* ตั้งค่าพอร์ต ALLOWED สำหรับ TCP/UDP
* Apply Template NFT อัตโนมัติ

---

### 🧰 Tools อื่น ๆ

* Port Scanner + Process Killer
* Xray/3X‑UI Auto Detect Ports
* GIVPN Auto Firewall
* IPSet Manager
* Log Viewer
* Backup & Restore ระบบ
* System Hardening (sysctl)

---

# 📦 วิธีติดตั้ง

ดำเนินการบน Ubuntu 18.04–22.04

```bash
sudo apt update -y
sudo apt install -y curl wget git
```

## ติดตั้ง HardShield‑X

```bash
curl -s https://raw.githubusercontent.com/TspKchn/HardShield-X/main/HardShield-X.sh -o HardShield-X.sh
sudo chmod +x HardShield-X.sh
sudo ./HardShield-X.sh
```

---

# 📂 โครงสร้างไฟล์

```
HardShield-X.sh                # สคริปต์หลัก
/etc/HardShieldX/safelist.txt   # รายชื่อ IP ที่ห้ามบล็อก
/usr/local/bin/nft-monitor.sh   # nft monitor service
/usr/local/bin/auto-mitigation.sh
/etc/systemd/system/nft-monitor.service
/etc/systemd/system/auto-mitigation.service
/var/log/attack-detect.log
/var/log/nft-ddos.log
```

---

# 🔧 การใช้งาน

รันสคริปต์แล้วจะเจอเมนูหลัก:

```
1) Firewall Manager
2) Auto-Mitigation Modes
3) Ports & Services
4) System Hardening
5) Logs & Monitoring
6) Xray / 3X-UI
7) GIVPN Tools
8) IPSet Manager
9) Backup & Restore
0) Exit
```

---

# 🔄 อัปเดตสคริปต์ในอนาคต

(สามารถเพิ่ม Auto-Update ให้ได้ ถ้าต้องการ)

---

# 🛠 ต้องการให้ใส่ Badge / Logo / คำอธิบายเพิ่มไหม?

สามารถเพิ่มได้ เช่น

* Shields.io Badges
* HardShield-X โลโก้
* ตัวอย่างภาพ Dashboard
* Versioning System
* Release Notes
* Auto Update Command

แจ้งผมได้เลย! 🚀
