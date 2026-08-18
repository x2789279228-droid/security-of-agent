#!/bin/bash
# ── Flink Dashboard Basic Auth 凭证生成脚本 ──
# 生成 config/nginx/flink.htpasswd, 供 frontend(3002) 反代 Flink UI 鉴权。
#
# 用法: bash tools/gen-htpasswd.sh <用户名> <密码>

set -e

HT_USER="${1:?用法: gen-htpasswd.sh <用户名> <密码>}"
HT_PASS="${2:?缺少密码参数}"

OUT_DIR="$(dirname "$0")/../config/nginx"
mkdir -p "$OUT_DIR"

HASH="$(openssl passwd -apr1 "$HT_PASS")"
if [ -z "$HASH" ]; then
  echo "错误: openssl 生成哈希失败 (请确认 openssl 支持 -apr1, 勿用 BusyBox 精简版)" >&2
  exit 1
fi
printf '%s:%s\n' "$HT_USER" "$HASH" > "$OUT_DIR/flink.htpasswd"

echo "✅ 已生成 $OUT_DIR/flink.htpasswd (用户: $HT_USER)"
echo "   该文件含密码哈希, 已被 .gitignore 忽略, 请勿提交。"
