#!/bin/sh
# SSH 密钥权限修复
# Docker 挂载的文件权限可能不正确（Windows Docker 挂载为 0777）
# 将密钥复制到 /tmp/ssh 并设置正确的 Unix 权限

SSH_SRC="/tmp/ssh-keys"
SSH_DST="/tmp/ssh"

if [ -f "$SSH_SRC/id_rsa" ]; then
    mkdir -p "$SSH_DST"
    cp "$SSH_SRC/id_rsa" "$SSH_DST/id_rsa"
    cp "$SSH_SRC/id_rsa.pub" "$SSH_DST/id_rsa.pub" 2>/dev/null
    cp "$SSH_SRC/known_hosts" "$SSH_DST/known_hosts" 2>/dev/null
    chmod 700 "$SSH_DST"
    chmod 600 "$SSH_DST/id_rsa"
    chmod 644 "$SSH_DST/id_rsa.pub" 2>/dev/null
    echo "[entrypoint] SSH key copied to $SSH_DST with correct permissions"
else
    echo "[entrypoint] No SSH key found at $SSH_SRC/id_rsa (stub mode)"
fi

# 启动主服务
exec "$@"
