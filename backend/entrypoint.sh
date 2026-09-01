#!/bin/sh
# 强制 UTF-8 locale (python:3.12-slim 默认 POSIX/ASCII, 含中文的 .py 报 SyntaxError)
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

# SSH 密钥权限修复
# Docker 挂载的文件权限可能不正确（Windows Docker 挂载为 0777）
# 将密钥复制到 /tmp/ssh 并设置正确的 Unix 权限
#
# v4 修复(2026-09-01):Docker 9p bind mount 在容器启动时存在 race condition
# 9p mount 就绪需要几秒,entrypoint 第一次跑 [ -f ] 经常返回 false
# 这里加 retry: 每秒检查一次, 最多 30 秒,确保 mount 就绪后再 cp

SSH_SRC="/tmp/ssh-keys"
SSH_DST="/tmp/ssh"

# 等待 9p mount 就绪
_mount_ready=0
for _i in 1 2 3 4 5 6 7 8 9 10 15 20 30; do
    if [ -f "$SSH_SRC/id_rsa" ]; then
        _mount_ready=1
        break
    fi
    sleep 1
done

if [ "$_mount_ready" = "1" ]; then
    mkdir -p "$SSH_DST" /root/.ssh
    cp "$SSH_SRC/id_rsa" "$SSH_DST/id_rsa"
    cp "$SSH_SRC/id_rsa.pub" "$SSH_DST/id_rsa.pub" 2>/dev/null
    cp "$SSH_SRC/known_hosts" "$SSH_DST/known_hosts" 2>/dev/null
    chmod 700 "$SSH_DST" /root/.ssh
    chmod 600 "$SSH_DST/id_rsa"
    chmod 644 "$SSH_DST/id_rsa.pub" 2>/dev/null
    # 兼容仍指向 /root/.ssh/id_rsa 的旧配置
    cp "$SSH_DST/id_rsa" /root/.ssh/id_rsa
    chmod 600 /root/.ssh/id_rsa
    echo "[entrypoint] SSH key copied to $SSH_DST and /root/.ssh (after ${_i}s)"
else
    echo "[entrypoint] No SSH key found at $SSH_SRC/id_rsa after 30s retries (stub mode)"
fi

# 启动主服务
exec "$@"
