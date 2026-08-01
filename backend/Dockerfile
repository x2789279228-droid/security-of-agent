FROM python:3.12-slim

WORKDIR /app

# 安装 OpenSSH 客户端（用于 SSH 传输层执行远程响应）
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 创建非 root 用户
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
# SSH 密钥暂存目录（entrypoint 会从这里复制到 /tmp/ssh 并修正权限）
RUN mkdir -p /tmp/ssh-keys /tmp/ssh && chmod 777 /tmp/ssh-keys /tmp/ssh
RUN chown -R appuser:appgroup /app

EXPOSE 8000

USER appuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
