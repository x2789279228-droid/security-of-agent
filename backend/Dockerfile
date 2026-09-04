# syntax=docker/dockerfile:1.6
# 启用 BuildKit 高级特性 (--mount=type=cache 必须 buildkit)
# 配合 buildkit cache mount + 清华 pip 源, 第二次 build 依赖项 0 秒命中

FROM python:3.12-slim

WORKDIR /app

# 安装 OpenSSH 客户端（用于 SSH 传输层执行远程响应）
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.lock ./
# BuildKit cache mount + 清华 pip 源
#   --mount=type=cache,target=/root/.cache/pip: 持久化 pip wheel cache,
#     跨 build 复用, 第二次 build 依赖项 0 秒完成
#   注意: 不能加 --no-cache-dir, 否则 pip 不写 cache, cache mount 失效
#   -i https://pypi.tuna.tsinghua.edu.cn/simple: 清华源比 PyPI 直连快 5-10x
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.lock

COPY . .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 创建非 root 用户
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
# SSH 密钥暂存目录（entrypoint 会从这里复制到 /tmp/ssh 并修正权限）
RUN mkdir -p /tmp/ssh-keys /tmp/ssh && chmod 700 /tmp/ssh-keys /tmp/ssh
# L2: 运行时策略目录（compose 可挂 volume；entrypoint 从镜像种子补齐）
RUN mkdir -p /app/response_engine/policies /data/response_policies \
    && chmod -R a+rwX /app/response_engine/policies /data/response_policies
RUN chown -R appuser:appgroup /app /data/response_policies

EXPOSE 8000

USER appuser

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
