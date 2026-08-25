# 08 · 部署、运维与调优

> 把开发环境跑通是第一步，这一章讲**生产化**要知道的所有事：
> 端口、TLS、CI/CD、调优、故障排查。

---

## 一、端口暴露矩阵（生产视图）

| 服务 | 端口 | 绑定 | 防护 | 备注 |
|------|------|------|------|------|
| 前端 Web | 3001 | 对外 | Nginx 隐藏版本 + 安全响应头 | |
| Flink Dashboard 反代 | 3002 | 对外 | HTTP Basic Auth | 实际 Flink REST 不暴露 |
| 后端 API | 8001 | 对外 | JWT + 限流 + CORS | |
| Kafka UI | 18082 | 对外 | 登录认证 (LOGIN_FORM) | |
| Kafka SASL_SSL | 9093 | 对外 | TLS + SCRAM-SHA-512 账号 | 外部日志源用 |
| Kafka 本机 | 9094 | 127.0.0.1 | 无认证 | 本机工具用 |
| PostgreSQL | 5433 | 127.0.0.1 | 密码 | |
| Redis | 6380 | 127.0.0.1 | requirepass + protected-mode | |
| Schema Registry | 8085 | 127.0.0.1 | — | |
| Prometheus | 9090 | 对外（建议加认证） | — | |
| Grafana | 3000 | 对外 | 登录 | |
| Flink REST | 8081 | **不映射** | 经 3002 反代 | |
| OTel Collector | 4317/4318 | 容器内 | — | |
| Tempo | 3200/4317 | 127.0.0.1 | — | |

---

## 二、必填环境变量

```env
# LLM
SHARED_MEMORY_LLM_API_KEY=sk-...
SHARED_MEMORY_EMBEDDING_API_KEY=sk-...

# 安全
SHARED_MEMORY_JWT_SECRET=<random-32-bytes-base64>
SHARED_MEMORY_ADMIN_PASSWORD=<strong>

# 数据库
POSTGRES_PASSWORD=<strong>
REDIS_PASSWORD=<strong>
KAFKA_UI_PASSWORD=<strong>

# Kafka 外部证书
KAFKA_PUBLIC_HOST=<your-domain-or-ip>   # 外部日志源访问地址
KAFKA_SSL_PASSWORD=<cert-password>
```

**用 `:?` 强制必填**（`config.py`）— 任何缺失都会启动失败。

---

## 三、首次部署清单

- [ ] `.env` 已设置全部 `:?` 必填项
- [ ] `bash tools/gen-htpasswd.sh admin your-password` 已生成 `config/nginx/flink.htpasswd`
- [ ] `bash tools/gen-kafka-certs.sh` 已生成 Kafka TLS 证书（KAFKA_PUBLIC_HOST 含在 SAN 中）
- [ ] `bash tools/create-kafka-users.sh soc-log-source <强密码>` 已创建外部日志源账号
- [ ] `docker compose up -d --build` 全部 healthy
- [ ] `docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager` 提交成功
- [ ] 外部验证：
  - `redis-cli -h <host> -p 6380 ping` 应连接被拒
  - `curl http://<host>:8081` 应不可达
  - `curl -sI http://localhost:3001/` 应无 Nginx 版本号，且含 X-Frame-Options / CSP 头
  - `curl http://localhost:3002` 未登录应返回 401
- [ ] 注入测试数据看前后端正常

---

## 四、生产部署（叠加 prod 配置）

```bash
# 1. 拉取预构建镜像
IMAGE_TAG=v1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml pull

# 2. 启动
IMAGE_TAG=v1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

**`docker-compose.prod.yml` 关键点**：
- 不再 build 容器，直接 `image: ghcr.io/...`
- 关闭调试端口（如 Flink REST 映射）
- 资源限制（mem / cpus）
- 日志驱动改为 json-file + rotate

---

## 五、外部日志源接入（生产）

1. 生成证书（KAFKA_PUBLIC_HOST 已设）：
   ```bash
   bash tools/gen-kafka-certs.sh
   ```
2. 启动 Kafka 后创建日志源账号：
   ```bash
   bash tools/create-kafka-users.sh soc-log-source <强密码>
   ```
3. 把 `certs/kafka/ca-cert.pem` 和账号分发给日志源机器
4. 模拟器对接示例：
   ```bash
   python log_simulator.py --kafka <host>:9093 --mode chain \
     --sasl-user soc-log-source --sasl-password <password> \
     --ca-cert certs/kafka/ca-cert.pem
   ```

**防火墙白名单（双保险）**：
```powershell
# Windows
netsh advfirewall firewall add rule name="Kafka-SASL-Allow" dir=in action=allow protocol=TCP localport=9093 remoteip=10.0.20.0/24
```
```bash
# Linux
ufw allow from 10.0.20.0/24 to any port 9093 proto tcp
ufw deny 9093
```

---

## 六、CI/CD

`.github/workflows/`：

| 文件 | 触发 | 任务 |
|------|------|------|
| `ci.yml` | PR / push main | 后端 pytest（覆盖率门禁）+ 前端 lint+build + Flink 编译 + Docker 构建校验 |
| `publish.yml` | push main / tag v* | 构建并推送到 GHCR (`ghcr.io/<owner>/soc-{backend,frontend,flink}`) |
| `deploy.yml` | 手动 | staging/production 双环境，production 人工审批；暂无远程服务器前默认禁用 |

**镜像版本规则**：
- main → `:main` + `:sha-<7>`
- `v*` tag → `:<semver>` + `:latest`
- 生产必须显式指定 `IMAGE_TAG`

---

## 七、调优 Checklist

### Flink
- [ ] `flink-conf.yaml` 中 `parallelism.default` 与 Kafka 分区数匹配
- [ ] `state.backend: rocksdb`（大状态）
- [ ] `execution.checkpointing.interval: 60s`
- [ ] `state.checkpoints.num-retained: 3`
- [ ] TaskManager 内存 ≥ 4 GB

### Kafka
- [ ] Topic 分区数 ≥ 3（生产）
- [ ] `retention.ms` 按合规要求设置（默认 7 天）
- [ ] `min.insync.replicas: 2`（防丢消息）
- [ ] 监控 Lag 指标

### Backend
- [ ] 多副本：把限流从内存 dict 改 Redis 滑动窗口
- [ ] 调整 worker 数：`uvicorn --workers 4`
- [ ] 异步 DB 连接池：SQLAlchemy `pool_size=20, max_overflow=10`
- [ ] LLM 调用加超时与重试

### PostgreSQL
- [ ] `shared_buffers` ≥ 2 GB
- [ ] `work_mem` ≥ 64 MB
- [ ] pgvector HNSW 索引已建
- [ ] 监控慢查询

### Qdrant
- [ ] collection 数量隔离（RAG / Agent memory 各自独立）
- [ ] payload 索引按查询字段建
- [ ] 监控内存（向量常驻）

### Redis
- [ ] `maxmemory-policy: allkeys-lru`
- [ ] 持久化按需开启

---

## 八、可观测性

### 指标（Prometheus + Grafana）
- 容器指标：cAdvisor
- Backend 指标：`/api/metrics` (prometheus_client)
- Flink 指标：Flink Metrics Reporter
- Kafka 指标：Kafka Exporter

### 日志
- 容器日志：`docker compose logs -f <service>`
- 应用日志：`backend/logs/`
- 结构化 JSON，关键字段：`trace_id / event_id / actor / action / decision`

### 链路（OTel → Tempo）
- 接入点：`flink-jobs` 和 `backend/observability/pipeline_tracer.py`
- UI：http://localhost:16686 (Jaeger) / http://localhost:3200 (Tempo)

### 看板
Grafana 内置 provisioning：
- `config/grafana/provisioning/datasources/datasources.yaml`
- 建议看板：Flink 指标、Backend 速率、响应时长、CAD 熔断

---

## 九、故障排查

### 1. 启动失败
```bash
# 看具体哪个容器失败
docker compose ps
docker compose logs <service>

# 常见：
# - .env 缺必填项
# - 端口被占
# - 卷权限
```

### 2. 前端调 API 404
- 看后端是否启动
- 看 `VITE_API_BASE_URL` 是否正确（默认 `/api`）
- 看 CORS 白名单是否包含前端域名

### 3. Kafka 消息不流动
```bash
# 看 topic 列表
docker exec soc-kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

# 看 Lag
docker exec soc-kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --all-groups

# Flink 不消费？
docker exec soc-flink-jobmanager /opt/flink/bin/flink list  # 应有 2 个 RUNNING
```

### 4. LLM 审计卡住
- 看 `circuit_breaker` 状态：可能熔断了
- 看 LLM API 是否可达 / 配额
- 看 prompt token 是否超限
- 看 RAG 检索是否超时

### 5. 响应执行失败
- 看 `response_logs` 表
- 看 `asset_whitelist` 是否包含目标
- 看 `command_whitelist` 是否包含命令
- 看 SSH 连接（`/var/log/auth.log` 在目标机器）

### 6. 数据源拒绝
- 看 `data_sources` 表，看 `enabled` 字段
- 看拒绝原因（4 类：JSON 解析 / Schema / 认证 / 重复）
- 用 `python log_simulator.py --apiKey soc-simulator-2024` 验证

### 7. 整体慢
- 看 Backend worker 数（`uvicorn --workers N`）
- 看 LLM 调用耗时（最大瓶颈）
- 看 PostgreSQL 慢查询
- 看 Kafka 消费 lag

---

## 十、升级流程

```bash
# 1. 备份数据
docker exec soc-postgres pg_dump -U postgres soc > backup-$(date +%F).sql

# 2. 拉新版本
git pull
docker compose pull

# 3. 滚动升级（如有蓝绿）
docker compose up -d --no-deps backend
docker compose up -d --no-deps frontend

# 4. 验证
curl http://localhost:8001/health
# 注入测试数据看链路
```

---

## 上一章

> [07 数据模型与消息契约](./07-data-model.md)

---

## 下一章

- 想看推荐学习路径：→ [09 推荐学习路径]
- 卡住了：→ [10 常见问题与陷阱]


---

## 动手点

1. **看自己机器上的端口监听**：
   ```bash
   # Windows
   netstat -an | findstr LISTENING | findstr :3001
   # Linux
   ss -tlnp | grep 3001
   ```

2. **看指标**：
   ```bash
   curl http://localhost:8001/metrics | head -50
   ```

3. **模拟一次升级**：
   - 改 `backend/app.py` 一个无害字符串
   - `docker compose up -d --build backend`
   - 验证不丢数据
