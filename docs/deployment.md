# 部署与 CI/CD 手册

本文档说明平台的三种运行方式与镜像发布/回滚流程。

## 目录

- [开发环境 (dev)](#开发环境-dev)
- [生产环境 (prod)](#生产环境-prod)
- [流处理架构 (Flink 唯一事实源)](#流处理架构-flink-唯一事实源)
- [CI/CD 流水线](#cicd-流水线)
- [镜像版本策略](#镜像版本策略)
- [回滚](#回滚)
- [部署检查清单](#部署检查清单)

## 运行方式总览

| 环境 | 命令 | 镜像来源 | 说明 |
|------|------|----------|------|
| dev | `docker compose up -d --build` | 本地源码构建 | 含宿主机调试端口 |
| staging | `IMAGE_TAG=main docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | GHCR `:main` | 无调试端口 |
| production | `IMAGE_TAG=<semver> docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | GHCR `:<semver>` | 生产环境, 需人工审批 |

## 开发环境 (dev)

```bash
cp .env.example .env   # 填入真实口令/密钥
docker compose up -d --build
```

- 基础设施 (PostgreSQL/Redis/Kafka/Kafka UI/Schema Registry) 与 4 个自建服务全部源码构建。
- 可选开发兜底 (`docker-compose.dev.yml`): 响应引擎 stub 传输 + 执行层 dry_run。

## 生产环境 (prod)

前置:

1. 镜像已由 Publish 工作流发布到 GHCR (见下节)。
2. 目标机已放置 `.env` (含全部口令/密钥) 与 compose 文件。
3. 目标机已登录 GHCR: `docker login ghcr.io`。

部署:

```bash
IMAGE_TAG=1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
IMAGE_TAG=1.2.3 docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

生产覆盖内容:

- 自建服务强制使用 GHCR 预构建镜像 (`${IMAGE_TAG}` 必填)。
- 后端强制 `SHARED_MEMORY_KAFKA_ENABLED=true` (关闭 HTTP 直连双路径)。
- 关闭宿主机调试端口 (PostgreSQL 5433 / Redis 6380 / Kafka 9094 / Schema Registry 8085)。
- 仅保留对外必需端口: 前端 3001/3002, API 8001, Kafka SASL_SSL 9093, Kafka UI 18082。

## 流处理架构 (Flink 唯一事实源)

```
日志源 ──Kafka security-logs-raw──▶ [Flink·Java] LogValidationJob  校验/标准化/API认证/去重
                                       │  security-logs-validated / -rejected
                                       ▼
                                   [Flink·Java] AnomalyDetectionJob  异常评分 + CEP 攻击链
                                       │  enriched / alerts / audit-queue / cep-partial
                                       ▼
                              [Python·薄消费者] kafka_consumer
                                       存储(PG) + 记忆树 + Audit-LLM + 响应引擎
```

**原则**: Flink 是唯一流处理事实源 (校验/去重/评分/CEP/聚合/指纹)。Python 后端是薄消费者,
不再重复实现任何流式逻辑。历史重复实现已移除:

| 能力 | 归属 | 说明 |
|------|------|------|
| 校验/标准化 | Flink LogValidationJob | Python 侧仅消费已校验结果 |
| 去重 | Flink (60s keyed state) | Python Redis 24h 去重已移除 |
| 异常评分 | Flink (Welford 动态基线) | Python 不再重算, 直接消费评分 |
| 幂等兜底 | PostgreSQL `security_events.event_id` 唯一索引 | 跨重放/双路径扇出只落库一次 |
| Schema 契约 | `backend/schemas/*.json` ↔ `flink-jobs/schemas/*.avsc` | 消费侧校验, 不合规走 DLQ |

**生产级可靠性配置** (Flink, 见 `docker-compose.yml`):

- RocksDB 状态后端 + 增量 checkpoint, 持久化到命名卷 `flink_state` (容器重建不丢)。
- `EXACTLY_ONCE` + KafkaSink 事务 (重启/重放不重不漏)。
- 失败自动重启 (fixed-delay 3 次 × 10s)。
- 并行度由 `parallelism.default` 统一配置 (不再在代码硬编码)。
- 每个作业暴露 Prometheus 指标 (端口 9250/9251)。

**状态与故障可见性**:

- `GET /api/kafka/status` — 消费者统计 + 消费 lag + Flink 作业状态 (单一状态视图)。
- `GET /api/pipeline/status` — 全管道拓扑状态: Flink→Kafka→Python 每一环。
- `GET /api/kafka/rejections` — Flink 拒绝原因聚合 (数据质量)。
- `GET /metrics` — Python 侧 Prometheus 出口; Flink 侧 9250/9251。
- `trace_id` 全链路: Flink 将 traceId 写入 Kafka header, 贯穿 PG 存储/LLM 审计/响应。
- DLQ (`security-logs-dlq`, 保留 30 天) — 处理失败消息可见可回溯。

**故障恢复演练**:

```bash
# 1. Flink 重启恢复 (checkpoint 兜底, 不重不漏)
docker compose restart flink-jobmanager flink-taskmanager
docker compose exec flink-jobmanager /opt/flink/submit-jobs.sh   # 重新提交作业

# 2. 后端重启 (PG 幂等兜底, 重放不重复落库)
docker compose restart backend

# 3. 查 DLQ / 消费 lag / Flink 作业状态
curl -s localhost:8001/api/pipeline/status
```

## CI/CD 流水线

| 工作流 | 触发 | 作用 |
|--------|------|------|
| `ci.yml` | PR + push main | 后端 pytest(覆盖率门禁) / 前端 lint+build / Flink 编译 / Docker 构建校验 |
| `publish.yml` | push main + `v*` 标签 | 构建并推送 GHCR 镜像 |
| `deploy.yml` | 手动触发 (默认禁用) | SSH 远程部署到 staging/production |

CI 徽章: `[![CI](https://github.com/<owner>/<repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<owner>/<repo>/actions/workflows/ci.yml)`

## 镜像版本策略

镜像命名: `ghcr.io/<owner>/soc-{backend,frontend,flink}`

| 触发 | 标签 |
|------|------|
| push main | `:main`, `:sha-<7位commit>` |
| 打标签 `v1.2.3` | `:1.2.3`, `:latest`, `:sha-<7位commit>` |

规则:

- 日常部署用 `:main` (可回滚到任一 `:sha-*`)。
- 正式发版打 `v*` 标签发布语义版本。
- 基础设施镜像已锁版本 (见 `docker-compose.yml`), 不跟随 `:latest` 漂移。
- 已知问题: `capev2/cape` 镜像在 Docker Hub 不存在 (API 404), 启用 sandbox profile 前需替换为真实镜像。

## 回滚

```bash
# 回滚到某次提交对应的镜像
IMAGE_TAG=sha-abc1234 docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
IMAGE_TAG=sha-abc1234 docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

数据库迁移说明: 本项目无独立迁移工具, 表结构由 `init_db()`/`init.sql` 管理, 回滚镜像不改变数据; 若表结构已前移, 回滚后新字段写入可能报错, 需人工评估。

## 部署检查清单

- [ ] `.env` 全部 `:?` 必填项已配置 (POSTGRES/REDIS/KAFKA_UI/JWT/ADMIN/KAFKA_PUBLIC_HOST/KAFKA_SSL_PASSWORD)
- [ ] `tools/gen-htpasswd.sh` 已生成 `config/nginx/flink.htpasswd`
- [ ] GHCR 镜像已发布 (CI Publish 工作流绿色)
- [ ] `docker compose config -q` 通过
- [ ] 目标机防火墙: 仅 3001/3002/8001/9093/18082 对外
- [ ] `curl -fsS http://localhost:8001/api/health` 返回 ok
