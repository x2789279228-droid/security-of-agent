# 依赖版本清单与升级策略

> 统一登记本平台所依赖的镜像 / Python / Java 组件版本与锁定策略，作为依赖管理与安全审计基线。
> 原则：**镜像锁具体版本（避免浮游 `latest`/major 漂移），Python 依赖用 `requirements.lock` 精确锁定，Java(Maven) 依赖用 `<version>` 显式声明。**

## 1. Docker 镜像（docker-compose.yml 全量）

| 服务 | 镜像 | tag | 说明 |
|---|---|---|---|
| 主数据库 | `pgvector/pgvector` | `pg16`（待锁 patch，见下） | 知识库/记忆向量 |
| 缓存 | `redis` | `7.4.2-alpine` | |
| 向量库 | `qdrant/qdrant` | `v1.15.1` | RAG |
| Kafka broker | `confluentinc/cp-kafka` | `7.6.0` | KRaft 模式 |
| Kafka UI | `provectuslabs/kafka-ui` | `v0.7.2` | |
| Schema Registry | `confluentinc/cp-schema-registry` | `7.6.0` | |
| OTel Collector | `otel/opentelemetry-collector-contrib` | `0.159.0` | 双写 Tempo+Jaeger |
| Tempo | `grafana/tempo` | `2.10.8` | 30 天 retention |
| Jaeger | `jaegertracing/jaeger` | `2.7.0` | all-in-one v2 |
| Temporal 编排 | `temporalio/auto-setup` | `1.27.1` | |
| Temporal UI | `temporalio/ui` | `2.38.1` | |
| Temporal 存储 | `postgres` | `16.4` | 独立库 |
| Prometheus | `prom/prometheus` | `v3.14.0` | /metrics 采集 |
| Grafana | `grafana/grafana` | `12.3.8` | Tempo/Prometheus 看板 |
| Suricata | `jasonish/suricata` | `8.0.6` | NDR |
| MISP | `coolacid/misp-docker` | `core-v2.4.177a` | 威胁情报 |
| CAPE | `capev2/cape` | `latest` | **无官方镜像，演示勿启用**；需自建镜像替换 |
| 自有服务 | `ghcr.io/x2789279228-droid/soc-*` | `${IMAGE_TAG:-dev}` | backend/frontend/flink |

## 2. Python 依赖（backend）

- 入口：`backend/requirements.txt`（人类可读：`>=A,<B` 双界范围）
- **锁定文件：`backend/requirements.lock`**（pip-compile 生成，90 包精确 `==`；CI 与 Docker 用 `-r requirements.lock` 安装）
- 更新流程：改 `requirements.txt` → `python -m piptools compile -o requirements.lock requirements.txt` → CI 验证
- 工具：pip-tools 7.6.1（Python 3.11）

## 3. Java / Maven（flink-jobs）

| 组件 | 版本 | 备注 |
|---|---|---|
| Flink | `1.20.5` | 运行时由 flink 镜像 lib 提供 |
| flink-connector-kafka | `3.3.0-1.20` | provided，由 lib 提供 |
| kafka-clients | `3.4.0` | provided |
| Jackson | `2.18.10` | 修 8 个 CVE |
| **lz4-java** | **`at.yawk.lz4:1.11.1`** | CVE-2026-59949 修复坐标；`org.lz4:lz4-java` 已 abandon 且无修复版，已排除 |
| OpenTelemetry | `1.40.0` | Java agent/API |

> CI `flink-build` job 用 `mvn dependency:tree` 断言 lz4-java 坐标系（防回归）。

## 4. 升级策略速查

- **镜像**：锁具体 minor/patch 版本，升级需更新清单 + `docker compose config` 校验。
- **Python**：先改范围 → pip-compile 重新生成 lock → `pip install --dry-run -r requirements.lock` 校验可解析。
- **Maven**：显式 `<version>`，CI dependency:tree 断言关键 CVE 坐标系。
- **升级前**：对照本清单评估影响面；升级后回归（pytest / docker compose config / flink build）。
