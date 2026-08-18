# 部署与 CI/CD 手册

本文档说明平台的三种运行方式与镜像发布/回滚流程。

## 目录

- [开发环境 (dev)](#开发环境-dev)
- [生产环境 (prod)](#生产环境-prod)
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
- 关闭宿主机调试端口 (PostgreSQL 5433 / Redis 6380 / Kafka 9094 / Schema Registry 8085)。
- 仅保留对外必需端口: 前端 3001/3002, API 8001, Kafka SASL_SSL 9093, Kafka UI 18082。

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
