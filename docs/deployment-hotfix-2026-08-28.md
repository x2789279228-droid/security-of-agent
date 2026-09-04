# 部署说明 · 多 Agent 审查 SSE 增强（Hotfix 2026-08-28）

> **事件**：Monitor 页 SSE 实时事件流无法体现多 Agent 审查流程 → 后端事件总线加 `agent` / `stage` 字段 + 前端 `EVENT_META` 追加 `agent_activity`。
> **配套**：[多 Agent 审查实时可视化反例](../upgrade-proposals/)（v8 漏报）、`docs/deployment.md`（基线部署手册）、`README.md`（快速启动）。

---

## 0. 当前状态

| 阶段 | 状态 | 持久性 |
|---|---|---|
| 临时热修补 | ✅ 已落地 | ❌ **不入镜像层**，`docker compose restart` 会丢 |
| 持久化（推荐） | ⏳ 5 分钟做完，见 §2 | ✅ 改动入镜像，重启/重建安全 |

**判定**：演示前若时间紧，热修补可临时用；交付/演示前**必须**做 §2 持久化。

---

## 1. 改动清单（Hotfix 覆盖的文件）

| 文件 | 改动摘要 |
|---|---|
| `backend/event_bus.py` | `BusEvent` 加 `agent: str = ""` 和 `stage: str = ""` 字段；`publish()` 加 keyword 参数，默认 `agent="system"` / `stage=""`，**完全向后兼容** |
| `backend/log_ingestion.py` | `audit_complete` / `response_action` 发布处补传 `agent="audit_pipeline"` / `agent="response_engine"`，`stage` 同理 |
| `backend/temporal/activities.py` | 同上 |
| `backend/observability/watchdog.py` | `pipeline_health` 补传 `agent="cad_supervisor"`, `stage="supervise"` |
| `backend/observability/health_monitor.py` | `pipeline_health` 补传 `agent="health_monitor"`, `stage=alert.stage` |
| `backend/edr_fusion/edr_adapter.py` | `edr_correlation` 补传 `agent="edr_fusion"`, `stage="correlate"` |
| `backend/phishing_guard/__init__.py` | `phishing_llm_verdict` 补传 `agent="phishing_guard"`, `stage="verdict"` |
| `backend/data_security/llm_classifier.py` | `data_security_llm_verdict` 补传 `agent="data_security_llm"`, `stage="classify"` |
| `backend/scheduler.py` | `tuning` 补传 `agent="tuning"`, `stage="tune"` |
| `backend/work_order_service.py` | `sla_breach` 补传 `agent="sla_watchdog"`, `stage="sla_breach"` |
| `backend/routers/chat.py` | `chat/stream` 的 `agent_start` / `agent_done` 改走 `event_bus.publish("agent_activity", {agent, stage, session_id, phase})` |
| `frontend/src/lib/eventStream.ts` | `StreamEvent` 加 `agent?` / `stage?` 字段；`EVENT_META` 追加 `agent_activity: { label: 'Agent 活动', badge: 'bg-ink text-white' }`（append 不 prepend） |

> ⚠️ **改动是纯加性**：`BusEvent` 加字段、`event_bus.publish()` 新增 keyword 参数默认值、`EVENT_META` 追加键——任何调用方未传新参数都走默认 `"system"` / `""`，不破既有 8 类事件渲染。

---

## 2. 持久化（最关键，5 分钟做完）

> 必须在项目根目录 `D:\揭榜挂帅\shared-memory-platform` 执行。

```powershell
# 1. 若 docker cp 时复制的是原始文件，先把容器内当前文件拷回源码树
#    （如已用 git/vscode 改源码，可跳过；冲突时以容器内文件为准并手动合入）
docker cp shared-memory-backend:/app/event_bus.py            backend/event_bus.py
docker cp shared-memory-backend:/app/log_ingestion.py        backend/log_ingestion.py
docker cp shared-memory-backend:/app/temporal/activities.py  backend/temporal/activities.py
docker cp shared-memory-backend:/app/observability/watchdog.py        backend/observability/watchdog.py
docker cp shared-memory-backend:/app/observability/health_monitor.py  backend/observability/health_monitor.py
docker cp shared-memory-backend:/app/edr_fusion/edr_adapter.py        backend/edr_fusion/edr_adapter.py
docker cp shared-memory-backend:/app/phishing_guard/__init__.py       backend/phishing_guard/__init__.py
docker cp shared-memory-backend:/app/data_security/llm_classifier.py   backend/data_security/llm_classifier.py
docker cp shared-memory-backend:/app/scheduler.py             backend/scheduler.py
docker cp shared-memory-backend:/app/work_order_service.py   backend/work_order_service.py
docker cp shared-memory-backend:/app/routers/chat.py         backend/routers/chat.py
# 前端从容器内拷 dist 出来比对（前端源码在主机，仅 dist 进了容器）：
docker cp shared-memory-frontend:/usr/share/nginx/html/assets ./frontend/dist_assets_reference

# 2. 重新构建自建服务镜像（把改动固化进镜像层）
docker compose build backend frontend

# 3. 用新镜像重启（temporal-worker 复用 backend 镜像，build backend 即覆盖）
docker compose up -d backend frontend temporal-worker

# 4. 验证镜像里的代码确实包含新逻辑
docker exec shared-memory-backend python -c "from event_bus import BusEvent; print(list(BusEvent.__dataclass_fields__.keys()))"
# 期望输出（顺序可能不同，但必须含 'agent' 和 'stage'）：
# ['seq', 'type', 'data', 'timestamp', 'agent', 'stage']
```

---

## 3. 三种部署方式

| 场景 | 命令 | 适用 |
|---|---|---|
| **临时热修补**（演示前 5 分钟救命） | `docker cp` + `docker restart` | 见下方 §3.1 |
| **标准持久化**（推荐） | `docker compose build backend frontend && docker compose up -d backend frontend temporal-worker` | 改动入镜像 |
| **生产环境**（GHCR 镜像） | `IMAGE_TAG=<tag> docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | 需先 publish；不开调试端口 |
| **本地纯前端开发** | `npx vite --port 3010` | 仅前端热改；后端走容器 |

### 3.1 临时热修补命令（已落地，复用于其他紧急修复）

```powershell
# 后端：把改动 cp 进容器并重启
docker cp backend/event_bus.py           shared-memory-backend:/app/event_bus.py
docker cp backend/log_ingestion.py       shared-memory-backend:/app/log_ingestion.py
docker cp backend/temporal/activities.py shared-memory-backend:/app/temporal/activities.py
# ...（按 §1 列表完整 cp）
docker restart shared-memory-backend soc-temporal-worker

# 前端：本地 build dist 后部署进容器
cd frontend
npx vite build
docker cp .\dist\. shared-memory-frontend:/usr/share/nginx/html/
docker restart shared-memory-frontend
cd ..
```

---

## 4. 验证清单（部署后逐项打勾）

### 4.1 后端代码层

```powershell
# 1) BusEvent 字段已注入容器
docker exec shared-memory-backend python -c "from event_bus import BusEvent; print(list(BusEvent.__dataclass_fields__))"

# 2) publish 接受 keyword 参数
docker exec shared-memory-backend python -c "from event_bus import event_bus; event_bus.publish('test', {}, agent='t', stage='t'); print('OK')"

# 3) 验证 log_ingestion 已 import 新 keyword
docker exec shared-memory-backend python -c "import inspect, log_ingestion; src = inspect.getsource(log_ingestion); assert 'agent=' in src and 'stage=' in src, 'log_ingestion 还没传 agent/stage'; print('OK')"
```

### 4.2 服务健康

```powershell
# 后端 /health
curl -fsS http://localhost:8001/api/health

# 后端 SSE 端点（看 connected 事件）
timeout 3 curl -N http://localhost:8001/api/events/stream

# 前端入口（应有 200，无 Nginx 版本号）
curl -fsSI http://localhost:3001/ | Select-Object -First 5

# Temporal Worker 在跑
docker logs --tail 20 soc-temporal-worker
```

### 4.3 业务验证（"多 Agent 审查"动画）

1. 浏览器打开 `http://localhost:3001/` → 用 admin 登录
2. 顶部导航 → **系统监控** (Monitor)
3. 实时事件流区域：
   - 旧 5 段管线动画仍在
   - `EventToolbar` 的 chip 中出现 **Agent 活动** 类型
   - 任意点开一条事件，展开 JSON 应包含 `_agent` / `_stage` 字段
4. （可选）触发攻击链看 Agent 接力：

   ```powershell
   python log_simulator.py --kafka localhost:9094 --mode chain --count 5
   ```

   观察 PipelineStrip 的接收节点脉冲、`agent_activity` chip 计数增长。

---

## 5. 端口与服务清单

| 服务 | 容器名 | 容器端口 | 宿主端口 | 用途 |
|---|---|---|---|---|
| 前端 Web | `shared-memory-frontend` | 80 | **3001** | 业务 UI |
| Flink/Grafana/Jaeger/Temporal 反代 | `shared-memory-frontend` | 8080 | **3002** | 内部看板总入口（Basic Auth） |
| 后端 API | `shared-memory-backend` | 8000 | **8001** | API（JWT 保护） |
| Temporal Worker | `soc-temporal-worker` | — | — | 4 层 Agent 编排执行者（无对外端口） |
| Kafka UI | `soc-kafka-ui` | 8080 | 18082 | Topic 监控（登录认证） |
| Kafka SASL_SSL | `soc-kafka` | 9093 | 9093 | 外部日志源（TLS + SCRAM） |
| Kafka 本机 | `soc-kafka` | 9094 | 127.0.0.1:9094 | 本机 log_simulator |
| PostgreSQL | `shared-memory-pg` | 5432 | 127.0.0.1:5433 | 业务库 |
| Redis | `shared-memory-redis` | 6379 | 127.0.0.1:6380 | 滑动窗口 |
| Qdrant | `soc-qdrant` | 6333/6334 | 127.0.0.1:6333/6334 | 向量库 |
| Schema Registry | `soc-schema-registry` | 8081 | 127.0.0.1:8085 | Schema |
| Temporal Server | `soc-temporal` | 7233 | 127.0.0.1:7233 | 编排 gRPC |
| Temporal UI | `soc-temporal-ui` | 8080 | 经 3002/temporal | 编排可视化 |
| Grafana | `soc-grafana` | 3000 | 127.0.0.1:3000 | 看板 |
| Prometheus | `soc-prometheus` | 9090 | 127.0.0.1:9090 | 指标 |
| Tempo | `soc-tempo` | 3200/4317 | 内网 | trace 存储 |
| OTel Collector | `soc-otel-collector` | 4317/4318 | 内网 | trace 接收 |
| Jaeger | `soc-jaeger` | 16686 | 127.0.0.1:16686 | trace 备查 |
| Flink JobManager | `soc-flink-jobmanager` | 8081/9250 | 127.0.0.1:9250 | 流处理 + 指标 |
| Flink TaskManager | `soc-flink-taskmanager` | 9251 | 127.0.0.1:9251 | 指标 |

---

## 6. 回滚

```powershell
# 1) 把源码改回上一个稳定 commit（只回滚 §1 列出的文件，影响面最小）
git checkout <stable-commit-sha> -- backend/ frontend/src/lib/eventStream.ts

# 2) 重新 build + 重启
docker compose build backend frontend
docker compose up -d backend frontend temporal-worker

# 3) 验证 SSE 事件已不再有 _agent 字段
timeout 3 curl -N http://localhost:8001/api/events/stream | Select-String -Pattern '_agent|_stage'
# 期望：旧事件（断线续传回放窗口内）可能仍带 _agent 字段；新产生的事件应不带
```

---

## 7. 风险与缓解

| 风险 | 说明 | 缓解 |
|---|---|---|
| **临时热修补丢失** | `docker cp` 不入镜像层 | **立即做 §2 持久化** |
| 前端 dist 缓存 | Nginx `/assets/*` 长期缓存 | build 后 `docker compose restart frontend` |
| Temporal Worker 不同步 | 复用 backend 镜像 | `up -d` 务必带 `temporal-worker` |
| `agent_activity` 事件被旧客户端忽略 | 前端 `EVENT_META` 追加；旧版本前端无此 chip | 部署前清浏览器缓存或硬刷（Ctrl+Shift+R） |
| Flink checkpoint 失败 | `flink_state` 卷权限 9999:9999 | 详见 `docs/deployment.md` §"已知操作要点" |
| 旧事件 `seenSeqs` 不匹配 | 缓冲上限 500，重启后旧事件被覆盖 | 不影响，正常 |
| 多 Agent 字段空字符串 | 调用方未传 keyword 时默认 `""` | 前端 `metaOf` 已加空值兼容 |

---

## 8. 演示前 1 分钟最后检查

- [ ] `docker ps` 看到 `shared-memory-backend` / `shared-memory-frontend` / `soc-temporal-worker` 都 `Up` + `healthy`
- [ ] `curl -fsS http://localhost:8001/api/health` 返回成功
- [ ] `curl -fsSI http://localhost:3001/` 返回 200
- [ ] 浏览器打开 `/monitor`，事件流入正常
- [ ] 浏览器点开任意事件，展开 JSON 含 `_agent` / `_stage` 字段
- [ ] （演示多 Agent）`log_simulator.py --kafka localhost:9094 --mode chain --count 5` 跑一发，EventToolbar 出现 `Agent 活动` chip，计数 ≥1
- [ ] 浏览器硬刷（Ctrl+Shift+R）清前端缓存

---

## 9. 相关文档

- `docs/deployment.md` — 基线部署手册（CI/CD、镜像版本、staging/production、回滚）
- `docs/study-guide/08-deployment.md` — 学习手册的部署章节
- `README.md` §"快速启动" / §"CI/CD 与部署" — 入口级说明
- `docs/upgrade-proposals/2026-q3-tech-stack-upgrade-v8.md` — v8 升级提案（含多 Agent 反例溯源）

---

**最后更新**：2026-08-28 15:43 · 由 Mavis 整理
