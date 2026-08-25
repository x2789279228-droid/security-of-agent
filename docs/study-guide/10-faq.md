# 10 · 常见问题与陷阱

> 这一章收录**最常被问 / 最常踩坑**的问题。
> 找不到答案时，再回头翻 [README] 的章节索引。

---

## 一、启动类

### Q：docker compose up 卡在 `pulling fs layer`
**原因**：镜像源网络问题。
**解决**：配置镜像加速；或 `--pull never` 用本地已有镜像。

### Q：启动报 `port is already allocated`
**原因**：宿主机端口被占。
**解决**：
```bash
# Windows
netstat -ano | findstr :3001
# 找到 PID，杀掉
taskkill /PID <pid> /F
```

### Q：backend 一直重启，看 `JWT_SECRET must be set`
**原因**：`.env` 缺 `SHARED_MEMORY_JWT_SECRET`。
**解决**：`.env` 是 `.env.example` 复制来的，缺必填项。补全后重启。

### Q：Flink 作业提交后 `RUNNING` 但没消费
**原因**：Kafka group offset 已提交过空消费；或 topic 还没数据。
**解决**：
```bash
# 重置 group offset
docker exec soc-kafka /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 \
  --group log-validation-job \
  --reset-offsets --to-earliest --execute
```

### Q：前端构建报 "Module not found"
**原因**：`node_modules` 与 `package.json` 不一致。
**解决**：
```bash
cd frontend
rm -rf node_modules package-lock.json
npm ci
```

---

## 二、数据类

### Q：注入日志但前端看不到
**排查顺序**：
1. Kafka 9094 端口通不通
   ```bash
   docker exec soc-backend nc -zv soc-kafka 9092
   ```
2. topic 有没有数据
   ```bash
   docker exec soc-kafka /opt/kafka/bin/kafka-console-consumer.sh \
     --bootstrap-server localhost:9092 --topic security-events-enriched --max-messages 1
   ```
3. backend 是否消费
   ```bash
   docker logs soc-backend | tail -50
   # 应有 "Stored event #..."
   ```
4. SSE 是否通
   ```bash
   curl -N http://localhost:8001/api/events/stream
   ```
5. 前端是否订阅了对应 type

### Q：日志中心 80% 高危事件卡在"待审计"
**原因**（已修复）：Flink 路由把高严重事件送 alerts 不送 audit-queue。
**解决**：详见 `audit/02-日志中心根因排查报告.md`。
**当前状态**：`_handle_enriched` 已对 score≥0.6 的事件也排队审计。
**仍卡在待审计的事件**：历史数据不会自动补审，需手动 SQL 触发或忽略。

### Q：anomaly_score 列是 0 但 raw_data._anomaly_score 有值
**原因**：Flink 字段写入方式不一致。
**解决**：`init.sql` 有迁移逻辑：
```sql
UPDATE security_events
SET anomaly_score = CAST(raw_data->>'_anomaly_score' AS REAL)
WHERE raw_data ? '_anomaly_score'
  AND COALESCE(anomaly_score, 0) = 0
  AND CAST(raw_data->>'_anomaly_score' AS REAL) IS NOT NULL;
```

### Q：pgvector 检索慢
**排查**：
```sql
-- 1. 确认 HNSW 索引存在
SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'knowledge_chunks';

-- 2. 看实际查询计划
EXPLAIN ANALYZE
SELECT * FROM knowledge_chunks
ORDER BY embedding <=> (SELECT embedding FROM knowledge_chunks LIMIT 1)
LIMIT 10;

-- 3. 调高 ef_search 会更准但更慢
SET hnsw.ef_search = 100;
```

### Q：Qdrant 连接失败
**排查**：
```bash
# 1. Qdrant 容器是否 healthy
docker ps | grep qdrant

# 2. 从 backend 容器内连
docker exec soc-backend curl -s http://soc-qdrant:6333/health

# 3. 看 backend 启动日志有没有 "Qdrant unavailable, fallback to pgvector"
```

---

## 三、LLM 类

### Q：LLM 一直返回空 / 超时
**排查**：
1. `SHARED_MEMORY_LLM_API_KEY` 是否正确
2. LLM API base URL 是否可达
3. 看 backend 日志：`curl failed` / `timeout` / `connection refused`
4. 临时降级：把 `llm_temperature=0` 测稳定性

### Q：Stabilizer 修复失败
**看返回**：
```python
result = stabilizer.stabilize(raw)
print(result.error_type)   # json_error / unknown_tool / param_invalid
print(result.feedback_to_llm)  # 给 LLM 的反馈
```
**常见原因**：
- 工具名 LLM 编的（不在 `ALL_TOOLS`）
- 参数类型根本不对（schema 缺失）

### Q：MCP Guard 总是 deny
**看返回**：
```python
result = guard.call_tool(request)
for check in result['checks']:
    print(check['check'], check['passed'], check['message'])
```
**常见 deny 原因**：
- `registry` 未通过：工具未注册（拼写错）
- `permission` 未通过：当前角色无权限
- `validator` 未通过：参数类型/范围错
- `policy` 未通过：命中 deny 规则

### Q：CAD 算 hallucination_risk 一直 1.0
**原因**：evidence_trail 全部声明都查不到依据。
**排查**：
- LLM 声明的 IP/event_id/资产是否真实存在
- 看 `verifier` 日志：每条 claim 的 verify 结果
- LLM 是否在编造引用

### Q：响应执行卡在 pending
**原因**：
- 等人工审批（看 `human_approval` 工单）
- `ttl_manager` 在等冷却
- `safe_executor` 在等模式降级

---

## 四、Flink 类

### Q：Flink 作业 `FAILED`
**看日志**：
```bash
docker exec soc-flink-taskmanager cat /opt/flink/log/flink-*.log | grep -i error
```

**常见**：
- 序列化问题（JobRestart 时类路径变了）
- 状态恢复失败（改并行度后状态不兼容）
- Kafka 不可达（重启 Kafka 后 Flink 没重连）

### Q：CEP 没匹配上
**排查**：
- 事件 eventType 是否精确匹配（区分大小写）
- `withinMinutes` 是否太短
- keyBy 的 key 是否一致（如 src_ip 格式要相同）

### Q：改了 Flink 代码不生效
**注意**：Flink 容器内代码是构建时打进去的，需要重建：
```bash
docker compose build flink-jobmanager flink-taskmanager
docker compose up -d flink-jobmanager flink-taskmanager
docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager
```

---

## 五、响应执行类

### Q：执行报 "command not in whitelist"
**解决**：在 `command_whitelist.py` 加白名单（注意风险）。

### Q：执行报 "asset not in whitelist"
**解决**：
- 在 `assets` 表加目标
- 或在 `asset_whitelist.py` 临时放行

### Q：回滚失败
**看**：
- `response_logs.rollback_token` 是否还在
- TTL 是否已过期（系统回收了）
- 防火墙规则是否被外部改动

### Q：审批工单一直 pending
**排查**：
- 看 `human_approval` 任务
- 看 SSE 是否推送了 `approval` 事件
- 通知渠道（邮件/IM）是否配置

---

## 六、前端类

### Q：登录后跳 401
**原因**：JWT 过期或后端无感重启。
**解决**：
- 重新登录
- 看 localStorage 里的 token 是否还有效

### Q：SSE 频繁断
**排查**：
- 浏览器 DevTools Network，看 EventStream
- 看 backend 日志的 `Broken pipe`
- 前端重连退避是否生效

### Q：列表加载慢
**排查**：
- 后端 `GET /api/logs/events` 的 `limit` 是否太大
- 是否缺索引
- 前端是否用虚拟滚动

### Q：样式不生效
**排查**：
- Tailwind class 是否在 safelist
- 是否清缓存：`rm -rf node_modules/.vite`

---

## 七、可观测性类

### Q：Tempo 看不到 trace
**排查**：
- OTel Collector 是否在收：`docker logs soc-otel-collector`
- 应用是否启用了 tracing：`tracing_enabled=True` + `tracing_sample_rate>0`
- trace_id 是否在消息头：`security-alerts` 看 Kafka Header

### Q：Prometheus 抓不到 backend metrics
**排查**：
- `metrics_enabled=True`
- `/api/metrics` 端点是否在白名单（不被全局中间件拦截）
- 端口 9090 是否可达

### Q：Grafana 看板没数据
**排查**：
- 数据源配置（`config/grafana/provisioning/datasources/datasources.yaml`）
- 看板 JSON 是否导入
- 时间范围

---

## 八、性能类

### Q：Backend CPU 高
**排查**：
- LLM 调用阻塞（应该用异步）
- 同步 I/O（应该用 aio）
- 循环里有 sleep

### Q：PostgreSQL 锁等待
**排查**：
```sql
SELECT * FROM pg_stat_activity WHERE wait_event IS NOT NULL;
-- 看哪些查询在等锁
```

### Q：Redis 内存爆
**排查**：
```bash
docker exec soc-redis redis-cli info memory
# 看 maxmemory / used_memory
```
**优化**：
- 调 TTL
- 限流改用滑动窗口
- 缓存改 LRU 策略

---

## 九、调试技巧

### 1. 看 trace_id 全链路
```bash
# 在 Kafka 头里查
docker exec soc-kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic security-alerts \
  --property print.headers=true --max-messages 1 2>&1 | grep traceparent
```

### 2. 关掉某些组件测试
```bash
# 只保留核心 3 个
docker compose up -d postgres redis kafka
docker compose up -d backend frontend
# 跳过 Flink、Prometheus、Grafana
```

### 3. 直接调内部函数
```bash
# 在 backend 容器内
docker exec -it soc-backend bash
cd /app
python -c "
from log_ingestion import LogIngestion
li = LogIngestion()
# 单步调试
"
```

### 4. 看 LLM 真实输入
```python
# 在 agent_executor.py 加
import json
print(json.dumps(prompt, ensure_ascii=False, indent=2))
```

### 5. 跑单测
```bash
cd backend
python -m pytest tests/test_prompts_integrity.py -v
```

---

## 十、版本升级陷阱

### Q：从 1.0 升到 1.2，数据库报错 "column does not exist"
**原因**：增量迁移没跑。
**解决**：
- `init.sql` 用 `IF NOT EXISTS`，可重跑
- 或 SQLAlchemy 启动时 `create_all` 自动建新表
- 但**新列**要手动 ALTER 或重跑 init.sql

### Q：升级后 LLM 行为变了
**原因**：prompt 模板改了。
**解决**：用 `git diff` 看 `prompts/`，回滚或调整。

### Q：升级后 Flink 状态恢复失败
**原因**：Flink 状态 schema 变了。
**解决**：
- 临时设 `state.backend.incremental: false`
- 或放弃状态重启（接受短时数据重放）

---

## 十一、贡献代码

### 提 PR 流程
1. 从 main 拉分支：`git checkout -b feature/xxx`
2. 写代码 + 测试
3. 跑 `pytest tests/` 全过
4. 跑 `npm run lint` + `npm run build`
5. 提交 `git commit -m "feat: ..."`
6. 推 PR，CI 自动跑

### 代码规范
- Python: black + isort + ruff
- TypeScript: prettier + oxlint
- Java: spotless
- Commit: conventional commits

### 提 PR 必含
- 测试用例
- 文档更新（如有 API 变化）
- CHANGELOG

---

## 反馈渠道

- 文档错误：直接修改 `docs/study-guide/*.md` 并提 PR
- 代码 bug：提 GitHub Issue
- 安全问题：私下联系维护者
- 答辩问题：参考 [09 学习路径] 的"易被问到"清单


---

## 上一章

> [09 推荐学习路径](./09-learning-path.md)

---

## 收尾

文档到这里结束。

如果读完了所有 10 章，你已经：
- 知道平台做什么（[00]）
- 知道怎么搭起来（[01][08]）
- 知道一条事件怎么走（[02]）
- 知道后端每个模块干什么（[03]）
- 知道 Flink 怎么写（[04]）
- 知道 5 道自审计闸（[05]）
- 知道前端怎么展示（[06]）
- 知道数据怎么存（[07]）
- 知道怎么学（[09]）
- 知道怎么排错（[10]）

下一步：**动手**。从 [09 学习路径] 的"三个'必改实验'"挑一个开始。
