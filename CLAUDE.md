# security-of-agent — 项目约定

共享记忆安全审计 Agent 平台（Kafka + Flink + FastAPI + React）。

## 技术栈

- 消息总线：Apache Kafka 3.7 (KRaft)
- 流处理：Apache Flink 1.18（CEP + DataStream）
- 后端：Python FastAPI + SQLAlchemy(async) + pgvector + Redis + aiokafka
- 向量库：PostgreSQL 16 + pgvector（embedding 1024 维）
- LLM：OpenAI 兼容 API（SiliconFlow，GLM-Z1-9B-0414）
- 前端：React 19 + TypeScript + Tailwind CSS 4 + Framer Motion

## 目录结构（约定）

```
backend/
  rag/             # RAG 知识库：导入器/检索/上下文注入/证据验证/种子
  agents/          # Audit-LLM 四层流水线 (Decomposer→ToolBuilder→Executor→Reviewer)
  mcp_guard/       # 工具调用 4 层控制
  security_guard/  # 调用安全守卫
  response_engine/ # 响应策略 + 安全执行
  trusted_action_gateway/  # A0-A4 自治等级 / 幂等 / 影响控制
  phishing_guard/  # 钓鱼检测
  observability/   # 监控/追踪/看门狗
frontend/src/
  pages/           # 路由页面（/logs /security-audit /response /operations /rag ...）
  components/      # 页面组件（按模块分子目录）
  lib/api.ts       # 所有后端 API 封装
```

## 知识库类型（source 字段）

`mitre-attack` / `capec` / `cve` / `kev` / `vulnerability` / `policy` / `playbook` / `internal`
定义见 `backend/rag/kb_types.py`。结构化字段存 `metadata` JSONB 列。
**约定**：同一 cve_id 全库唯一（应用层去重），新增导入器必须先查重再插入。

## 关键纪律

- 改完必须验证：后端 `cd backend && python -m pytest rag/tests/ -v` + `python -c "import app"`；前端 `cd frontend && npx tsc --noEmit` 或构建
- DB 不可用时后端运行在 DEGRADED 模式（列表返回 []，统计返回 0）——这是设计行为，不是 bug
- 密钥/token 不进代码、不进 commit（放 .env，`SHARED_MEMORY_` 前缀）
- PostgreSQL 未运行时，离线单测复用 `backend/conftest.py` 的 mock `models` 模式
- 大改动先进 Plan Mode 出方案，确认后再动手

## 红线（先问主人）

删除文件/目录/git 历史；修改 .env/密钥/CI/CD；数据库 schema 迁移；git push/rebase/reset --hard；装全局依赖；公开发布。
