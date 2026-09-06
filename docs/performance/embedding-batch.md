# Embedding 单条 → 请求内批量(默认100)优化
**日期**: 2026-09-07 | 目标: 现状嵌入为"每次 HTTP 仅 1 条文本", 改为一次 HTTP 处理 64–100 条(请求内数组), 提升批量/回填吞吐。

## 基调(已核实)
- `EmbeddingClient`(`summary_compression.py`) 用 `httpx.AsyncClient` POST `{base}/embeddings`,
  每次 payload `texts:[text]`(或 OpenAI 兼容 `input:[text]`), 即单条 HTTP、无 batch。
- 双协议响应解析已在: MiniMax `vectors` / OpenAI `data[].embedding`; Redis 单 key 缓存, 命中率指标已备。
- MiniMax emb0-01 与 OpenAI 兼容 **原生支持数组**, 故 batch = 把多条合成一次请求体。

## 改动
- `EmbeddingClient` 新增:
  - `_post_embedding(texts, type_)`: 单次 POST(数组合法地选择请求键 `texts`(MiniMax) 或 `input`(OpenAI)；
    响应按序取 vectors / data[].embedding)。
  - `embed_batch(texts, type_)`: 一次 http 整批复用统一 caching(先查每条的 Redis, 命中即取, 仅 miss 子集进单次 HTTP
    → **miss-only**)；失败回退零向量(与 `embed` 同等语义)；emit_trace + hits/misses 指标兼容。
  - `embed_many(texts, type_)`: 自动按 `EMBED_BATCH_SIZE`(默认100/env 可调,支持到你目标 64–100)切块循环 `embed_batch`，
    对任意长度 list 安全。
- 热路径接入(把"逐条并发单发"改为 chunk 批量):
  - `fix_embeddings.py`(缺失/错维 embedding 回填): 由 per-row concurrency `embed` → 每 100 条一次 `embed_many`。
  - 其它 query 型 `.embed`（RAG 检索/单 query 等每条只需 1 向量）不聚合, 保持原样(避免无意义 batching)。
- 新单测 `tests/test_embed_batch.py`:
  1) `embed_batch` N 条一次 POST、顺序/归一对齐;
  2) `embed_many` 230 条按 100/100/30 → 3 次 HTTP;
  3) 缓存命中预置时仅 miss 子集入请求(miss-only)且 hits/misses 计数正确。

## 环境/回退
- `EMBED_BATCH_SIZE`(默认100)；`SHARED_MEMORY_EMBEDDING_BATCH_KEY`=`texts`|`input`(默认按模型自动: embo/minimax→texts).
- 超长/超限只影响 provider 单请求限制,以批次≤100+tier共0; 单条不可用走 retry+零向量, 与原 `embed` 同。

## 验证与已知
- 新增 embed 单测 3 passed; embedding/llm cache 相关文件内 `test_embed_counters_and_trace` 在其并发同批交错时会偶发未处理线程告警导致红, 单独重跑 passed(判定为既有的跨用例资源 flaky, 与本改动无关; 本改动未触碰原 `.embed`/计数器/trace 逻辑).
- 真实远程 HTTP 未在本机撞; 批次已用 fake client 单测锁定"一次 POST 全组/顺序/缓存 miss-only/零向量"契约。

## 待办(可选后续)
- `rag/seeder`/迁移(pgvector→qdrant) 内部逐条 embed 亦可切 embed_many; 因属新近/一次性编排,未列本次必做。
- 如需服务端观测: agent-traces/embedding batch calls 已随 emit_trace 可见。
