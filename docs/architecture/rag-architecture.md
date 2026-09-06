# RAG 子系统架构剖析

> 工作区：`D:/揭榜挂帅/shared-memory-platform/backend/rag/`
> 周边：`qdrant_store.py` / `vector_store.py` / `grounding_verifier.py` / `llm_enhancer.py`
> 性质：只读探索报告

---

## 1. 模块定位 + 一句话定义

| 组件 | 一句话定义 |
| --- | --- |
| `rag/retriever.py` | 混合检索编排器：rule expand → dense + BM25 → RRF → cross-encoder 三步流水线 |
| `rag/lexical.py` | 词法原语层：SOC 专名提取（CVE/T-ID/哈希/IP）、中英混合切词、稀疏 TF 编码、进程内 RRF 融合 |
| `rag/reranker.py` | Cross-encoder 重排：Infinity HTTP → 特征重排（无 LLM）→ LLM list-rerank 三级降级 |
| `rag/query_transform.py` | 查询改写层：规则扩展（默认）+ LLM rewrite/step-back（可选）+ HyDE（仅 empty_only/always） |
| `rag/chunker.py` | 安全专用分块器：按 `步骤/Step` → `##` markdown → 段落 → 固定窗口 4 级回退 |
| `rag/knowledge_base.py` | KB CRUD + 审批/签名 + content_hash 防篡改；`pending / approved / signed_import / rejected` 四态 |
| `rag/seeder.py` | 启动期 seed + 受管后台 embedding 回填（带 `_backfill_tasks` 引用保活） |
| `rag/mitre_importer.py` | MITRE ATT&CK STIX 拉取器（GitHub raw → 解析 attack-pattern → `kb_manager.add_document`） |
| `rag/capec_importer.py` | CAPEC STIX 拉取器（同上结构，独立 URL） |
| `rag/evidence_verifier.py` | 单/批断言验证：retriever 召回 → prompt 拼接 → LLM JSON 判定 `supported/contradicted/unsupported` |
| `rag/context_builder.py` | 把 `RetrievalResult` 渲染成 LLM 上下文（截断到 `max_tokens`） |
| `rag/import_status.py` | 进程内单例导入进度（`start/update/finish/fail`） |

模块总入口：`rag/__init__.py:21-29`，对外 8 个符号：`kb_manager / security_chunker / retriever / rag_context_builder / evidence_verifier / seed_knowledge_base / import_enterprise_attack / import_capec`。

---

## 2. 顶层架构图（ASCII）

### 2.1 检索主流程（运行时最热路径）

```
┌──────────────┐
│ 调用方        │  SubAuditor / Executor / RedAgent / tool_registry._knowledge_search / routers/rag.py
└──────┬───────┘
       ▼
┌──────────────────────────────────────────────────────────────────┐
│ Retriever.retrieve(session, query, top_k, ...)                    │  rag/retriever.py:40
│  ──[async]── 1) transform_query (LLM 旁路)                       │  query_transform.py:26
│  ──[async]── 2) embedder.embed(dense_text)                       │  summary_compression.py:458
│  ──[async]── 3) _hybrid_search (or _vector_search / _filter)     │  rag/retriever.py:267
│  ──[async]── 4) _drop_unapproved (KB 防投毒)                     │  rag/retriever.py:442
│  ──[async]── 5) rerank_chunks (可选 CE 重排)                     │  rag/reranker.py:202
└──────┬───────────────────────────────────────────────────────────┘
       │
       ├──[主路径 A: Qdrant hybrid]──▶ qdrant_store.query_hybrid     │  qdrant_store.py:346
       │       ├─ native Fusion.RRF (服务端 prefetch 融合)            │
       │       └─ 降级: 双路 query + rrf_fuse (进程内)               │  rag/lexical.py:255
       │
       ├──[主路径 B: 进程内融合]──▶ _vector_search (Qdrant→pgvector)   │  rag/retriever.py:479
       │                         + _lexical_search (ts_rank/overlap) │  rag/retriever.py:357
       │                         + rrf_fuse                          │  rag/lexical.py:255
       │
       ├──[降级 C: 精确词短路]──▶ _exact_term_search (ILIKE on needles)│  rag/retriever.py:217
       │       （必须并入候选, 不能被 dense 短路掉）                  │
       │
       └──[降级 D: 纯过滤]──▶ _filter_search (ILIKE + 标签)          │  rag/retriever.py:617
```

### 2.2 写入主流程（启动期 / 导入期 / 文档新增）

```
                                  ┌─────────────────────────────────┐
                                  │ 入口: 3 条                      │
                                  │  A) app.py:152 seed_kb          │
                                  │  B) routers/rag.py:184 /rag/docs │
                                  │  C) mitre/capec import_*        │
                                  └────────────┬────────────────────┘
                                               ▼
                                 ┌──────────────────────────────┐
                                 │ kb_manager.add_document      │  rag/knowledge_base.py:32
                                 │  → status = signed_import    │
                                 │    (auto_signed || signed src)│
                                 │  → content_hash 防篡改        │  memory_guard.py:56
                                 └────────────┬─────────────────┘
                                              ▼
                                 ┌──────────────────────────────┐
                                 │ security_chunker.chunk_doc    │  rag/chunker.py:39
                                 │  → build_search_lex          │  rag/lexical.py:117
                                 │  → 写入 KnowledgeChunk (emb=NULL)
                                 └────────────┬─────────────────┘
                                              ▼
                  ┌────────────────┬──────────┴───────────┬─────────────────┐
                  ▼                ▼                      ▼                 ▼
            [A] seeder 路径   [B] /rag/docs 路径      [C] importer 路径    [启动后兜底]
            embedding=None     embedder.embed()      embedding=None       scheduler 巡检
            (立即回填)          (同步逐 chunk)         (立即回填)           has_missing_embeddings
                  │                │                      │                 │  scheduler.py:484
                  ▼                ▼                      ▼                 ▼
                  └──────────────┬──┴──────────────────────┘                │
                                 ▼                                          ▼
                       _backfill_runner(scope)                          launch_embedding_backfill
                         (受管 task 引用保活)                              (scheduler.py:490)
                                 │
                                 ▼
                       embedder.embed (按 batch=200)
                                 │
                                 ▼
                       _sync_all_to_qdrant (chunks 路径)  seeder.py:1182
                                 │
                                 ▼
                       qdrant_store.upsert_chunks_batch   qdrant_store.py:194
```

---

## 3. 配置全景（`config.py` 与 RAG 相关的关键开关）

RAG 相关配置集中在 `config.py:33-53`：

| 字段 | 默认 | 作用 |
| --- | --- | --- |
| `embedding_dim` | 768 | 嵌入维度，pgvector + Qdrant 共用 |
| `vector_search_threshold` | 0.75 | 向量相似度阈值（memory 侧） |
| `qdrant_enabled / qdrant_url / qdrant_collection` | True / 空 / `soc_knowledge_chunks` | Qdrant 总开关 |
| `qdrant_memories_collection` | `agent_memories` | agent 记忆专用 collection |
| `qdrant_vector_size` | 0 | 0=回退到 `embedding_dim` |
| `qdrant_timeout` | 5.0 | 同步 client 超时 |
| `rag_hybrid_enabled` | True | 启用 Qdrant hybrid collection（`{qdrant_collection}_v2`） |
| `rag_hybrid_collection` | 空 | hybrid collection 名覆盖 |
| `rag_rrf_k` | 60 | RRF k 常数（`retriever.py:325`、`lexical.py:62`） |
| `rag_prefetch` | 20 | 每路召回数（双路融合后截 top_k） |
| `rag_bm25_backend` | `"builtin"` | `builtin`（稳定哈希 TF）/`fastembed`（Qdrant/bm25） |
| `rag_query_rewrite` | `"rules"` | `off / rules / llm` |
| `rag_hyde` | `"empty_only"` | `off / empty_only / always` |
| `rag_rerank_enabled` | True | 重排总开关 |
| `rag_rerank_url` | 空 | Infinity CE URL；空=走特征重排 |
| `rag_rerank_api_key` | 空 | 本地目标免 Bearer |
| `rag_rerank_model` | `BAAI/bge-reranker-v2-m3` | CE 模型名 |
| `rag_rerank_top_n` | 20 | 重排输入上限 |
| `embedding_cache_ttl` | 3600 | embedding 缓存 TTL |
| `llm_cache_ttl` | 86400 | LLM 响应缓存 TTL（v6 走 Redis） |
| `llm_global_concurrency` | 8 | 全平台 LLM HTTP 并发（含 RAG） |
| `llm_budget_unlimited` | True | 默认不因预算降级 RAG/审计 |
| `self_play_rag_top_k` | 8 | Red Agent 检索 top_k |

**启动期 seed**（`app.py:150-154` + `app.py:158-160`）：先 `seed_knowledge_base(session)`，再并发 `launch_embedding_backfill("chunks")` + `launch_embedding_backfill("memories")`。
**Qdrant collection 就绪**：`app.py:111-122` 调用 `qdrant_store.ensure_collection()` 与 `vector_store._ensure_memories_collection()`（失败仅警告，降级 pgvector）。

**6 个 LLM 增强模块**（与 RAG 无直接依赖）：
`config.py:262-282` 定义 `llm_traffic_enabled` / `llm_phishing_enabled` / `llm_data_security_enabled` / `llm_encrypted_traffic_enabled` / `llm_edr_enabled` / `llm_intel_enabled` / `llm_sandbox_enabled` 7 个开关（题目中"6 个"应为笔误，实际有 7 个），每个独立日预算（`llm_*_budget_jpy_per_day`）。
`llm_enhancer.py`（14KB）通过 `enhance_traffic / enhance_phishing / enhance_data_security / enhance_encrypted_traffic / enhance_edr / enhance_intel / enhance_sandbox` 暴露，**全程不调 retriever**——它们的"知识上下文"由上游 SubAuditor 在调用前用 `knowledge.search` tool 召回，enhancer 自身只读 LLM（`grep "retriever|kb_manager" llm_enhancer.py` 0 命中）。

---

## 4. 数据来源与导入

### 4.1 MITRE ATT&CK
- **拉取源**：`mitre_importer.py:29-32` `ENTERPRISE_ATTACK_URL = https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
- **拉取方式**：`httpx.AsyncClient(timeout=120, follow_redirects=True)` GET → 整包 `resp.json()` (`mitre_importer.py:158-161`)
- **过滤条件**：`obj.type == "attack-pattern" and not revoked and not deprecated`（`mitre_importer.py:170-174`）
- **字段映射**：`TACTIC_MAP` kill_chain_phase → 内部威胁枚举；`SEVERITY_MAP` → severity (`mitre_importer.py:35-67`)
- **存储**：`kb_manager.add_document(source="mitre-attack", ..., metadata={attack_id, tactic, platforms, url})` (`mitre_importer.py:221-235`)
- **分块**：`security_chunker.chunk_document` + `build_search_lex` 写入 `KnowledgeChunk.embedding=None`（`mitre_importer.py:250-264`）
- **幂等**：`search_documents(query=tech_id, limit=1)` 命中则 `skipped`（`mitre_importer.py:214-219`）
- **回填触发**：导入完成后 `launch_embedding_backfill(scope="chunks")` (`mitre_importer.py:281-282`)

### 4.2 CAPEC
- 同上结构，独立 `CAPEC_URL = https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json`（`capec_importer.py:27-30`）
- `CAPEC_THREAT_MAP`（capec_importer.py:33-45）与 `CAPEC_SEVERITY_MAP`（47-53）做 threat_type 转换
- 缺省时 `category="unknown"` → threat_types=`["ANY"]`（`capec_importer.py:196`）

### 4.3 KB 文档（`knowledge_base.py`）
- **四态审批**：`pending`（internal 默认）→ `approved`（第二人审批）/ `signed_import`（签名源自动）→ `rejected`（`knowledge_base.py:48-101`）
- **签名机制**：`memory_guard.kb_source_is_signed(source)` 判定 `mitre-attack / capec / cve / playbook` 等白名单（`memory_guard.py:159-163`），签名源免审批直接入 `signed_import`
- **同源防重复**：导入器用 `search_documents(query=tech_id, limit=1)` 判重
- **content_hash**：`memory_guard.content_hash(text)` 写入 `metadata_.content_hash` 字段（`knowledge_base.py:57-59`）
- **删除联动**：`delete_document` 同步删 `KnowledgeChunk` + `qdrant_store.delete_by_doc_id`（`knowledge_base.py:148-165`）

### 4.4 启动期 seed（`seeder.py`）
- `seed_knowledge_base(session)`（`seeder.py:944`）：检查 `KnowledgeChunk` count>10 → 跳全量，仅补 CVE；否则遍历 `SEED_KNOWLEDGE`（约 30 篇：14 MITRE + 8 Playbook + Windows/Linux/网络/云基线 + EventID/IOC 流量/漏洞分级 + Log4Shell CVE），`embedding=None` 占位（`seeder.py:993`）
- `_ensure_missing_seed_docs`（`seeder.py:1006`）：增量补 CVE 文档

### 4.5 后台 embedding 回填
- **入口**：`launch_embedding_backfill(scope)`（`seeder.py:1074`）
- **关键修复 v6**（注释见 `seeder.py:1059-1063`）：原 `asyncio.create_task` 因 request-scoped session + 任务无引用被 GC 取消而**从未真正跑过**；现改为 `_backfill_tasks` 集合保活 + 自建 `async_session` + scheduler 巡检自愈
- **节流**：`batch=200`/`ZERO_EPS=1e-5`/`_MAX_FAIL_PER_ID=3`（`seeder.py:1067-1071`）
- **零向量检测**：`vector_dims() <> dim OR bool_and(abs(v) <= eps) = true`（SQL 层 `seeder.py:1161-1178`），修复原"用 `embedding == [0.0]` Python 字面量比较长向量永远不为真"的 bug
- **失败退避**：`attempts[id] >= 3` 本运行放弃（`seeder.py:1108`），节流 0.2s（`seeder.py:1129`）
- **Qdrant 双写**：chunks 回填完成后 `_sync_all_to_qdrant` 批量 64 调 `upsert_chunks_batch`（`seeder.py:1182-1216`）
- **scheduler 周期巡检**：`scheduler.py:484-499` `_embedding_backfill_patrol`，间隔同 `EMBED_BACKFILL_INTERVAL`

---

## 5. 文档处理链路

### 5.1 切分策略（`chunker.py`）
- **入口**：`chunk_document(doc_id, title, content, source, threat_types, severity, tags)`（`chunker.py:39`）
- **结构化切分优先级**（`chunker.py:80-95`）：
  1. `re.split(r"(?:步骤|Step|阶段)\s*[：:\d]+", content)`（playbook 步骤）
  2. `re.split(r"\n#{1,3}\s+", content)`（markdown 标题）
  3. `re.split(r"\n\s*\n", content)`（双换行段落）
  4. 回退：固定 600 字符窗口 + 80 overlap（`chunker.py:33-34`）
- **合并策略**：`_merge_sections` 累加至 `chunk_size`（默认 600 字符），按 `chunk_overlap=80` 末尾滑窗（`chunker.py:102-140`）
- **token 估算**（`chunker.py:173-177`）：`中文字数 + 其他字符/2 + 1`（混合中英的粗估）
- **chunk_id**：`f"chk_{doc_id}_{chunk_index}_{uuid4().hex[:6]}"`（`chunker.py:66, 154`），UUID5 派生 Qdrant point id（`qdrant_store.chunk_point_id` `qdrant_store.py:39-41`）

### 5.2 embedding 批量化
- `embedder.embed(text, type_="query"|"db")`（`summary_compression.py:458`）：单条
- `embedder.embed_batch(texts)`（`summary_compression.py:559`）：批
- `embedder.embed_many(texts)`（`summary_compression.py:621`）：批 + 维度裁切 + Redis 缓存
- **回填路径只调 `embedder.embed` 单条**（`seeder.py:1123`），但已被 200 批切片 + 0.2s 节流
- **新增文档路径**（`routers/rag.py:139`）逐 chunk 同步调 `embedder.embed`

### 5.3 写入字段 / Collection / Payload
**Postgres `knowledge_chunks` 主表**（实际字段由 `models.py` 决定）：
- `id, doc_id, chunk_id, content, title, source, threat_types (jsonb), severity, tags (jsonb), token_count, embedding (vector(768)), search_lex, created_at`
- `search_lex` = `build_search_lex(title, content, threat_types)`（`lexical.py:117`），最多 400 词

**Qdrant `soc_knowledge_chunks` collection**（`qdrant_store.py:84-114`）：
- dense vector：`size=embedding_dim (768)`, `Distance.COSINE`
- payload：`chunk_id, doc_id, content[:1500], title, source, severity, threat_types, tags`（冗余存用于 payload filter，`qdrant_store.py:149-153`）

**Qdrant `soc_knowledge_chunks_v2` hybrid collection**（`qdrant_store.py:99-111`）：
- named dense vector + `bm25` SparseVectorParams（`Modifier.IDF` 服务端补权重）
- 幂等 upsert：`_sparse_vector` 客户端只发词频稀疏向量（`qdrant_store.py:32-37`，`lexical.py:215-225`）

**pgvector 双写**：每个 `KnowledgeChunk` 行同时存 `embedding` 列（`retriever.py:538-577` 的 `(embedding <=> :vec)` 利用），但实际检索优先 Qdrant。

---

## 6. 检索主流程详解

完整流程见 §2.1 流程图。关键决策点：

### 6.1 总入口（`retriever.py:40-148`）
1. `transform_query` 拿到 `{original, expanded, lexical_query, keywords, lexical_first, hyde_text, step_back, rewritten}`（`query_transform.py:26`）
2. `dense_text = hyde_text or expanded or rewritten or query`
3. `embedder.embed(dense_text, type_="query")` —— **同步异步边界 #1**（LLM 旁路时 None）
4. 分支：
   - `hybrid and (query or query_embedding)` → `_hybrid_search`（`retriever.py:84-114`）
   - elif `query_embedding` → `_vector_search`（`retriever.py:115-120`）
   - elif 有 query 或过滤条件 → `_filter_search`（`retriever.py:121-125`）
5. `_drop_unapproved` 防 RAG 投毒（`retriever.py:127`，`memory_guard.kb_is_retrievable` 仅通过 `approved / signed_import`）
6. `do_rerank and query and len(chunks) > 2` → `rerank_chunks`（`retriever.py:129-143`）

### 6.2 HyDE empty_only 重试（`retriever.py:97-114`）
当 hybrid 路径返回空 + 之前没生成过 hyde + `not skip_llm` → 再次 `transform_query(rewrite="off", hyde="always", empty_hits=True)`，用 hyde embedding 重跑 `_hybrid_search`。
**注**：根据 `query_transform.py:61` `if want_hyde and not state["lexical_first"]`，CVE/哈希/T-ID 等精确查询**绝不触发 HyDE**（避免 LLM 幻觉污染召回）。

### 6.3 `_hybrid_search` 内部（`retriever.py:267-355`）
**主路径 A（Qdrant hybrid）**：
- `qdrant_store.query_hybrid(dense, si, sv, top_k, prefetch, threat_type, severity, source, min_score=0.0)`（`retriever.py:282-294`）
- 服务端 `Fusion.RRF` 失败时回退双路 query + 进程内 `rrf_fuse`（`qdrant_store.py:398-431`）

**主路径 B（进程内融合）**：
- `_vector_search`（Qdrant→pgvector 兜底，`retriever.py:479-615`）
- `_lexical_search`（Postgres `ts_rank`/词法 overlap，`retriever.py:357-440`）
- `rrf_fuse(k=60)`（`retriever.py:320-326`）

**精确词短路**（`retriever.py:188-215, 301-304, 343-353`）：`_inject_exact_terms` 总是把 CVE/T-ID 命中插到候选最前，**不允许 Qdrant dense 邻居淹没词法结果**。

**降级到 `_filter_search`**：`chunks` 为空时（`retriever.py:348-350`），用 ILIKE + threat_type/severity/source 标签。

### 6.4 `_drop_unapproved`（`retriever.py:442-477`）
- 查 `KnowledgeDoc.approval_status` + `valid_until`（`retriever.py:452-457`）
- `kb_is_retrievable` 仅过 `approved / signed_import`（`memory_guard.py:163`）
- `kb_chunk_is_fresh` 检查有效期（`ops_loop.kb_chunk_is_fresh`）
- **防 RAG 投毒**：未审批/已拒绝的内部文档不进入检索

### 6.5 同步 vs 异步边界

| 操作 | 类型 | 标注 |
| --- | --- | --- |
| `Retriever.retrieve` | 全程 async | `async def retrieve` |
| `transform_query` | async（含 LLM 旁路） | `_llm_rewrite / _llm_hyde` 调 `summary.llm.chat` |
| `embedder.embed` | async（HTTP） | `summary_compression.py:458` |
| `qdrant_store._call` | async + `asyncio.to_thread` | `qdrant_store.py:71-80`（**同步 QdrantClient 包装**，规避异步 client 版本差异） |
| `httpx.AsyncClient` 拉 MITRE/CAPEC | async | `mitre_importer.py:158` |
| `_backfill_runner` | async + 模块级 `_backfill_tasks` 保活 | `seeder.py:1089` |
| `httpx.cross_encoder_rerank` | async + 15s 超时 | `reranker.py:18, 132` |
| LLM list-rerank | async（最后回退） | `reranker.py:219-232` |

### 6.6 性能红线 / 缓存
- `embedding_cache_ttl=3600` / `llm_cache_ttl=86400`（Redis 共享，`config.py:28-30`，`app.py:81-82`）
- `llm_global_concurrency=8` 全平台 LLM 限流（`config.py:148`）
- `rag_prefetch=20` 控制双路召回上限（`retriever.py:289`）
- 重排 `CE_TIMEOUT=15s`（`reranker.py:18`）—— **CPU reranker 20 文档常见 2-8s，0.8s 会 100% 超时**
- `qdrant_timeout=5.0`（`config.py:39`）
- `audit_inflight_max=12` / `audit_workers=12` 与 RAG 检索并发叠加形成实际并发上限

---

## 7. 查询改写（`query_transform.py`）

### 7.1 三层策略
| Mode | 触发 | 实现 |
| --- | --- | --- |
| `rules`（默认） | `rag_query_rewrite=rules` | `lexical.expand_query_text` 纯规则（`query_transform.py:35`） |
| `llm` | `rag_query_rewrite=llm` | 规则 + `_llm_rewrite`（`query_transform.py:42-58`） |
| HyDE `off` | `rag_hyde=off` | 不生成 hyde_text |
| HyDE `empty_only` | 默认 | 仅当 hybrid 返回空才生成（`query_transform.py:60-65`） |
| HyDE `always` | `rag_hyde=always` | 总是生成 |

### 7.2 HyDE 实现
- `_llm_hyde(query)`（`query_transform.py:93-112`）调 `summary.llm.chat`，prompt 取自 `rag/hyde` + `rag/hyde_system`（`prompts.py`），fallback 硬编码 system；输出截 600 字符
- 触发条件 `want_hyde and not state["lexical_first"]` —— CVE/哈希/T-ID 查询**绝不走 HyDE**

### 7.3 LLM 改写
- `_llm_rewrite(query)` 返回 `{rewritten, keywords, step_back}`，失败回退到规则结果（`query_transform.py:43-58`）
- `step_back` 注入 `expanded` 字段（`query_transform.py:50`）
- `_parse_json` 支持 trim 截取 `{...}` 段（`query_transform.py:115-127`）

### 7.4 审计 skip_llm 路径
- `skip_llm=True` 时 `transform_query` **直接返回规则结果**（`query_transform.py:39-40`）—— 避免审计流水线无谓的 LLM 开销

---

## 8. 词法检索（`lexical.py`）

### 8.1 安全专名正则（`lexical.py:18-23`）
- `CVE_RE`: `CVE-YYYY-N+`
- `ATTACK_RE`: `T\d{4}(\.\d{3})?`
- `HASH_RE`: `[a-fA-F0-9]{32,64}`（MD5/SHA1/SHA256）
- `IP_RE`: IPv4
- `ASCII_WORD_RE` / `CJK_RE` 双轨切词

### 8.2 别名表（`lexical.py:26-60`）
- `ATTACK_ALIASES`：T-ID/威胁枚举 → 自然语言（"T1059" → "powershell, 命令执行" 等）
- `CVE_ALIASES`：CVE ↔ 俗称（"CVE-2021-44228" ↔ "log4shell, log4j"）

### 8.3 切词 `tokenize`（`lexical.py:94-114`）
- 专名 → 别名展开（双向）
- T1059.001 同时保留 T1059（父级）
- ASCII 词（>1 字符）+ CJK bigram 双轨
- 防御"误删别名"的去重保序

### 8.4 搜索 lex 构建（`lexical.py:117-132`）
- `build_search_lex` 供 Postgres `search_tsv` / 词法召回用，最多 400 词

### 8.5 精确召回 needles（`lexical.py:135-152`）
- 长度≥3 的 CVE/T-ID/哈希，最多 12 个
- 被 `_exact_term_search`（`retriever.py:217-265`）通过 `ILIKE` 直接命中

### 8.6 稀疏向量编码
- `to_sparse_tf`（`lexical.py:215-224`）：blake2b 哈希 token 到 int index，**纯词频，无 IDF**（IDF 由 Qdrant `Modifier.IDF` 服务端补）
- `to_sparse_fastembed`（`lexical.py:231-246`）：`rag_bm25_backend=fastembed` 时改用 `Qdrant/bm25`；失败置 `_fastembed_failed=True` 单次回退
- `encode_sparse(backend=)`（`lexical.py:249-252`）：调度入口

### 8.7 RRF 融合（`lexical.py:255-284`）
- `rrf_fuse(ranked_lists, k=DEFAULT_RRF_K=60)` —— 经典 RRF
- 返回 `[{id, rrf_score, ranks}]`，去重保序

### 8.8 词法 overlap 兜底（`lexical.py:287-295`）
- `lexical_overlap_rank(query, content)` —— 无 Postgres `ts_rank` 时的简易 Jaccard，sqlite 测试/降级用

---

## 9. 向量检索：Qdrant vs pgvector

### 9.1 Qdrant 写入（`qdrant_store.py`）
- **Collection 1**：`soc_knowledge_chunks` —— 单 dense 向量（`qdrant_store.py:84-98`）
- **Collection 2**：`soc_knowledge_chunks_v2`（hybrid）—— named dense + bm25 sparse（`qdrant_store.py:99-111`）
- **点 ID**：`uuid5(NAMESPACE_DNS, f"soc-knowledge-chunk:{chunk_id}")` 幂等（`qdrant_store.py:39-41`）
- **payload 过滤**：`threat_types / severity / source`（`qdrant_store.py:336-344`）
- **同步 client + `asyncio.to_thread`**（`qdrant_store.py:71-80`）—— 规避 qdrant-client 异步版本差异

### 9.2 Qdrant 检索（`qdrant_store.py:290-466`）
- `search()`：纯 dense + payload filter
- `query_hybrid()`：prefetch dense + bm25 + `Fusion.RRF`（失败时双路 query + 进程内 `rrf_fuse` 兜底，`qdrant_store.py:398-431`）

### 9.3 pgvector 兜底（`retriever.py:537-587`）
- `(embedding <=> CAST(:vec AS vector))` 数据库端排序（`retriever.py:569-579`）
- `vector_dims(embedding) = :vdim_guard` 维度防御
- jsonb 过滤 `threat_types @> CAST(:threat_type AS jsonb)`

### 9.4 agent 记忆向量（`vector_store.py`）
- 独立 `QdrantStore` 风格但写入 `agent_memories` collection（`vector_store.py:69-83`）
- 维度护栏：拒绝与 `embedding_dim` 不一致的写入（`vector_store.py:108-116`）
- 信任过滤：`_apply_trust_filter` + `memory_guard.LLM_MIN_TRUST`（`vector_store.py:200-211`）
- 提示注入防御：`looks_like_injection` → trust≤0.1 + 内容截 500（`vector_store.py:101-105`）

---

## 10. RRF 融合

| 位置 | k 常数 | 来源 | 触发 |
| --- | --- | --- | --- |
| `lexical.rrf_fuse` | 60 | `lexical.py:62 DEFAULT_RRF_K` | 默认 |
| `retriever._hybrid_search` 进程内融合 | 60 | `rag_rrf_k` 配置 | hybrid 模式 Qdrant 不可用 |
| `qdrant_store.query_hybrid` 兜底融合 | 60 | `qdrant_store.py:430` | 服务端 RRF 失败 |
| Qdrant 服务端 `Fusion.RRF` | 内置 | `qdrant_store.py:392` | hybrid 模式首选 |

---

## 11. 重排（`reranker.py`）

### 11.1 三级降级链
1. **HTTP cross-encoder**（`reranker.py:113-199`）
   - URL 候选派生（`reranker_candidate_urls`，`reranker.py:33-50`）：原 URL + `/rerank` + `/v1/rerank`
   - 两种 payload 形态（model+query+documents+top_n / 简化版）
   - 本地目标（`soc-bge-rerank` / `localhost` / `*.internal`）免 Bearer；外部用 `llm_api_key` / `embedding_api_key` 兜底
   - `CE_TIMEOUT=15s`（`reranker.py:18`）
   - 失败原因记录 `last_err`，不静默
2. **特征重排**（`reranker.py:81-110`）
   - 公式 `base*8.0 + overlap*0.7 + title_hit*0.2 + exact*0.5`（`reranker.py:99`）
   - 完全无 LLM，零网络
3. **LLM list-rerank**（`retriever.py:722-...`）
   - 仅在 `skip_llm=False` 时启用（`reranker.py:215-232`）
   - 若特征分已把精确词抬到 top1 → 保留特征分不切换（`reranker.py:223-228`）

### 11.2 关键修复
- `reranker.py:117-118` 注释：禁止回落到 `llm_base_url/v1/rerank` —— MiniMax 等对话网关无 `/rerank` 端点
- `reranker.py:34-50` `rerank_candidate_urls` 防"拼接出 `/rerank/v1/rerank` 双重路径"

---

## 12. 上下文组装 + 证据校验 + 接地校验

### 12.1 上下文组装（`context_builder.py`）
- `RAGContextBuilder.build_context(result, max_tokens=2000)`（`context_builder.py:29-91`）
- 格式：每块 `### 知识条目 (score=X) — title` + 来源/威胁类型/严重度 + `> ID: chunk_id` + content
- 截断到 `max_tokens`（默认 2000，约 4000 字符），加 `[上下文截断]` 标记
- `build_verification_prompt(claim, result)`（`context_builder.py:93-105`）：渲染 `rag/evidence_verify` prompt

### 12.2 证据校验（`evidence_verifier.py`）
- `EvidenceVerifier.verify_claim`（`evidence_verifier.py:56-124`）：
  1. `retriever.retrieve(claim, threat_type, severity, top_k=3, min_score=0.5)`
  2. `rag_context_builder.build_verification_prompt`
  3. LLM 判 `verdict ∈ {supported, contradicted, unsupported}` + `confidence` + `supporting_evidence`
- `verify_batch`（`evidence_verifier.py:126-157`）：**串行** 调 `verify_claim`，计算 `hallucination_risk = unsupported / total`
- **集成点**（`agent_executor.py:404-466`）：审计 SubAuditor 收集 `threat_claims`，按 severity 排序取前 5，按 `threat_type` 独立 session 验证

### 12.3 接地校验（`grounding_verifier.py`，42KB）
- `GroundingVerifier`（`grounding_verifier.py:153`），多 Layer 校验器（**不是 RAG 子系统组件**，但消费 RAG 输出）：
  - `verify_chunk`（`grounding_verifier.py:168`）
  - `_verify_knowledge_consistency`（`grounding_verifier.py:719-765`）：检查 `claim_type` 是否与 `knowledge_chunks[*].threat_types` 匹配（大小写不敏感 + 子串包含）
  - `filter_fresh_chunks`（`grounding_verifier.py:737`）复用 freshness 过滤
- **PR2 双源约束**（`grounding_verifier.py:733-734`）：KB 命中但**无事件证据**时不得 `knowledge_supported=True` —— 单源 RAG 不得单独定罪

### 12.4 三个"校验"的关系与分工

| 组件 | 输入 | 输出 | 集成位置 |
| --- | --- | --- | --- |
| `context_builder` | `RetrievalResult` | prompt 文本 | SubAuditor 注入 / EvidenceVerifier |
| `evidence_verifier` | LLM claim | `verdict / confidence` JSON | `_verify_claims_with_knowledge`（`agent_executor.py:404`） |
| `grounding_verifier` | 整 chunk + claim + 事件 | `GroundingReport`（多 Layer 评分） | 审计 CAD 终评 |

**对内 vs 对外接口**：
- `context_builder` / `evidence_verifier` —— **对内**组件，API 路由不直接暴露
- `retriever` / `kb_manager` —— **对外** API（`routers/rag.py`）
- `grounding_verifier` —— 跨系统消费 RAG 输出，不依赖 RAG 的内部状态

---

## 13. 双向量库架构

| | **Qdrant** | **pgvector** |
| --- | --- | --- |
| **存什么** | RAG knowledge chunks + agent memories | RAG knowledge chunks embedding 列 + Memory embedding 列（兜底） |
| **Collection / 表** | `soc_knowledge_chunks` + `_v2`（hybrid） + `agent_memories` | `knowledge_chunks.embedding` (vector(768)) + `memories.embedding` |
| **维度** | 768 (取 `embedding_dim`) | 768 (pgvector 维度硬编码) |
| **payload / 字段** | chunk_id, doc_id, content, title, threat_types, severity, source, tags | 上述 + search_lex（仅 pg）, token_count, created_at |
| **写入入口** | `qdrant_store.upsert_chunk/batch` + `_sync_all_to_qdrant`（回填） | `KnowledgeChunk.embedding = vec` |
| **读取路径** | `qdrant_store.search / query_hybrid` | `(embedding <=> CAST(:vec AS vector))` + `vector_dims()` 维度护栏 |
| **降级** | 不可用/连接失败 → `None` | 始终可用，是兜底 |
| **Hybrid 检索** | 首选（服务端 `Fusion.RRF`） | 进程内 `rrf_fuse`（`retriever.py:320`） |
| **维度防御** | 创建时 `size=embedding_dim` | SQL 层 `vector_dims(embedding) = :vdim_guard` |
| **删除** | `delete_by_doc_id`（payload filter） | `KnowledgeChunk.doc_id = X` 物理删 |

**Memory 模型**（`vector_store.py`）：`Memory(agent_id, content, embedding, source_type, provenance_id, content_hash, trust, signed, metadata_)`，写时做 `looks_like_injection` 信任降级 + 维度护栏 + 信任过滤。

---

## 14. 性能 / 限流模型

### 14.1 缓存策略
| 缓存 | TTL | 位置 | 共享 |
| --- | --- | --- | --- |
| Embedding 缓存 | 3600s | `embedder.embed_many` 内 Redis | 跨进程 |
| LLM 响应缓存 | 86400s | `summary.llm.set_redis` | 跨重启/容器 |
| 业务缓存（enhancer） | 自定义 | `llm_enhancer._biz_cache_*` | 进程内 |
| Qdrant 客户端 | 长连接 | `qdrant_store._client` + `_client_lock` | 进程内懒加载 |
| 审计 SSE 事件 | n/a | `event_store.start_invalidate_listener` | 跨进程 Redis pub/sub |

### 14.2 异步并发
- **全平台 LLM HTTP 并发**：`llm_global_concurrency=8`（`config.py:148`）
- **P0 预留**：`llm_p0_reserve=2`（`config.py:149`）
- **审计 worker 池**：`audit_workers=12`（`config.py:132`）
- **RAG 检索侧**：无独立并发限制，受 LLM 全局并发节流
- **HyDE empty_only 重试**：单次重试，**无并发展开**

### 14.3 预取
- `rag_prefetch=20`（`retriever.py:65, 289`）：双路每路召回 20 条再融合截 top_k
- 严格意义上无 prefetch 复用（无请求级缓存，因为 query 多变）

### 14.4 背压
- `audit_inflight_max=12`（`config.py:114`）超限 P0/P1 入队 / P2/P3 收口
- `audit_queue_max=2000`（`config.py:133`）
- PQ 拉取间隔 `audit_pq_drain_interval_s=1.0`（`config.py:130`）
- **RAG 检索本身无背压** —— 但通过全平台 `llm_global_concurrency` 间接受限
- embedder 0.2s 节流（`seeder.py:1129`）

---

## 15. 与其它子系统耦合

### 15.1 审计流水线
- **`tool_registry._knowledge_search`**（`tool_registry.py:312-346`）—— **RAG 的对外 tool 接口**，SubAuditor 通过 tool 召回 knowledge
- **`agent_executor._extract_rag_context`**（`agent_executor.py:349-376`）—— 汇总阶段注入 prompt
- **`agent_executor._extract_knowledge_chunks`**（`agent_executor.py:378-402`）—— 给 `GroundingVerifier` Layer 4 消费，过滤无 `threat_types` 的 chunk
- **`agent_executor._verify_claims_with_knowledge`**（`agent_executor.py:404-466`）—— 用 `evidence_verifier` 验证 threat_claims，按 severity 排序取前 5，按 threat_type 独立 session 验证

### 15.2 响应引擎
- 不直接调 RAG，仅消费审计结果

### 15.3 自博弈（self_play）
- **`red_agent._rag_hints_and_specs`**（`self_play/red_agent.py:212-240`）—— Red Agent 用 RAG 召回 ATT&CK 候选，提取 `mitre_id`（`T\d{4}(\.\d{3})?`）生成杀伤链
- **`blue_learner._persist_kb`**（`self_play/blue_learner.py:131-156`）—— Self-Play 漏报反哺，**写入 KB 候选规则**（`source="self-play"`, `auto_signed=False`，需第二人审批才进生产检索）

### 15.4 RAG 写入反哺
- **HTTP 入口**（`routers/rag.py:184-...`）：internal 文档走 `pending` 审批态；签名源只允许 importer 直写（`routers/rag.py:190-198`）
- **审批流**：`kb_manager.approve_document` 第二人审批（`knowledge_base.py:83-101`）

### 15.5 Qdrant vs pgvector 分工
详见 §13。

### 15.6 7 个 LLM 增强器（`llm_enhancer.py`）
- 7 个增强器（traffic / phishing / data_security / encrypted_traffic / edr / intel / sandbox）—— **不直接调 RAG**；上下文由上游 SubAuditor 通过 `knowledge.search` 工具召回后注入
- 每个模块独立日预算 + 独立 TTL 业务缓存

---

## 16. 已知脆弱点（不修，只列）

1. **`_backfill_runner` GC 取消 bug 历史**（`seeder.py:1059-1063`）—— v6 已修，但代码注释明示原 bug 导致"Qdrant/pg 实测 0 真实向量"长期存在
2. **零向量比较 bug 历史**（`seeder.py:1164-1167`）—— `embedding == [0.0]` Python 字面量比较长向量永真，已修
3. **`Lexical.overlap_rank` 简易 Jaccard**（`lexical.py:287-295`）—— 降级路径无 IDF / 长度归一化
4. **CE 重排 15s 超时**（`reranker.py:18`）—— CPU BGE-reranker-v2-m3 20 文档常见 2-8s
5. **HyDE LLM 调用无并发展开**（`retriever.py:99-114`）—— empty_only 重试串行
6. **`_exact_term_search` 长度阈值 `len(s) < 3` 过滤**（`lexical.py:143`）—— 极短精确词丢失
7. **MIL `pending` 文档仅 HTTP 入口可写**（`routers/rag.py:190-198`）—— bypass 通过 importer 直写有审计空白
8. **`content_hash` 用 `memory_guard.content_hash`**（`memory_guard.py:56`）—— 散列算法未在 RAG 模块内明文
9. **MITRE/CAPEC 单包全量加载**（`mitre_importer.py:158-161`）—— enterprise-attack.json 数十 MB，120s 超时但内存峰值高
10. **Qdrant 同步 client + `asyncio.to_thread`**（`qdrant_store.py:71-80`）—— 高并发下线程池争用
11. **`audit_schemas.py` 未被本报告覆盖** —— 任务范围之外的 JSON 抽取器
12. **RAG 检索无独立限流**（`retriever.py` 无 semaphore）—— 受全平台 `llm_global_concurrency=8` 间接限制
13. **`_hybrid_search` 进程内融合时 dense + lexical 串行**（`retriever.py:309-317`）—— 可并行未并行
14. **MitmEnabled 时 TLS 解密代理与 RAG 检索耦合度低** —— 不直接相关

---

## 17. 关键文件引用速查

| 主题 | 关键引用 |
| --- | --- |
| 检索总入口 | `rag/retriever.py:40-148` |
| Hybrid 主路径 | `rag/retriever.py:267-355`、`qdrant_store.py:346-466` |
| 词法召回 | `rag/retriever.py:217-265, 357-440` |
| 词法原语 | `rag/lexical.py:18-23, 94-152, 215-284` |
| 重排三级降级 | `rag/reranker.py:113-199, 202-235` |
| 查询改写 / HyDE | `rag/query_transform.py:26-127` |
| 上下文组装 | `rag/context_builder.py:29-105` |
| 证据校验 | `rag/evidence_verifier.py:56-157` |
| KB CRUD + 审批 | `rag/knowledge_base.py:32-203` |
| 分块 | `rag/chunker.py:39-171` |
| Seed + 回填 | `rag/seeder.py:944-1227` |
| MITRE 导入 | `rag/mitre_importer.py:138-283` |
| CAPEC 导入 | `rag/capec_importer.py:140-277` |
| Qdrant 客户端 | `qdrant_store.py:44-471` |
| Memory 向量 | `vector_store.py:23-302` |
| Embedding 批量化 | `summary_compression.py:458, 559, 621` |
| 启动 seed | `app.py:111-122, 149-162` |
| 路由层 | `routers/rag.py:45-71, 184-...` |
| 工具暴露 | `tool_registry.py:312-346` |
| 审计调用 | `agents/agent_executor.py:349-466` |
| Red Agent 召回 | `self_play/red_agent.py:212-240` |
| Blue Learner 反哺 | `self_play/blue_learner.py:131-156` |
| 周期巡检 | `scheduler.py:484-499` |
| 接地校验 | `grounding_verifier.py:719-765` |
| 签名 + freshness | `memory_guard.py:56, 159-163`、`ops_loop.kb_chunk_is_fresh` |
| 配置 | `config.py:33-53, 148-149, 262-282` |

---

## TL;DR

`backend/rag/` 是一个 12 文件、~120KB 的安全知识库 + 混合检索子系统，核心是 `Retriever.retrieve` 这条三步流水线：规则 query expand → dense (Qdrant → pgvector) + BM25 (Qdrant sparse `Modifier.IDF` / `ts_rank` / 词法 overlap) → RRF(k=60) → 交叉编码器重排 (HTTP Infinity 15s 超时 → 特征重排 → LLM list-rerank)。数据来源分三路：启动期 `seed_knowledge_base` 预置 ~30 篇 + 启动后 `launch_embedding_backfill` 受管异步回填 + `MITRE/CAPEC` STIX 拉取器；所有 KB 文档经 `kb_manager.add_document` 走 `pending → approved/signed_import` 审批态防投毒，`_drop_unapproved` 在检索时再次过滤。双向量库架构：Qdrant 承担 hybrid 检索事实源（`soc_knowledge_chunks` + `_v2`），pgvector 兜底；agent 记忆走独立 `agent_memories` collection，`vector_store` 维度护栏 + 信任过滤。配置上 8 个 `rag_*` 开关 + 3 个查询改写模式（rules/llm/HyDE empty_only/always） + Qdrant 总开关形成可降级矩阵。审计侧通过 `tool_registry._knowledge_search` 暴露为 tool，SubAuditor 召回 → `context_builder` 组装 → `evidence_verifier` 验证断言 → `grounding_verifier` Layer 4 KB 一性校验（PR2 双源约束：单源 RAG 不得单独定罪）；self-play 通过 `red_agent` 用 RAG 召回 ATT&CK 候选，`blue_learner` 把漏报反哺为 KB 候选规则（仍需第二人审批）。
