# TEE 推理 + 国密算法 国产化合规增强 — 安全平台升级方案

| 字段 | 值 |
|------|----|
| 文档标题 | TEE 推理 + 国密算法 国产化合规增强 |
| 作者 | mavis |
| 日期 | 2026-09-05 |
| 状态 | Draft（rev 3，FieldCipher 单例就地 configure；L0 软件密钥独立 env） |
| 适用仓库 | `shared-memory-platform` |
| 关联 | 创新矩阵 #10；v5 §4.2 国密路线图（本方案**取代并补全**，v5 未含 TEE）；v6 §4 等保三级 10 项自评；`2026-q3-tool-behavior-signature.md`（MCP 行为签名已落地，本方案不重造） |

> **一句话**: 把 SOC 提示词关进可远程证明的机密虚机，并把仓库里真实在用的 HS256 / Fernet / RSA-TLS / MD5 缓存逐项换成 SM2/SM3/SM4（开发用软件库演示，密评用认证密码模块），而不是在 PPT 里写一句「全栈国密」。

> **定位**: 创新矩阵 #10 评分 实施成本 5 / 学术 3 / 工程 4 / 演示 1 / 复用 2 = ★★，标签是 **合规补漏**，不是 AI 创新主线。本方案按「可合入的 PR」写，不按白皮书写。

---

## 0. TL;DR

| 维度 | 当前（代码事实） | 本方案 | 增量 |
|------|------------------|--------|------|
| LLM 客户端 | **`backend/llm_client.py` 不存在**。`LLMClient` 住在 `backend/summary_compression.py`，`httpx.AsyncClient` POST `{base_url}/chat/completions`，read timeout 90s，无 mTLS、无证明 | 抽出真正的 `backend/llm_client.py`；密评模式 fail-closed 校验 `QuoteEnvelope`；请求体按 §6.1.3 SM 会话封装（须有解密对端 `mock_gateway`） | 对端存在时，提示词不以明文 JSON 出界；**仅开 wrap 而无网关不算交付** |
| LLM 部署 | `config.py` 默认 `llm_model=""`；**compose 默认注入** `mimo-v2.5 @ https://api.xiaomimimo.com/v1`；embedding 默认 `https://maas-api.cn-huabei-1.xf-yun.com/v2` | 信创主路径：海光 CSV（+ DCU/GPU CC 若可得）私有化 Qwen/DeepSeek；TDX+NVIDIA CC 仅非信创/出海备选 | 云厂商不再看见 chat 原文；**L0 仍接受 embedding 出界到讯飞**（T3 残余） |
| JWT | `auth.py` **import 时**绑定 `ALGORITHM = "HS256"` / `SECRET_KEY`，密钥 `SHARED_MEMORY_JWT_SECRET` 明文 env | 去掉模块常量，读 `settings`；PR5 只交 flag + 仍签发 HS256；Q2=SM2 时按 §6.2.2 剖面签发 | 身份鉴别算法可申报商密（密评模式关 HS256） |
| 字段加密 | `field_cipher.py` Fernet；前缀 `ENC:`；**import 时**读 env；key 空 → 未加密 | **L0 = SM4-CBC + HMAC-SM3**（`gmssl==3.2.2`）；双读 `ENC:` / `SM4ENC:`；密评模式强制 SDF；GCM 仅 L1+ | 关掉「写了加密模块但 key 空」；L0 不要求 GCM |
| 审计完整性 | `audit_trail.py` 无链哈希；DB 失败 **fail-open** 进 500 条内存缓冲 | SM3 链式哈希（epoch 顾问锁）+ 周期 SM2 锚；`audit_fail_closed_actions` 名单 | 对应等保「安全审计 / 数据完整性」 |
| Kafka | 容器内 `kafka:9092` **PLAINTEXT**（**全部内部 topic，远多于 v6 所写 7 个**）；外部 9093 SASL_SSL（**RSA-2048** 自签）；Python / Flink **不配 ssl** | L0 只加密 audit/alert 字段（raw 默认关）；L1 **新增** `SSL://kafka:9096` 客户端选择加入，**不改 9092** | 内网明文是事实；禁止 flip 9092 打停 Flink |
| 南北向 HTTPS | nginx `listen 80`/`8080`；compose 另映射 **`8001:8000` 直出 FastAPI** | L1 双栈 TLS1.3 + GMTLS；**密评 overlay 不得发布宿主 8001** | 不假装 Chrome 原生 GMTLS；8001 是现网旁路 |
| 密钥 | JWT / Fernet / admin / Redis / PG 全在 env 明文 | 开发可用 env；`SHARED_MEMORY_CRYPTO_BACKEND=sdf` 时应用只拿 `key_id` | 密评最容易挂的点；PIN 仍是编排秘密（诚实写出） |
| 密码库 | `cryptography` + `PyJWT`，**无 gmssl / Tongsuo** | L0 钉死 `gmssl==3.2.2` 纯 Python（**不能申报密评**）；L1 SDF（GM/T 0018）主、厂商 PKCS#11 可选 | 「演示」和「过密评」切开 |
| TEE | 无 | L2 才上硬件：CSV 主、TDX 备；CPU TEE **不保护** GPU HBM，除非 GPU CC | 不把 TDX 写成政府项目唯一路径 |

**推荐节奏（揭榜挂帅）**: **L0-demo（1–2 人周：抽出客户端 + KAT + 双读字段 + 链哈希 flag 关 + 文档，不能申报密评）→ L0-contract（SM2-JWS 剖面 + SM 会话对端 + QuoteEnvelope fixture，另计人周）→ L1 SDF + Tongsuo → L2 CSV/云 TEE**。没有自有 CSV 机器时，用国内云 CSV/TDX 实例托管 vLLM，应用只做 attestation——加速项，不是跳过国密。

**本方案相对 v5 §4.2**: v5 只画了 SM2 Agent→Tool / SM3 审计链 / SM4 PG+Kafka 的 L0/L1/L2，**没有 TEE**。本文件取代那张草图，并把 MCP 工具调用的「SM2 签名」降为可选项——行为签名已在 `mcp_guard/behavior_signature.py` 落地，密码学签名另算，禁止重复造轮子。

---

## 1. 背景与动机

### 1.1 平台处理的是「重要数据」，LLM 调用今天会出界

本仓库是 AI SOC：Audit-LLM / 7 角色 Agent / `llm_enhancer` / 钓鱼与加密流量分析，都会把 **告警原文、资产 IP、工单、审计结论** 拼进 prompt。

调用链（核过代码，全部经 `summary.llm.chat`，PR1 抽出后自动覆盖）：

```
agents/base.py            summary.llm.chat(messages)
agents/agent_executor.py / agent_reviewer.py / agent_decomposer.py / sub_auditor.py
llm_enhancer.py           summary.llm.chat(...)  另有独立 MD5 `_biz_cache_key`
post_mortem_service.py / observability/watchdog.py
rag/evidence_verifier.py / rag/query_transform.py / rag/retriever.py
self_play/red_agent.py / blue_learner.py / reviewer.py
cad.py                    只检查 llm_api_key 是否为空，不检查传输与证明
```

`LLMClient.chat`（`summary_compression.py`）行为：

1. 用 `hashlib.md5(f"{prompt_text}:{temperature}")` 做缓存键，进程 dict + Redis `llmcache:`。
2. 预算门禁（可关）。
3. `httpx.AsyncClient(timeout=Timeout(connect=10, read=90, write=10, pool=10))` **无 cert、无 mTLS、无自定义 verify**。
4. `POST {base_url}/chat/completions`，`Authorization: Bearer {api_key}`，JSON 正文即 messages。
5. 失败返回 `{"error":..., "fallback": true}` JSON 字符串，调用方经常当模型输出解析。

`config.py` 默认 `llm_api_key = llm_base_url = llm_model = ""`，所以 **未配环境变量时根本不打模型**（`cad.py audit_config` 会报 critical）。但 `docker-compose.yml` 后端服务默认：

- `SHARED_MEMORY_LLM_BASE_URL` → `https://api.xiaomimimo.com/v1`
- `SHARED_MEMORY_LLM_MODEL` → `mimo-v2.5`

因此：**v6「本项目当前未启用任何 LLM」只对 `config.py` 默认值成立；按 compose 拉起来，提示词会经普通 HTTPS 到云端网关。** TLS 只能防路径窃听，防不了提供商侧看见明文，也没有推理环境证明。

这与等保「通信保密性 / 数据保密性」和密评「密码应用方案覆盖重要数据全生命周期」直接冲突。政府 / 关基 / 揭榜挂帅客户不会接受「告警原文在小米/任意 MaaS 内存里算完再回来」。

### 1.2 密码栈是西方默认，而且几处是「模块在、密钥空」

| 点 | 事实 |
|----|------|
| 身份 | `auth.py` HS256 HMAC-SHA256；`user_store.py` bcrypt（口令哈希，本方案不改成 SM3 口令哈希，避免登录大迁移） |
| 字段 | Fernet；compose 把 `SHARED_MEMORY_FIELD_ENCRYPTION_KEY` 默认空串注入 → `FieldCipher._init_cipher` 直接 disable |
| Kafka | 外网 9093 有 SASL_SSL，证书由 `tools/gen-kafka-certs.sh` **`openssl req -newkey rsa:2048`** 自签 365 天；**Python 与 Flink 走 `kafka:9092` PLAINTEXT** |
| 南北向 | nginx `:80`，无 443，无证书 |
| 审计 | `audit_trail` 表无 hash 列；注释写「不可篡改」，实现是普通 INSERT + 失败进 deque |
| 缓存 | LLM / Embedding 缓存键都是 MD5 |
| 依赖 | `cryptography>=42`、`PyJWT>=2.8`；全库 grep `gmssl\|tongsuo\|SM2\|SM3\|SM4\|GMTLS` **无生产代码命中**（只出现在 upgrade-proposals） |

「用了 SM4 某处」过不了等保三级，更过不了密评。密评看的是 **密码应用方案**：算法合规、协议合规、密钥管理、**商密产品认证证书**、应用安全性。env 里的 Fernet key、自实现 SM4、未认证的 `gmssl` 纯 Python，都会在密钥管理和密码产品两项挂。

### 1.3 为什么现在写，而不是继续堆在 v5/v6 清单里

- v5 §4.2 给了三阶段国密，但把 SM2 主要绑在「Agent→Tool 调用签名」，没盘点 JWT/Fernet/MD5/nginx，也没 TEE。
- v6 §4 把缺口写成 10 项必检，其中 #1 JWT SM2、#2 Kafka 传输、#3 field_cipher SM4、#4 审计链式哈希 正是本方案 L0/L1 的文件级目标。
- 创新矩阵明确 #10 不要当 AI 主线单独立项。本方案是 **合规补漏工程**，演示效果差（矩阵演示分 = 1），所以成功标准是对照表 + 单测 + feature flag，不是 Monitor 页动画。

### 1.4 法规口径（先划线，避免把厂商 PPT 当法律）

本方案区分三层，**映射到具体标准族，不发明条款号**：

1. **等保 2.0**：GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》**第三级**。本方案能对上的是安全通信网络 / 安全区域边界 / 安全计算环境里的身份鉴别、通信完整性、通信保密性、数据完整性、数据保密性、剩余信息保护、安全审计、可信验证。
2. **密码法 + 密评**：《中华人民共和国密码法》；商用密码应用安全性评估通常依据 GM/T 0054（基本要求）、GM/T 0115（测评要求）、GM/T 0116（测评过程）。等保三级信息系统在实践中普遍被要求密评，但 **密评通过 ≠ 等保通过**，反之亦然。
3. **信创 / 国产化**：CPU/OS/密码模块采购清单。海光 CSV 是国内 x86 机密计算主路径；Intel TDX 有供应链与政府采购政策风险，**只作为商业/出海备选，不能写成政府项目的唯一 TEE**。

**明确不采用为法规原文的材料**：

- v5「GA/T 2380-2026 33 项一票否决 / 70 分及格 / 三级强制国密」——来源是 v5 引用的行业解读（安恒信息、协会稿等）。**本方案不把它当法规原文**，只承认：数据安全被单独加强考核是真实趋势，具体条款以正式标准文本和当地测评机构作业指导书为准。
- v6 引用的「2026-01-01 新《网络安全法》第 20/39/42 条及罚款数字」——实施前必须核对全国人大常委会公布文本。本方案把「AI 系统纳入等保对象、训练/推理数据不出境」当作 **产品风险**，不把未经核对的罚款表写进设计约束。

---

## 2. 现状核验（以代码为准，不靠概念）

### 2.1 用户点名的钩子 `backend/llm_client.py` 不存在

全库无该文件。真实实现：

```184:204:backend/summary_compression.py
class LLMClient:
    """LLM 客户端 — 支持重试、降级、成本控制、响应缓存"""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url.rstrip("/")
        self.model = settings.llm_model
        self.client: httpx.AsyncClient | None = None
        self._response_cache: dict[str, str] = {}
        ...
    async def ensure_client(self):
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=10.0),
            )
```

`chat()` 缓存键：

```218:221:backend/summary_compression.py
        digest = hashlib.md5(
            f"{prompt_text}:{temperature}".encode("utf-8")
        ).hexdigest()
        cache_key = f"llmcache:{digest}"
```

`EmbeddingClient.embed` 同样 `hashlib.md5`。`app.py` 启动时 `summary.llm.set_redis(redis_client)`。单测 `backend/tests/test_emb_backfill_and_llm_redis.py` 直接 `from summary_compression import EmbeddingClient, LLMClient`。

**PR1 必须先创建 `backend/llm_client.py`**，把 `LLMClient` / `CostTracker` / `cost_tracker` / `estimate_tokens` / `_extract_text_content` 迁过去。`EmbeddingClient` **留在** `summary_compression.py`（不搬）。`summary_compression.py` re-export `LLMClient` 等，保证下列 import 零改动：

- `from summary_compression import summary, embedder, LLMClient, CostTracker, _extract_text_content`
- 单测：`test_emb_backfill_and_llm_redis.py`、`test_llm_cache_and_embedding.py`、`test_token_cost.py`、`test_trace_degraded.py`
- `app.py` lifespan：`summary.llm.set_redis`、`cost_tracker`

### 2.2 JWT 不是 RSA，更不是 SM2

```15:36:backend/auth.py
SECRET_KEY = settings.jwt_secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120
...
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
```

`get_current_user` `jwt.decode(..., algorithms=[ALGORITHM])`。密钥空则 **503**（这点比 field_cipher 诚实）。登录在 `routers/auth.py`：内置 admin 用 env 口令**明文比对**，注册用户走 bcrypt。前端 `frontend/src/lib/api.ts` 只存 `access_token` 字符串，不解析 `alg`。

**PR5 必须删除模块级 `ALGORITHM` / `SECRET_KEY`**，改为函数内读 `settings.jwt_alg` / `settings.jwt_secret`，否则「按 settings 选算法」是空操作。PyJWT 不识别 SM2；Q2=SM2 时按 §6.2.2 注册 `Sm2Algorithm`，Q2 未决时 PR5 **只交 flag 管道 + 仍签发 HS256**。

### 2.3 字段加密是可选 Fernet，而且默认关

```1:44:backend/field_cipher.py
使用 Fernet (AES-128-CBC + HMAC-SHA256) 对称加密方案。
...
ENCRYPT_FIELDS = ("apiKey", "srcIp", "dstIp", "message")
ENC_PREFIX = "ENC:"
```

调用点只有：

- `kafka_producer.publish_audit_result` / `publish_alert` — 发送前 `encrypt_message`
- `kafka_consumer._process_message` — 处理后 `decrypt_message`
- **`produce_raw_batch`（网关 → `security-logs-raw`）不加密**，Flink 看到的是明文 camelCase 事件

compose 两处 `SHARED_MEMORY_FIELD_ENCRYPTION_KEY: ${SHARED_MEMORY_FIELD_ENCRYPTION_KEY:-}`，空即关闭。PG 业务表（`security_events` 等）**没有**列级加密。

### 2.4 审计 trail：有 who-did-what-when，无完整性

`models.AuditTrail` / `init.sql` 列：`actor, actor_role, action, target_type, target_id, before, after, ip, user_agent, reason, created_at`。无 `prev_hash` / `entry_hash` / `anchor_sig`。

`log_action` 失败进 `_fallback_buffer`，上限 `_FALLBACK_MAX = 500`，超出丢最老。`scheduler._audit_trail_flush_loop` 60s 冲刷。这是可用性优先，**与「不可篡改」注释相反**。DBA 或 SQL 注入改历史行，应用层发现不了。

### 2.5 Kafka 传输是「外网有 TLS、内网明文、应用层加密未开」

`docker-compose.yml` kafka 服务：

- `PLAINTEXT://kafka:9092` — 容器网络，backend / Flink / schema-registry 都走这
- `SASL_SSL://<KAFKA_PUBLIC_HOST>:9093` — 外部日志源，SCRAM-SHA-512 + PKCS12
- `PLAINTEXT_HOST://localhost:9094` — 本机工具（prod overlay 关掉）

`backend/kafka_producer.py` / `kafka_consumer.py` 的 `AIOKafkaProducer` / `AIOKafkaConsumer` **只传 `bootstrap_servers=settings.kafka_bootstrap`**（compose 设为 `kafka:9092`），没有 `security_protocol` / `ssl_context`。

证书：`certs/kafka/*.pem`、`*.p12` 已存在，但是 RSA。`KAFKA_SSL_CLIENT_AUTH: none`，外网 TLS 是加密不是双向认证。

密评抽查消息总线时，测评师会问：① 内网 PLAINTEXT 是否在同一安全域且物理/逻辑隔离？② 证书算法是否商密？③ 应用层是否对重要字段加密？三问目前只有③有半套代码且默认关。

**Topic 数量**：v6 写「7 topic」是过时口径。`config.py` + `flink-jobs/.../KafkaConfig.java` 现有 raw / validated / rejected / enriched / alerts / audit-queue / audit-results / dlq / cep-partial / cep-patterns / sigma-hit / ingest / behavior-alerts / ndr-* 等，**全部内部 listener 均 PLAINTEXT**。密评材料禁止抄「7 topics」。

同走 `kafka:9092` 且无 `security.protocol` 的客户端（L1 不得静默 flip 9092）：`kafka_producer.py`、`kafka_consumer.py`、`edr_fusion/edr_adapter.py`、`ids_connector/suricata_connector.py`、`KafkaConfig.java`（Flink 全部作业）、schema-registry、kafka-ui。

### 2.6 南北向不是 HTTPS（含已暴露的 8001）

`frontend/nginx.conf` 两个 server：`:80` 前端 + API 反代，`:8080` Flink/Grafana/Jaeger/Temporal Basic Auth。无 `ssl_certificate`。compose 映射 `3001:80`、`3002:8080`。后端 CORS `allowed_origins` 默认 `http://localhost:3001`。

另外：`docker-compose.yml` 与 `docker-compose.prod.yml` 都映射 **`8001:8000`**，`docs/deployment.md` 防火墙清单有意放行 8001。运维常用 `curl http://localhost:8001/api/health` 绕过 nginx。L1 只给 nginx 上证书 **盖不住这条旁路**。密评 / `gm` overlay **必须 `ports: []` 掉宿主 8001**（容器网络内 frontend 仍访问 `backend:8000`）。8001 仅 dev 默认 compose 保留。

浏览器 GMTLS 是已知坑（仅部分 360/奇安信/国产套件）。本方案 **不把「Chrome 原生 GMTLS」写成 L0 交付物**。

### 2.7 MCP 已有行为签名，没有密码学签名

`mcp_guard/guard_server.py` 在 4 层检查之后接 `BehaviorDetector`（UEBA 指纹），不是 SM2。v5 写的「Agent→Tool SM2 签名」若在本方案再做一套，会和已落地的 `2026-q3-tool-behavior-signature.md` 抢同一调用点。本方案：**L0 不做 MCP SM2；L1 可选挂签名包装器，默认关。**

### 2.8 密钥与残留信息

| 密钥/秘密 | 位置 | 形态 |
|-----------|------|------|
| JWT | `SHARED_MEMORY_JWT_SECRET` | 明文 hex |
| 字段加密 | `SHARED_MEMORY_FIELD_ENCRYPTION_KEY` | 明文 Fernet urlsafe b64，常空 |
| Admin | `SHARED_MEMORY_ADMIN_PASSWORD` | 明文，登录直接 `==` |
| LLM API | `SHARED_MEMORY_LLM_API_KEY` | 明文 Bearer |
| Redis | `redis://:${REDIS_PASSWORD}@redis:6379/0` | 口令，**无 TLS** |
| PG | `postgresql+asyncpg://admin:${POSTGRES_PASSWORD}@postgres:5432/...` | 口令，compose **未开 sslmode** |
| Kafka SSL 库密码 | `KAFKA_SSL_PASSWORD` / 凭据文件 | 明文文件挂进容器 |
| LLM 响应缓存 | 进程 dict + Redis `llmcache:*` | **明文 completion**，键 MD5 |
| Embedding 缓存 | Redis `embed_cache:*` | 明文向量，键 MD5 |
| `llm_enhancer._biz_cache_key` | Redis 业务去重 | **独立 MD5**，与 `LLMClient` 缓存不是同一键空间 |

`LLMClient._cache_set` 把模型输出原样 `setex`。密评「剩余信息保护」会问：会话结束后 Redis 里是否还躺着告警结论。TTL 默认 86400s（`llm_cache_ttl`）。

compose 默认 embedding：`SHARED_MEMORY_EMBEDDING_BASE_URL:-https://maas-api.cn-huabei-1.xf-yun.com/v2`。Chat TEE **阻止不了** 知识库/告警文本经 embedding 出界到讯飞。L0 将此列为已接受风险（T3 旁路）；L1 起 embedding 与 chat 走同一 Guard（同一私有化服务）。

### 2.9 算法盘点总表（替换清单，不是口号）

| 位置 | 当前 | 目标 | 密评关注点 |
|------|------|------|------------|
| JWT `auth.py` | HS256（import 时常量） | 密评：§6.2.2 SM2-JWS；Q2 未决时保持 HS256 + flag | 密钥是否来自密码模块；alg 降级 |
| `user_store.py` 口令 | bcrypt | **保持 bcrypt** | 不在本方案范围 |
| `field_cipher.py` | Fernet AES-128-CBC+HMAC-SHA256 | **L0 SM4-CBC+HMAC-SM3**；L1+ 若产品证书含 GCM 再升 SM4-GCM | 禁止自实现 GCM；走 `gmssl`/SDF/Tongsuo |
| Kafka 内网 | 全部内部 topic PLAINTEXT（≫7） | L0：audit/alert 字段 SM4；raw 默认关。L1：新增 9096 SSL，9092 不动 | 总线抽查；Flink `keyBy(srcIp)` |
| Kafka 外网 | TLS + RSA-2048 + SCRAM-SHA-512 | 证书换 SM2 或双证书；SCRAM 可暂留 | 套件与证书算法 |
| nginx/frontend | HTTP/80 + **宿主 8001 明文 FastAPI** | 双栈 TLS1.3+GMTLS；密评 overlay 不发布 8001 | 浏览器兼容；禁止静默降级到 HTTP |
| LLM HTTP | 普通 HTTPS 到云 | 证明 + §6.1.3 SM 会话；L1/L2 GMTLS | 提示词是重要数据 |
| Embedding HTTP | 讯飞 HTTPS | L0 接受出界；L1 同 Guard | 知识库文本 |
| `audit_trail.py` | 无链 | SM3 链 + SM2 锚 + epoch 顾问锁 | 完整性 / 抗抵赖 |
| LLM/embed/`llm_enhancer` 缓存键 | MD5（三处） | SM3；enhancer 纳入 PR6 | 完整性算法 |
| Agent→Tool MCP | 无密码学签名 | 可选 SM2；默认不做 | 指向已有行为签名 |
| 密钥 | env 明文 | 分级：dev env / 密评 SDF | 最容易挂 |

---

## 3. 目标与非目标

### 3.1 目标

1. **抽出** `LLMClient` 到 `backend/llm_client.py`，所有现有 `summary.llm.chat` 调用方继续工作。
2. **Pillar A**：密评模式（`SHARED_MEMORY_TEE_REQUIRED=true`）下，未通过 `QuoteEnvelope` 决策缓存的推理后端 **不得** 收到 prompt。
3. **Pillar B**：仓库内实际使用的对称/哈希/签名算法可切换到 SM4/SM3/SM2；L0 钉死 `gmssl==3.2.2` + **SM4-CBC+HMAC-SM3** 可演示 GB/T 附录向量；L1 密钥进 SDF 认证模块。
4. 给出可直接粘贴进密评申请的 **密码应用方案骨架**（架构图 + 三张表 + 密钥生命周期 + 产品清单）。
5. 对照 GB/T 22239-2019 第三级控制点与 GM/T 0115 测评单元，**诚实标注覆盖/部分覆盖/不覆盖**。
6. 迁移可回滚：字段双前缀、JWT 双算法、feature flag。

### 3.2 非目标（本轮不做）

- **不**把 Flink / Kafka / PostgreSQL / Qdrant / Redis / 前端放进 TEE。理由：吞吐与状态体积不适合机密虚机；CPU TEE 也保护不了 GPU 上的 LLM；扩大边界会把 L2 变成采购项目而不是可合入 PR。
- **不**声称等保测评或密评已通过，不输出「33 项一票否决已清零」。
- **不**把 Qdrant 换成国产向量库（这是独立信创缺口，v5 §4.3 已点名；本方案只在 Open Questions 留一句）。
- **不**保证浏览器原生 GMTLS；管理面允许 TLS1.3 + 应用层 SM。
- **不**在 L0 用自实现 SM4 去申报密评。
- **不**重做 MCP UEBA；不修 CRIT-05 mock 执行器。
- **不**把 admin 明文口令、bcrypt、PG 全库 TDE、异地备份 30/100 公里、数据销毁流程一次性做完——那些是 v6 §4 #6–#10，本方案只接 #1–#4 及 LLM 信任边界。
- **不**把 Intel TDX 写成政府项目唯一 TEE。
- **不**假装 CPU TDX/CSV 能保护 GPU HBM 里的权重和 KV cache。

---

## 4. 合规映射

### 4.1 等保 2.0（GB/T 22239-2019 第三级）

下列条款号按 GB/T 22239-2019 第 8 章「第三级安全要求」常用结构引用。测评机构作业指导书可能把同一控制点拆到「安全通信网络 / 安全区域边界 / 安全计算环境」不同表格，**落地以测评合同附件为准**。

| 控制点族 | 标准位置（第三级） | 本方案措施 | 覆盖 |
|----------|-------------------|------------|------|
| 身份鉴别 | 安全计算环境 8.4.1（及管理面登录） | 口令（已有 bcrypt + 登录失败锁定）+ JWT；密评模式 JWT 改为 SM2 或密码机 HMAC；**组合鉴别**仍缺第二因子 | 部分。本方案不交付 OTP/智能卡，只换 JWT 算法与密钥出处 |
| 通信完整性 | 安全通信网络 8.2.2 / 计算环境通信 | LLM 请求 SM2 封装或 GMTLS；Kafka 应用层 SM4-CBC+HMAC-SM3；审计链 SM3 | 部分。内网 Kafka PLAINTEXT 要到 L1 新增 9096 才有 TLS 选项 |
| 通信保密性 | 同上 | SM4 会话 / GMTLS / TLS1.3；字段 SM4 | 部分。nginx 80、Redis/PG 无 TLS 仍在 |
| 数据完整性 | 安全计算环境 8.4.7 | 审计 SM3 链 + SM2 锚；字段 HMAC-SM3（L0）/ GCM（L1+） | 本方案主覆盖 |
| 数据保密性 | 8.4.8 | 字段 SM4；LLM 缓存 SM4 或禁缓存；推理进 TEE | 主覆盖（存储侧只覆盖 field_cipher 触及的字段，不是全库 TDE） |
| 剩余信息保护 | 8.4.10 | 密评模式 Redis `llmcache` 加密或关闭；TEE 内缓存优先 | 部分 |
| 安全审计 | 8.4.3 / 区域边界 8.3.5 | 已有 trail + 本方案抗篡改；LLM transcript 哈希入链 | 部分。v6 #5「全量写操作 @audited」仍是另一张工单 |
| 可信验证 | 8.2.3 / 8.3.6 / 8.4.6 | TEE 远程证明 + 模型度量绑定 | L2 才覆盖；L0/L1 标「不适用/计划」 |
| 数据备份恢复 | 8.4.9 | **不覆盖**（v6 #7 异地备份） | 不覆盖 |
| 个人信息保护 | 8.4.11 | 字段加密间接覆盖 IP 等；无专门个保设计 | 弱覆盖 |

**结论**: 本方案能把 v6 §4 的 #1–#4 从「代码级缺口」推进到「可测评的密码应用」；**不能**单独让等保三级通过。测评还有物理机房、网络架构、恶意代码、备份、管理制度。对外材料禁止写「本升级完成后即等保三级」。

### 4.2 密码法与密评

《密码法》对关键信息基础设施运营者要求使用商用密码进行保护，并开展商用密码应用安全性评估（条文以正式文本为准，常见对应第 27 条）。密评不是「代码 import sm4」，而是：

| 密评视角 | 本仓库今天 | L0 软件国密 | L1 认证模块 | L2 TEE |
|----------|------------|-------------|-------------|--------|
| 算法合规（SM2/3/4、禁止 MD5/DES/RSA-1024 等） | HS256 / AES-Fernet / MD5 / RSA-2048 TLS | 算法名对齐，**产品未认证** | 对齐 | 对齐 |
| 协议合规（TLCP/GMTLS、握手、套件） | TLS1.3 RSA 或 HTTP | 应用层 SM 可部分替代 | Tongsuo GMTLS 双栈 | TEE 网关 GMTLS |
| 密钥管理（生成/存储/分发/轮换/销毁） | env 明文 | 仍是 env，**密评必挂** | SDF 会话 + `key_id`；PIN 仍是编排秘密 | 会话密钥可在 TEE 内派生 |
| 密码产品认证（商密产品认证证书） | 无 | **明确不能申报** | 密码机/卡（SDF）+ 认证 Tongsuo 发行版 | 机密计算产品另证 |
| 密码应用安全性（实现正确、无明文、无降级） | 字段加密默认关；JWT 无降级保护 | 有双读/双算法，必须防降级攻击 | fail-closed | quote 过期 fail-closed |

GM/T 0115 测评单元（应用和数据安全常用）：身份鉴别、访问控制、安全审计、通信完整性、通信机密性、存储完整性、存储机密性、不可否认性，外加密钥管理、安全管理。本方案第 7 节按这些单元填表。

### 4.3 信创与机密计算选型

| 路径 | 适用 | 不适用于 |
|------|------|----------|
| **海光 CSV 机密虚机**（主） | 政府 / 关基 / 揭榜挂帅 | 需要 NVIDIA 生态且必须出海合规的场景 |
| 海光 DCU + 厂商机密计算栈 | 国产 GPU 推理 | 成熟度、驱动、vLLM 支持必须单独立项验证 |
| Intel TDX + NVIDIA CC（Hopper/Blackwell） | 商业市场、出海、已有 Intel 机架 | **不能**作为政府项目唯一方案 |
| 国内云厂商 CSV/TDX 实例（阿里云/火山/腾讯/移动云等，以当时商用目录为准） | 无自有 CSV 机器时的 L2 加速 | 仍要做 attestation；密钥与审计不能只信云控制台 |

**GPU 是真实难点**: vLLM 权重和 KV cache 在 GPU HBM。CSV/TDX 保护的是 **CPU 侧客户机内存和寄存器**。没有 GPU Confidential Computing（NVIDIA CC 或海光 DCU 对等能力）时，宿主机 DMA / 恶意设备可以把 HBM 读走。因此：

- L2 若只有 CPU TEE：**不得**在材料里写「模型与推理数据在运算过程中全程机密」。
- 密评模式若 `SHARED_MEMORY_TEE_REQUIRED=true` 且 `QuoteEnvelope.gpu_cc_policy` 不是 `verified`：拒绝 GPU 模型（`gpu_cc` 缺省、`none`、或 RAS 验签失败均算未 verified）。默认 **拒绝**，不接受签字豁免除非另开工单。
- CPU-only 小模型（纯 CPU vLLM）可以作 attestation 联调，不能作 SOC 生产推理。

---

## 5. 威胁模型

| ID | 威胁 | 现状 | 缓解 | 残余 |
|----|------|------|------|------|
| T1 | 宿管 / 云运维转储 LLM 进程内存、读 GPU HBM | 明文 prompt 在 backend 进程 + 云 MaaS | TEE + GPU CC；backend 进程仍会组装 prompt（**backend 不在 TEE**） | 应用主机仍可见组装后的 prompt，直到送进 TEE。v1 接受这条，靠主机加固 + 审计 |
| T2 | 路径上抓包得到告警原文 | 云 HTTPS 或内网 HTTP；Kafka 内网明文 | SM 会话 / GMTLS；字段 SM4 | 反向代理若做 TLS 终结仍能看见，除非 e2e 应用层 SM |
| T3 | LLM 提供商（mimo 云）看见 chat；讯飞看见 embedding | compose 默认两朵云 | chat 私有化进 TEE；**L0 不切断 embedding** | L0 知识库/告警文本仍去讯飞，已接受 |
| T4 | JWT secret 从 `.env` / compose 泄漏 → 伪造任意角色 | HS256 对称密钥即签名权 | 密钥进密码机；SM2 私钥不出模块 | 迁移期双算法可被降级到 HS256（必须关） |
| T5 | Fernet key 空或泄漏 | 空=不加密；泄漏=Kafka 字段可读 | 强制 key；SM4 密钥进模块 | 历史明文 topic 无法事后变密 |
| T6 | 篡改 `audit_trail` 行 | 无链 | SM3 链 + SM2 锚；周期外部存证 | fail-open 缓冲 500 条仍可丢；密评模式要改 |
| T7 | 伪造 TDX/CSV quote、重放过期 quote、用 QEMU 冒充 | 无验证 | `QuoteEnvelope`；**决策缓存**（不复用 nonce）；fixture 与真 quote 分 `kind` | 自建 RAS 的根信任仍是运维问题 |
| T8 | 中间盒剥掉 GMTLS，只留 RSA TLS | 无 GMTLS | 双栈时 **密评模式拒绝纯 RSA 套件**；应用层 SM 不依赖外层 TLS 算法 | 管理面若允许 RSA 降级，会被攻击者逼降 |
| T9 | 缓存侧信道：Redis `llmcache` 被读 | 明文 + MD5 键 | SM3 键 + SM4 值或禁缓存 | 键仍可能被用来做存在性推断 |
| T10 | Prompt 注入后工具调用 | 已有 MCP Guard + 行为签名 | 本方案不重复；可选 SM2 防抵赖 | 签名不等于「该不该调」 |
| T11 | 证明通过但模型被换成后门权重 | 无 | quote 绑定模型哈希 / 镜像度量 | 供应链投毒需另做模型签名仓库 |
| T12 | 开发人员把 `SHARED_MEMORY_CRYPTO_BACKEND=software` 带进生产 | 无开关 | `SHARED_MEMORY_ENV_NAME=prod` 且 backend=software → 拒绝启动 | 配置错误仍是人 |

**信任边界（v1）**:

- **不可信**: 宿主机 OS、云宿管、运维 SSH、backend 进程、Kafka、PG、Redis、nginx、浏览器。
- **可信计算基（TCB）**: 海光 CSV/TDX 客户机内的推理网关 + vLLM +（若有）GPU CC 固件；远程证明服务的根密钥；密码机。
- **有意不进 TCB**: Flink 作业、Qdrant、前端、Temporal。它们处理的数据在进 LLM 之前已经在不可信域；本方案保证 **离开 SOC 去推理的那一跳** 和 **落库的敏感字段/审计链** 可申报，而不是重做整个数据面。

---

## 6. 总体架构（两支柱）

```mermaid
flowchart TB
  subgraph untrusted ["不可信域: 宿主机 OS / 云宿管 / SOC 数据面"]
    FE["frontend nginx :80/:443"]
    BE["backend FastAPI<br/>LLMClient + TeeAttestationGuard"]
    KF["Kafka :9092 PLAINTEXT 保留<br/>L1 另开 :9096 SSL"]
    PG["PostgreSQL audit_trail + events"]
    RD["Redis llmcache"]
    FL["Flink / Qdrant / Temporal"]
  end

  subgraph tee ["TEE 客户机 主: 海光 CSV / 备: Intel TDX"]
    GW["推理网关<br/>GMTLS 或 SM session 终结"]
    VLLM["vLLM + 国产/可私有化权重"]
    subgraph gpu ["仅当 GPU CC 报告有效"]
      HBM["权重 + KV cache in HBM"]
    end
  end

  subgraph crypto ["密码模块"]
    SW["L0 gmssl software<br/>禁止申报密评"]
    HSM["L1/L2 商密认证密码机 SDF"]
  end

  subgraph ras ["远程证明"]
    RA["Attestation Verifier<br/>自建或云厂商"]
  end

  FE -->|"L0 HTTP / L1 双栈 TLS"| BE
  BE -->|"quote + nonce"| RA
  GW -->|"CSV/TDX quote + GPU CC report"| RA
  BE -->|"SM4 body + SM2 sign"| GW
  GW --> VLLM --> HBM
  BE --> KF --> PG
  BE --> RD
  BE --> HSM
  GW --> HSM
  BE -.->|"开发"| SW
```

### 6.1 Pillar A — Confidential LLM inference

#### 6.1.1 信任边界与双后端

| | 信创主路径 | 商业/出海备选 |
|--|------------|----------------|
| 机密虚机 | 海光 CSV | Intel TDX |
| 加速器 | 海光 DCU（有 CC 才宣称保护 HBM） | NVIDIA Hopper/Blackwell CC |
| 模型 | Qwen / DeepSeek 私有化权重，离线导入，度量哈希入库 | 同左或客户指定 |
| 引擎 | vLLM 或海光优化栈 | vLLM |
| 证明 | CSV report + 客户机测量寄存器（vLLM 二进制、模型哈希、启动参数）+ 可选 DCU report | TDX quote + NVIDIA CC attestation |

Backend **不在** TEE 里。它负责：拼 prompt、走 Guardrail、验 quote、SM 封装、写 audit。攻击者 root 了 backend 主机仍能看见即将送出的 prompt——这与把整个 SOC 塞进 TEE 是不同问题（见替代方案 C）。v1 的承诺是：**prompt 不会以明文到达不可证明的推理进程，也不会到达未证明的云 MaaS。**

#### 6.1.2 远程证明 — `QuoteEnvelope` 合同（冻结）

硬件 quote **不是** `Sign_HW(measurement || nonce || model_id || gpu_cc)`。TDX 签的是 TDREPORT，`REPORTDATA` 只有 **64 字节**；CSV / NVIDIA CC 是各自厂商 blob。应用层只把结构化声明的摘要塞进这 64 字节。

```python
# backend/tee/quotes.py
class QuoteEnvelope(TypedDict):
    kind: Literal["fixture", "csv", "tdx"]
    body: bytes                 # 厂商 quote 原文；fixture 见下
    gpu_cc: bytes | None        # NVIDIA CC / DCU 报告；无则为 None
    gpu_cc_policy: Literal["missing", "none", "verified"]
    claim_hash: bytes           # 32 bytes SM3；放入 REPORTDATA[0:32]，[32:64]=0
    nonce: bytes                # 32 bytes，每次向 guest/RAS 要新 quote 时由 GmCrypto.random 生成
    model_id: str
    model_sm3: bytes            # 32 bytes，权重文件 SM3
    vllm_image_digest: str      # "sha256:" + 64 hex
    tcb: str                    # 厂商 TCB 字符串，fixture 用 "fixture-v1"
```

`claim_hash = SM3( nonce || utf8(model_id) || model_sm3 || gpu_cc_digest )`  
`gpu_cc_digest = SM3(gpu_cc) if gpu_cc else 32×0x00`

**GPU CC 判定（fail-closed，D3）**：

| `gpu_cc_policy` | 含义 | `TEE_REQUIRED` + GPU 模型 |
|-----------------|------|---------------------------|
| `missing` | 信封无 `gpu_cc` 字段 | **拒绝** |
| `none` | 显式声明无 GPU CC（CPU-only 联调） | **拒绝 GPU 模型**；仅允许 `settings.tee_cpu_only_model=true` 的测试模型 |
| `verified` | RAS 已验厂商 GPU blob | 允许 |

`model_id == settings.llm_model` 只是字符串一致性检查。**权重绑定**走 `model_measurements` 表：构建管道对 checkpoint 文件做 SM3，写入 `(model_id, sm3_hash, vllm_image_digest, gpu_cc_policy, created_at)`。Guard 要求 `envelope.model_sm3` ∈ 该表且 `model_id` 匹配。compose 默认 `mimo-v2.5` **不得**出现在允许列表，除非有对应私有化度量行。

**新鲜度 vs 缓存（禁止复用 nonce）**：

- **决策缓存**（热路径 <1ms）：键 = `(kind, model_id, model_sm3, gpu_cc_digest, tcb)`，值 = `{ok: bool, verified_at, envelope_id}`，TTL = `SHARED_MEMORY_TEE_QUOTE_TTL_S`（默认 120）。命中则 **不再向 guest 要 quote、不换 nonce**，只复用「上次已验证的测量」。
- **冷路径**：缓存过期或测量变化 → 新 32-byte nonce → 向 TEE 网关 `GET /attestation?nonce=` 或 RAS → 校验证书链（TDX=DCAP；CSV=海光根；fixture=测试 HMAC 键）→ 写入决策缓存。
- Backend **不在 TEE 内**，不能本地 quote。

`SHARED_MEMORY_TEE_REQUIRED=true`：决策 `ok=false` 或缓存空且 RAS 失败 → **不发 HTTP**（含不得回落到 `api.xiaomimimo.com`），返回现有 fallback JSON，打 metric + `audit_trail` action=`llm.attestation_fail`。`false`（默认）：`attestation_skipped`，保持今天 httpx。

**PR8 fixture 文件** `backend/tee/fixtures/quote_ok.json` / `quote_bad_model.json` / `quote_gpu_none.json`：

```json
{
  "kind": "fixture",
  "nonce": "<64 hex>",
  "model_id": "qwen-test",
  "model_sm3": "<64 hex>",
  "vllm_image_digest": "sha256:00...",
  "gpu_cc_policy": "verified",
  "gpu_cc": "<hex or omit>",
  "claim_hash": "<64 hex>",
  "tcb": "fixture-v1",
  "body": "<hex HMAC-SM3(fixture_mac_key, claim_hash)>"
}
```

`fixture_mac_key` 仅测试：`SHARED_MEMORY_TEE_FIXTURE_MAC_KEY`（32 hex）。CI 禁止访问 `/dev/tdx-guest`。Verifier 对 `kind=fixture` 只验 HMAC，对 `csv`/`tdx` 走厂商库（L2）。

RAS：自建 verifier + fixture 为 PR8；云厂商 API 为 Q4/L2。

#### 6.1.3 传输 — v1 SM 会话合同（冻结）

不在 L0 做 SM2 ECDH 多 RTT。v1 用 **网关 SM2 公钥封装随机 SM4 会话密钥**（`gmssl` CryptSM2 的 C1C3C2）。

**配置**

- `SHARED_MEMORY_LLM_SM_SESSION` bool 默认 false
- `SHARED_MEMORY_LLM_GATEWAY_SM2_PUB` PEM 或未压缩 hex `04||X||Y`（64+1 字节）。mock 网关与测试共用 `backend/tee/fixtures/gateway_sm2.pem`

**会话状态（backend 进程内，≤1h）**

| 字段 | 编码 |
|------|------|
| `sid` | 16 字节随机，hex 32 字符 |
| `Ks` | 16 字节 SM4 密钥 |
| `Km` | 32 字节 HMAC-SM3 密钥；`Km = SM3(Ks \|\| "mac")` |
| `created_at` | unix 秒；年龄 > 3600 则轮换 |
| `wk_sent` | bool；首次请求带 `wk` |

**HTTP JSON 记录（替换整个 POST body，含 `reasoning_split` / `reasoning_effort` / `messages`）**

```json
{
  "v": 1,
  "sid": "<32 hex>",
  "ts": 1757030400,
  "nonce": "<64 hex>",
  "kid": "llm-session",
  "wk": "<Base64URL SM2-Encrypt(gateway_pub, Ks) or omit after first>",
  "blob": "<Base64URL iv||ct||mac>"
}
```

`blob` 明文 = UTF-8(原 `chat/completions` JSON，`ensure_ascii=False`，分隔符紧凑但 **key 顺序与现网 `payload` dict 插入顺序一致**，即 wrap 前 `json.dumps` 不 `sort_keys`)。  
`iv` 16 字节随机；`ct` = SM4-CBC-PKCS7(`Ks`, iv, plaintext)；`mac` = HMAC-SM3(`Km`, `sid_bytes || ts_be64 || nonce || iv || ct`) 32 字节。  
`blob` = Base64URL(`iv || ct || mac`)，无 pad。

**对端**：`backend/tee/mock_gateway.py`（stdlib `http.server` 或 FastAPI 单文件）。`POST /v1/chat/completions`：若 body 含 `"v":1` 则解密，把内层 JSON 交给固定 stub 回复（OpenAI `choices[0].message.content`），再用同一 `Ks` wrap 响应（响应记录无 `wk`，`kid=llm-session-resp`）。flag 关时 LLMClient 发送的字节必须与今天完全相同（PR7 用 httpx mock 断言）。

**重放窗口**：拒绝 `|now - ts| > 120` 秒；`nonce` 在每 `sid` 的 LRU（最多 4096）命中则拒绝。网关与 mock 同样执行。

**响应 unwrap**：外层必须 `v==1` 且 `sid` 匹配；否则当传输错误走现有 retry/fallback，不把密文当模型输出解析。

L1/L2 另开 GMTLS（D5）；v1 会话不依赖 Tongsuo。在 mock/真网关存在之前，**不得**把「提示词不再以明文 HTTP 离开」写成已交付。

#### 6.1.4 软件钩子

```
backend/llm_client.py              # PR1：仅迁 LLMClient/CostTracker/estimate_tokens/_extract_text_content
backend/summary_compression.py     # re-export 上述；EmbeddingClient 仍定义于此
backend/crypto/backend.py         # GmCryptoBackend + SoftwareGmBackend
backend/crypto/session.py         # SmSessionCodec
backend/tee/attestation.py        # TeeAttestationGuard
backend/tee/quotes.py             # QuoteEnvelope
backend/tee/mock_gateway.py       # PR7 解密对端
backend/tee/fixtures/             # quote_*.json, gateway_sm2.pem
```

`LLMClient.chat` 在 PR7/PR8 之后：

```python
async def chat(self, messages: list[dict], temperature: float = 0.3) -> str:
    await self._attestation.ensure_decision(model=self.model)  # 决策缓存；TEE_REQUIRED fail-closed
    ...
    payload = {..., "reasoning_split": True, ...}  # 保持 MiniMax 字段
    body = self._codec.wrap(payload) if self._codec.enabled else payload
    resp = await self.client.post(url, headers=headers, json=body)
    inner = self._codec.unwrap(resp.json()) if self._codec.enabled else resp.json()
    content = _extract_text_content(inner)
    ...
```

#### 6.1.5 延迟与 SLO

| 来源 | 量级（工程估计，不是本仓库实测） | 如何消化 |
|------|-----------------------------------|----------|
| CSV/TDX CPU | 典型 5–15% 计算开销 | 推理是 GPU bound |
| GPU CC | 文献/厂商口径常见 10–30%+ | **禁止把 CPU 数字套到 GPU** |
| GMTLS vs TLS1.3 | 握手同量级；会话复用后可忽略 | 连接池 |
| 软件 SM4-CBC+HMAC-SM3 vs AES-NI | 无 SM4 指令时数倍级 | L1 SDF / Tongsuo |
| 软件 SM2 加密 16B 会话密钥 | 毫秒级，每小时一次 | `wk` 只在会话首包 |
| Attestation 冷路径 | RAS/guest 一轮 RTT，10–50ms+ | 决策缓存 TTL 120s |
| Attestation 热路径 | **决策缓存命中 <1ms，不换 nonce、不拉 quote** | 见 §6.1.2 |

**SLO（相对现网）**:

- 现网：`httpx` read timeout **90s**，无 p95 承诺。
- L0（无 TEE）：SM 封装增加 p95 **< 20ms**（软件 SM4 对 chat body，body 通常 < 32KB）。
- 密评模式（有 TEE）：p95 = 现网 LLM p95 × 1.15 + 100ms（证明缓存命中）+ 传输封装。超时仍 90s，不把超时当 SLO。
- 证明失败：立即 fallback，不重试云 endpoint。
- 缓存命中：仍是 0 token 路径；密评模式若缓存出 TEE，必须 SM4，解码计入上述 20ms。

### 6.2 Pillar B — 国密替换通信与存储密码

#### 6.2.1 抽象层 + L0 库钉死 + SDF（冻结）

L0 **不**把 `sm4_gcm_*` 放进必选 Protocol。PyPI `gmssl` 3.2.2 纯 Python，只提供 SM4 ECB/CBC，无 GCM；本仓库 CI 含 Windows，不能假设 `libgmssl` ctypes。禁止为 GCM 自写 GHASH。

钉死：

- PyPI 名：`gmssl`，版本：`==3.2.2`（`requirements.txt` + lock）
- L0 对称：`SM4-CBC-PKCS7` + `HMAC-SM3`（encrypt-then-MAC）
- L1+：当 Tongsuo 或密码机**产品证书写明 SM4-GCM** 时，Protocol **可选** mixin `sm4_gcm_*`；未认证不得启用

```python
# backend/crypto/backend.py
class GmCryptoBackend(Protocol):
    def random(self, n: int) -> bytes: ...
    def sm3(self, data: bytes) -> bytes: ...
    def hmac_sm3(self, key_id: str, data: bytes) -> bytes: ...
    def sm4_cbc_encrypt(self, key_id: str, iv: bytes, plaintext: bytes) -> bytes: ...
    def sm4_cbc_decrypt(self, key_id: str, iv: bytes, ciphertext: bytes) -> bytes: ...
    def sm2_sign(self, key_id: str, data: bytes) -> bytes: ...   # raw r||s 64B
    def sm2_verify(self, key_id: str, data: bytes, sig: bytes) -> bool: ...
    def sm2_encrypt(self, key_id: str, plaintext: bytes) -> bytes: ...  # C1C3C2
    def sm2_decrypt(self, key_id: str, blob: bytes) -> bytes: ...
```

`SoftwareGmBackend` 文档第一句：**不得用于密评申报。** 密钥材料仅开发：从 `settings` 注入的 **独立** env（§8.1 `gm_field_sm4_key` / `gm_field_mac_key` / `gm_audit_sm2_private`），进程内存。**禁止**把 Fernet `field_encryption_key` 当 SM4 密钥。HMAC-SM3 用 SM3 的 HMAC（ipad/opad），不调外部库以外的轮函数。`key_id` → settings 映射见下表。

**L1 主接口 = GM/T 0018 SDF**，不是 PKCS#11 1.4（1999，无 SM 机制）。OASIS PKCS#11 3.x 对 SM4-GCM/SM2 也无便携定义，国产密码机普遍走 SDF。`SdfGmBackend` 实现同一 Protocol。PKCS#11 仅作**厂商可选适配**（私有 `CKM_*`），不作为切换门槛。

最小 SDF 函数集（与 Protocol 对齐）：

| SDF | 用途 |
|-----|------|
| `SDF_OpenDevice` / `CloseDevice` / `OpenSession` / `CloseSession` | 会话 |
| `SDF_GenerateRandom` | `random` |
| `SDF_GenerateKey` | 产生 SM4，标签=`key_id` |
| `SDF_Encrypt` / `SDF_Decrypt`（`SGD_SM4_CBC`） | `sm4_cbc_*` |
| `SDF_HashInit/Update/Final`（`SGD_SM3`） | `sm3` |
| `SDF_HMAC`（`SGD_SM3`）若固件提供；否则 L1 字段完整性改走证书中的 SM4-GCM，**禁止**在应用层用 `Hash(key\|\|data)` 冒充 HMAC | `hmac_sm3` |
| `SDF_InternalSign_ECC` / `InternalVerify_ECC` | `sm2_sign/verify` |
| `SDF_InternalEncrypt_ECC` / `InternalDecrypt_ECC` | `sm2_encrypt/decrypt`（会话 `wk`） |

应用查找的 `key_id`（SDF 对象标签 / 软件 env 映射）：

| key_id | 算法 | 用途 | software 材料（§8.1） |
|--------|------|------|----------------------|
| `jwt-sm2` | SM2 密钥对 | JWT（Q2=SM2） | `jwt_sm2_private` / `jwt_sm2_public` |
| `jwt-hs256` | HMAC-SHA256 | 迁移期 | 现 `jwt_secret` |
| `field-sm4` | SM4-128 | 字段 CBC | `gm_field_sm4_key`（32 hex = 16 B） |
| `field-mac` | HMAC-SM3 | 字段 MAC | `gm_field_mac_key`（64 hex = 32 B） |
| `audit-sm2` | SM2 | 审计锚 | `gm_audit_sm2_private`（PEM） |
| `llm-gateway-sm2` | SM2 **公钥** | 封装 `Ks` | `llm_gateway_sm2_pub` |
| `tee-fixture-mac` | HMAC-SM3 | 仅 CI fixture | `tee_fixture_mac_key` |

**SoftHSM2**（PR10 可选 CI job）：只做 AES/RSA **冒烟**，`pytest.mark.skip` 所有 SM 用例。不能当「PKCS#11 联调通过」。

`SHARED_MEMORY_CRYPTO_BACKEND=software|sdf`。`sdf` 打不开：abort，**禁止**静默回落 software。`SHARED_MEMORY_ENV_NAME=prod` 且 `software` → 拒绝启动。PIN：`SHARED_MEMORY_SDF_PIN` 仍是编排秘密（密钥管理残余，材料里写明，不装成已解决）。

`cryptography` 仅解密历史 Fernet 与非国密 TLS。

#### 6.2.2 SM2-JWS 剖面（冻结；PR5 默认仍 HS256）

JOSE 无标准 `SM2`。本系统私有 `alg=SM2`。前端只存 token 字符串（已核实 `api.ts`），不解析头。

**Q2 未决时 PR5 行为**：删除 `auth.py` 模块级 `ALGORITHM`/`SECRET_KEY`；签发/验签读 `settings.jwt_alg` / `settings.jwt_accept`；合法值目前只启用 `HS256`。`SM2` 出现在 accept 列表但 `jwt_alg` 仍 HS256 时 **不签发 SM2**。把 `backend/auth_sm2.py` 的 `Sm2Algorithm` 类与单测向量放进仓库，由 `if "SM2" in accept` 注册。Q2 拍板 SM2 后只需改 env，不必再设计线格式。

**Compact JWS（RFC 7515）**

signing-input = `ASCII(BASE64URL(utf8(header)) || '.' || BASE64URL(utf8(payload)))`

header：

```json
{"alg":"SM2","typ":"JWT","kid":"jwt-sm2","cty":"JWT"}
```

payload 与今天相同：`sub, role, exp, jti`（`exp` 为 NumericDate）。

**SM2 消息摘要（GB/T 35276 / GB/T 32918.2）**  
令 `M` = signing-input 的 UTF-8 字节（即 ASCII）。  
`IDA` = 默认用户标识 `1234567812345678`（16 字符 ASCII，GB/T 35276 默认）。  
`ZA = SM3( ENTLA || IDA || a || b || xG || yG || xA || yA )`（曲线参数与公钥，按 GB/T 32918）。  
待签摘要 `e = SM3(ZA || M)`。  
签名为 SM2 对 `e` 的签名，编码 **raw `r||s` 各 32 字节大端，共 64 字节**，再 Base64URL（无 pad）。**不用 DER。**

**公钥**：优先 PEM `-----BEGIN PUBLIC KEY-----`（SM2 OID）；线格式也接受未压缩 `04||X||Y`（65 字节）放进 `settings.jwt_sm2_public`。私钥不出 SDF；软件后端用 `SHARED_MEMORY_JWT_SM2_PRIVATE` PEM **仅开发**。

**PyJWT 注册草图**（`backend/auth_sm2.py`）：

```python
class Sm2Algorithm(jwt.algorithms.Algorithm):
    def prepare_key(self, key):
        return key  # key_id 或 PEM；禁止把 SM2 公钥字节交给 HMAC
    def sign(self, msg, key):
        return gm.sm2_sign(key_id="jwt-sm2", data=msg)  # 内部做 ZA||M
    def verify(self, msg, key, sig):
        return gm.sm2_verify(key_id="jwt-sm2", data=msg, sig=sig)
# jwt.register_algorithm("SM2", Sm2Algorithm())
```

**解码流程（防算法混淆）**

```
1. 拆 compact，JSON 解析 header（不验签）
2. alg = header.alg；若 alg ∉ settings.jwt_accept.split(",") → 401，**此时尚未选密钥**
3. 若 alg == "HS256" → 用 jwt-hs256 / jwt_secret HMAC-SHA256 验
   若 alg == "SM2"    → 用 jwt-sm2 验；**禁止**把 SM2 公钥/私钥字节传入 hmac.new
   其他 → 401
4. kid 若存在必须匹配该 alg 的 key_id；未知 kid → 401
5. exp / 现有 jti 逻辑不变
```

密评 overlay：`jwt_alg=SM2`，`jwt_accept=SM2`（关掉 HS256）。迁移期：`jwt_alg=SM2`，`jwt_accept=HS256,SM2`。

#### 6.2.3 field_cipher — `SM4ENC:` 二进制布局（冻结）

`FieldCipher` **禁止**在 import 时直接 `os.environ.get`。模块级单例 **进程内只构造一次**，与今天相同：`field_cipher = FieldCipher()` 在 import 时用当时的 `settings` 初始化。`kafka_producer.py` / `kafka_consumer.py` 的 `from field_cipher import field_cipher` 绑的是 **这个对象**，lifespan **不得** `field_cipher.field_cipher = FieldCipher(...)` 换实例（换了之后 Kafka 模块仍拿着旧的 disable 对象，探针显示 sm4、`publish_alert` 仍明文）。

就地重配：

```python
class FieldCipher:
    def configure(self, settings) -> None:   # 别名 reset_from_settings
        """Mutate _enabled / _mode / Fernet / SM4 key_ids in place. Same object."""
        ...

field_cipher = FieldCipher()  # import-time；读 settings，mode=off 则与今天 disable 相同

# app.py lifespan 与测试：
field_cipher.configure(settings)   # 同一 id()；禁止 rebind 模块名
```

测试注入同样 `configure(test_settings)`，不要 `monkeypatch` 成另一个实例却不改已 import 的别名。

`field_cipher_mode=off`：不要求 GM 密钥，行为与今天 disable 相同。  
`mode=sm4` 或 `dual` 且 `crypto_backend=software`：启动时 **必须** 有 `gm_field_sm4_key`（32 hex）和 `gm_field_mac_key`（64 hex）；缺一则 **显式 abort**（logger.error + raise），**禁止**静默 disable（否则 flag 开、Kafka 仍明文）。SDF 模式查 `field-sm4`/`field-mac` 句柄，缺同样 abort。  
`SHARED_MEMORY_FIELD_ENCRYPTION_KEY` **只**用于解密历史 `ENC:` Fernet，长度/编码不是 SM4 密钥。

**密文串**

```
ENC:<Fernet token utf-8>                         # 历史
SM4ENC:<Base64URL(blob)>                         # v1 L0
```

`blob`（version `0x01`，L0 CBC+HMAC）：

```
version     1 byte     0x01
kid_len     1 byte     N = len(kid)  1..64
kid         N bytes    UTF-8 key_id，默认 b"field-sm4"
iv          16 bytes   随机
ct          var        SM4-CBC-PKCS7(field-sm4, iv, utf8(plaintext))
mac         32 bytes   HMAC-SM3(field-mac, version||kid_len||kid||iv||ct||aad)
```

`aad` = UTF-8(字段名)，如 `srcIp` / `apiKey`；无字段名时空。  
Base64URL 无 pad。禁止 ECB。

version `0x02` **留给 L1 GCM**（证书允许时）：`iv` 12B + `ct` + `tag` 16B，无独立 mac。L0 实现遇到 0x02 且未启用 GCM → 解密失败（不回落 CBC）。

`decrypt_value`：`SM4ENC:` → 解 blob；`ENC:` → Fernet；无前缀 → 原样返回。密评 `field_cipher_mode=sm4` 时 `ENC:` 或无前缀记 `field_cipher_legacy_hits`，若 `SHARED_MEMORY_FIELD_CIPHER_REJECT_LEGACY=true` 则拒绝。  
`encrypt_value`：mode `sm4`/`dual` 写 `SM4ENC:`；`fernet` 写 `ENC:`；`off` 不加密。

**raw 通路**：L0 **不**改 `produce_raw_batch`（Q5）。PR9 flag `SHARED_MEMORY_FIELD_CIPHER_ENCRYPT_RAW` 默认 **false**。Flink `AnomalyDetectionJob` / `BehaviorAnomalyJob` / CEP **`keyBy(srcIp)` 且拒非 IPv4**。

若 Q5 选择「盲化指纹不改 Java 解密」：

- JSON **保留** `srcIp` 为 IPv4 明文（Flink 继续 keyBy）——这 **不算** 加密 raw，只是不加密该字段；或
- **推荐盲化**：新增 `srcIpHash` = 16 hex = `SM3("ip-v1" || utf8(ipv4))[:8]` 的 hex；`srcIp` 改为 `SM4ENC:...`；Java 改 `keyBy` 到 `srcIpHash` 并去掉 IPv4 校验。涉及文件：`LogValidationJob.java`、`AnomalyDetectionJob.java`、`BehaviorAnomalyJob.java`、`CepPartialMatchFunction.java`、Avro `security-event.avsc`。未改 Java **禁止** 把 `srcIp` 变成密文。

#### 6.2.4 Kafka / nginx（9092 不 flip；8001 密评关闭）

- L0：不改 broker 证书；Python/Flink 仍 `kafka:9092` PLAINTEXT。
- L1：`docker-compose.gm.yml` **新增** listener `SSL://kafka:9096`（RSA TLS1.3 过渡或 Tongsuo SM2 证书）。**不修改** `PLAINTEXT://kafka:9092`。opt-in 客户端把 `SHARED_MEMORY_KAFKA_BOOTSTRAP=kafka:9096` 并配置 `security_protocol=SSL`。Flink / schema-registry / kafka-ui / `edr_adapter` / `suricata_connector` **默认仍 9092**，直到各自 PR 显式切换。
- 外网 9093：L1 可将 `KAFKA_SSL_CLIENT_AUTH` 从 `none` 改为 `required`（已有 `client-*.pem`），与 9092 无关。
- SCRAM-SHA-512 不是国密，L1 材料写「高强度协议 + 应用层 SM4」。

nginx 双栈：`:443` TLS1.3；`:4443` GMTLS。**禁止 GMTLS 失败回落 HTTP。** 允许浏览器走 TLS1.3。密评 overlay：

- frontend 3001→443（或保持 3001 映射 443）
- **宿主 `8001:8000` 删除**（`ports: []` 覆盖）；验收：`docker compose -f docker-compose.yml -f docker-compose.gm.yml port backend 8000` 失败或无 8001

#### 6.2.5 审计链（并发、truncate、迁移）

增列（`init.sql` **和** `models._migrate_existing_tables` 的 `ALTER TABLE ... IF NOT EXISTS`，本仓库无 Alembic，pgdata 存量只走后者）：

```
chain_epoch INTEGER NOT NULL DEFAULT 0
seq         BIGINT                  -- epoch 内单调，顾问锁下分配
entry_hash  CHAR(64)
prev_hash   CHAR(64)
key_id      VARCHAR(64)
```

新表 `audit_trail_anchors(id, chain_epoch, last_seq, last_hash, sig, created_at)`。

启用时 `chain_epoch=1`；历史行 `epoch=0` 不参与链、不回填（避免并发停写）。

**哈希输入必须等于落库字节**：先 `_truncate(before/after)`、`reason[:2000]`、`user_agent[:200]`，再

```
canonical = json.dumps(
  {"actor", "actor_role", "action", "target_type", "target_id",
   "before", "after", "reason", "created_at"},
  ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
entry_hash = SM3( bytes.fromhex(prev_hash) || utf8(canonical) ).hex()
```

`created_at` 用已写入行的 UTC `isoformat`。

**并发**：写入前 `SELECT pg_advisory_xact_lock(hashtext('audit_chain')::bigint, chain_epoch)`（同一事务内取 `MAX(seq) WHERE epoch=?` → `prev_hash` → INSERT）。多 worker 安全。SQLite 测试用文件锁或单线程。

锚点：每 `SHARED_MEMORY_AUDIT_ANCHOR_EVERY_N`（默认 1000）条或每小时，`sm2_sign(audit-sm2, last_hash||ts)`。

**Q10 flag**：`SHARED_MEMORY_AUDIT_FAIL_CLOSED_ACTIONS` 默认空=全 fail-open。密评示例：`case.*,order.*,rule.*,asset.*,source.*`。匹配的 `action` 在 persist 失败时抛给 API；ingest / kafka 消费者 / `log_action_sync` 不匹配则仍进 500 缓冲。缓冲条目带 `hmac_sm3(field-mac, canonical)`。

校验：`python -m backend.tools.verify_audit_chain`。

#### 6.2.6 MCP SM2（可选，非阻塞）

若做：在 `McpGuardServer.call_tool` 通过 4 层 + 行为签名之后、execute 之前，对 `canonical(tool_name, arguments, caller, trace_id)` 做 SM2 签名写入 `tool_call_log`。这解决 **抗抵赖**，不解决「像不像平时」。默认 flag 关，避免和 UEBA PR 缠在一起。

---

### 6.3 国密替换范围图

```mermaid
flowchart LR
  subgraph in_scope ["本方案范围内"]
    JWT[JWT HS256 → SM2-JWS]
    FC[Fernet → SM4-CBC+HMAC-SM3]
    AT[audit_trail → SM3 链]
    LLM[LLM httpx → QuoteEnvelope + SM 会话]
    CACHE[MD5 cache → SM3 / SM4ENC]
    NGX[nginx 80 + 宿主8001 → 双栈且关闭8001]
    KFK[Kafka 字段；L1 新增 9096]
  end

  subgraph out_scope ["明确不做"]
    FL[Flink 进 TEE]
    PGTEE[PG 进 TEE]
    QD[Qdrant 国产替代]
    BCRYPT[bcrypt → SM3 口令]
    BAK[异地备份 30/100km]
  end

  subgraph optional ["可选"]
    MCP[MCP 调用 SM2 签名]
    EMB[Embedding 同 TEE]
  end
```

### 6.4 LLM 请求时序（证明 + SM）

```mermaid
sequenceDiagram
  participant Agent as Agent / llm_enhancer
  participant C as LLMClient
  participant G as TeeAttestationGuard
  participant R as RAS
  participant S as SmSessionCodec
  participant T as TEE 推理网关
  participant V as vLLM
  participant A as audit_trail

  Agent->>C: chat(messages)
  C->>C: SM3 缓存键
  alt cache hit
    C-->>Agent: cached completion
  else miss
    C->>G: ensure_decision(model)
    alt 决策缓存命中
      G-->>C: ok reused
    else 缓存过期
      G->>G: new 32B nonce
      G->>T: GET /attestation?nonce
      T->>R: QuoteEnvelope
      R-->>G: verify claim_hash in REPORTDATA
    end
    alt TEE_REQUIRED and fail
      G-->>C: AttestationError
      C->>A: log llm.attestation_fail
      C-->>Agent: fallback JSON
    else ok
      C->>S: wrap 整个 payload JSON
      C->>T: POST /v1/chat/completions  v=1 记录
      T->>T: 解 wk/blob + 重放窗
      T->>V: infer
      V-->>T: completion
      T-->>C: wrapped response
      C->>S: unwrap
      C->>A: transcript SM3 + envelope_id
      C-->>Agent: text
    end
  end
```

---

## 7. 密码应用方案（密评材料骨架）

本节可直接拆进《商用密码应用方案》。L0 提交时必须在封面标注 **「软件密码模块，未取得商密产品认证，仅用于开发演示」**。

### 7.1 密码应用技术架构

```
[用户浏览器] --TLS1.3 或 GMTLS-- [nginx 双栈]
        | 应用层 SM（重要操作，L1）
        v
[backend] --SDF GM/T 0018-- [密码机]
    |  SM4-CBC+HMAC-SM3 字段
    +---- Kafka :9092 明文 / :9096 SSL(opt-in) ---- Flink ---- PG
    |  SM3 审计链 + SM2 锚
    +---- Redis（SM4ENC 缓存或关闭）
    |  SM 会话 v=1 + QuoteEnvelope
    v
[TEE 推理网关 / mock_gateway] -- vLLM -- GPU CC
```

### 7.2 算法表

| 算法 | 标准 | 用途 | 密钥长度 | 实现（L0 / 生产） |
|------|------|------|----------|-------------------|
| SM2 | GB/T 32918；用户标识 GB/T 35276 | JWT、审计锚、会话 `wk`、（可选）MCP | 256-bit 曲线 | `gmssl==3.2.2` / SDF |
| SM3 | GB/T 32905 | 审计链、缓存键、transcript、HMAC | 256-bit 摘要 | 同上 |
| SM4 分组 | GB/T 32907 | 分组密码本身（ECB 禁止） | 128-bit | 同上 |
| SM4-CBC + HMAC-SM3 | 分组 GB/T 32907；HMAC 按 GM/T 0004 族 / 产品说明书 | **L0 字段、会话 blob、缓存值** | SM4-128 + SM3-256 | `gmssl` CBC；HMAC 自 SM3 构造 |
| SM4-GCM | 分组 GB/T 32907；**模式** GB/T 36624（AEAD） | **仅 L1+** 且产品证书写明 GCM | 128-bit + 128-bit tag | Tongsuo / 密码机；L0 Protocol 不包含 |
| 过渡 AES-128（Fernet） | 仅解密历史 `ENC:` | 迁移期 | 128-bit | `cryptography`，密评模式禁用加密路径 |
| 过渡 HS256 | RFC 7518 | 迁移期 JWT | ≥256-bit secret | PyJWT，密评模式禁用 |
| 过渡 RSA-2048 证书 | Kafka/可能的 nginx | L1 前 TLS | 2048 | OpenSSL 自签，密评须替换或双证书 |
| bcrypt | 口令存储 | 登录 | — | 保持 |

禁止：MD5（缓存键，含 `llm_enhancer._biz_cache_key`）、DES/3DES、ECB、RSA-1024、自写 SM4 轮函数或 GHASH。

### 7.3 协议表

| 协议 | 标准 | 端点 | 阶段 |
|------|------|------|------|
| HTTPS TLS1.3 | IETF | 浏览器 ↔ nginx | L1 起，管理面允许 |
| TLCP/GMTLS | GM/T 0024、GB/T 38636 | 国密客户端 ↔ nginx；backend ↔ TEE 网关 | L1/L2 |
| 应用层 SM 会话 v=1 | 本项目规范 §6.1.3（底层 SM2 加密 + SM4-CBC + HMAC-SM3） | `LLMClient` ↔ 网关/`mock_gateway` | L0-contract 起 |
| Kafka SASL_SSL | TLS + SCRAM-SHA-512 | 外部 9093 | 现状；L1 加客户端证 |
| Kafka 内网 TLS | TLS1.3 | **新增** backend opt-in ↔ `:9096`；9092 保持 PLAINTEXT | L1 |
| SDF | GM/T 0018 | backend ↔ 密码机 | L1 |

自有 SM 会话不是已经认证的「密码协议产品」。密评访谈时要准备：要么升级为 GMTLS（协议产品有证），要么说明会话只是认证算法的应用封装、密钥来自有证模块。

### 7.4 密钥表

| 密钥 | 算法 | 产生 | 存储 | 使用实体 | 轮换 | 销毁 |
|------|------|------|------|----------|------|------|
| JWT 签名 | SM2 或 HMAC-SM3 | 密码机 | 密码机 | backend `auth.py` | 90 天或事件触发 | 模块内销毁 + 旧钥只验不签 |
| 字段加密 `field-sm4` / `field-mac` | SM4-CBC + HMAC-SM3 | SDF `GenerateKey` / 开发 env | 密码机 / 进程 | field_cipher | 90 天，kid 在 blob | 覆写 |
| LLM 会话 `Ks` | SM4 临时 | backend RNG，SM2 加密给网关 | 进程内存，≤1h | LLMClient、网关 | 每 sid | 进程退出清零 |
| 审计锚 | SM2 | 密码机 | 密码机 | audit_trail | 年 | 归档后销毁 |
| TEE 证明根 | 厂商 | 硬件 | CPU/GPU fuses | RAS | 固件 | 不可 |
| 模型度量 | SM3 | 构建管道 | PG `model_measurements` | Guard | 随模型版本 | 旧版本保留审计 |
| 迁移 Fernet | AES | 原 env | env，密评禁用 | 只读解密 | 停止产生新 ENC: | 解密重加密后删除 |
| LLM API Bearer | 随机 | 配置 | env / 密码机 | 过渡云 endpoint | — | 切私有化后作废 |

### 7.5 密钥生命周期

1. **生成**: 生产禁止 `Fernet.generate_key()` 贴进 `.env`。必须 `SDF_GenerateKey` 或厂商工具，审计记 `key_id` 不记材料。
2. **存储**: 软件后端仅开发；生产私钥不出模块。PIN（`SHARED_MEMORY_SDF_PIN`）仍是编排秘密，密评访谈须说明双人管 PIN。
3. **分发**: `SHARED_MEMORY_SDF_LIBRARY`、`SHARED_MEMORY_SDF_DEVICE`，无 PEM 进 git。
4. **轮换**: JWT `kid`；字段 `kid` 在 `SM4ENC:` blob；审计链 `key_id` 列。
5. **销毁**: SDF 销毁对象；env 旧值从编排删除；Redis `llmcache:*` / `embed_cache:*` FLUSH。

### 7.6 密码产品清单（切换门槛）

| 阶段 | 产品 | 认证 | 用途 | 切换门槛 |
|------|------|------|------|----------|
| L0 开发 | PyPI `gmssl==3.2.2` | **无** | 功能与 KAT（CBC/SM2/SM3） | 禁止出现在密评申请「密码产品」表 |
| L0 开发 | 现有 `cryptography` | 无（且非国密） | 解密历史 Fernet | 密评模式不调用 encrypt |
| L1 | Tongsuo 发行版（需确认是否带商密证） | 视采购批次 | nginx / 可选 Kafka Java provider | 有证才写进申请表 |
| L1/L2 | 三未信安 / 江南天安 / 渔翁 等服务器密码机 | 商密产品认证证书（型号以合同为准） | SM2/3/4、RNG；**SDF 最小集联调** | 合同 + 证书复印件 + SDF 探针绿；**不**把 SoftHSM 当门槛 |
| L2 | 海光 CSV 平台 / 机密计算云实例 | 若有网安/商密相关认证则附 | 运算环境 | 测量值基线备案 |
| L2 备 | Intel TDX 云实例 + NVIDIA CC | 海外认证为主 | 非信创部署 | 不进政府采购材料主路径 |

**切换门槛（写进运维手册）**: `SHARED_MEMORY_CRYPTO_BACKEND=sdf` 且 `SHARED_MEMORY_ENV_NAME=prod` 时 software 路径拒绝启动。探针 `GET /api/health/crypto` 返回 `backend=sdf|software, jwt_alg, tee, field_cipher_mode`（无 PIN）。

### 7.7 残留信息

| 残留 | 当前 | 密评模式 |
|------|------|----------|
| `LLMClient._response_cache` | 明文 dict，>5000 淘汰 | 不缓存明文；只缓存 SM4 blob 或禁用 |
| Redis `llmcache:*` | 明文，TTL 24h，键 MD5 | 键 `llmcache:sm3:...`；值 SM4ENC；或 `SHARED_MEMORY_LLM_CACHE_ENCRYPT=true` / 关缓存 |
| Redis `embed_cache:*` | 明文向量，键 MD5 | 同左策略 |
| `llm_enhancer` 业务缓存 | `_biz_cache_key` MD5 | PR6 改 SM3；值策略同 llmcache |
| `audit_trail` fallback 500 | 明文内存 | HMAC 或 fail-closed |
| httpx 日志 | 可能打 URL | 禁止 log messages/body |
| TEE 内 vLLM prefix cache | 在 TCB 内 | 允许；客户机销毁时由 CSV/TDX 内存隔离保证 |
| Kafka 磁盘 7 天 | 可能明文 | 字段加密后落盘为密文；旧 segment 滚动淘汰 |

---

## 8. API / 接口 / 数据模型

### 8.1 配置表（**仅** `SHARED_MEMORY_*`；pydantic `env_prefix`）

现有 `Settings.Config.env_prefix = "SHARED_MEMORY_"`。回滚说明、compose、手册 **禁止** 使用无前缀名（`CRYPTO_BACKEND`、`TEE_REQUIRED`、`JWT_ALG`、`ENV=prod`、`LLM_CACHE=off`、`FIELD_CIPHER_ENCRYPT_RAW` 一律无效）。

| pydantic 字段 | 环境变量 | 默认 | 密评 overlay（`docker-compose.gm.yml`） |
|---------------|----------|------|------------------------------------------|
| `crypto_backend` | `SHARED_MEMORY_CRYPTO_BACKEND` | `software` | `sdf` |
| `sdf_library` | `SHARED_MEMORY_SDF_LIBRARY` | `""` | 厂商 `.so` 路径 |
| `sdf_device` | `SHARED_MEMORY_SDF_DEVICE` | `""` | 设备名 |
| `sdf_pin` | `SHARED_MEMORY_SDF_PIN` | `""` | 编排注入，禁止进镜像 |
| `jwt_alg` | `SHARED_MEMORY_JWT_ALG` | `HS256` | `SM2`（Q2 未决则保持 HS256） |
| `jwt_accept` | `SHARED_MEMORY_JWT_ACCEPT` | `HS256` | `SM2` |
| `jwt_sm2_public` | `SHARED_MEMORY_JWT_SM2_PUBLIC` | `""` | PEM 或 `04\|\|X\|\|Y` |
| `jwt_sm2_private` | `SHARED_MEMORY_JWT_SM2_PRIVATE` | `""` | **仅 software 开发** |
| `tee_required` | `SHARED_MEMORY_TEE_REQUIRED` | `false` | `true` |
| `tee_ras_url` | `SHARED_MEMORY_TEE_RAS_URL` | `""` | RAS URL |
| `tee_quote_ttl_s` | `SHARED_MEMORY_TEE_QUOTE_TTL_S` | `120` | `120` |
| `tee_cpu_only_model` | `SHARED_MEMORY_TEE_CPU_ONLY_MODEL` | `false` | `false` |
| `tee_fixture_mac_key` | `SHARED_MEMORY_TEE_FIXTURE_MAC_KEY` | `""` | 空（禁止生产 fixture） |
| `llm_sm_session` | `SHARED_MEMORY_LLM_SM_SESSION` | `false` | `true` |
| `llm_gateway_sm2_pub` | `SHARED_MEMORY_LLM_GATEWAY_SM2_PUB` | `""` | 网关公钥 |
| `llm_cache_hash` | `SHARED_MEMORY_LLM_CACHE_HASH` | `md5` | `sm3` |
| `llm_cache_encrypt` | `SHARED_MEMORY_LLM_CACHE_ENCRYPT` | `false` | `true` |
| `audit_chain_enabled` | `SHARED_MEMORY_AUDIT_CHAIN_ENABLED` | `false` | `true` |
| `audit_fail_closed_actions` | `SHARED_MEMORY_AUDIT_FAIL_CLOSED_ACTIONS` | `""` | `case.*,order.*,rule.*,asset.*,source.*` |
| `audit_anchor_every_n` | `SHARED_MEMORY_AUDIT_ANCHOR_EVERY_N` | `1000` | `1000` |
| `field_cipher_mode` | `SHARED_MEMORY_FIELD_CIPHER_MODE` | `off` | `sm4` |
| `field_encryption_key` | `SHARED_MEMORY_FIELD_ENCRYPTION_KEY` | `""` | 空。**仅**历史 Fernet `ENC:` 解密，不是 SM4 密钥 |
| `gm_field_sm4_key` | `SHARED_MEMORY_GM_FIELD_SM4_KEY` | `""` | 空（走 SDF `field-sm4`）。**L0 software 必填**：32 hex（16 B） |
| `gm_field_mac_key` | `SHARED_MEMORY_GM_FIELD_MAC_KEY` | `""` | 空（走 SDF `field-mac`）。**L0 software 必填**：64 hex（32 B） |
| `gm_audit_sm2_private` | `SHARED_MEMORY_GM_AUDIT_SM2_PRIVATE` | `""` | 空（走 SDF `audit-sm2`）。**L0 software + 开链/锚点必填**：PEM |
| `field_cipher_encrypt_raw` | `SHARED_MEMORY_FIELD_CIPHER_ENCRYPT_RAW` | `false` | `false` 直至 Q5 |
| `field_cipher_reject_legacy` | `SHARED_MEMORY_FIELD_CIPHER_REJECT_LEGACY` | `false` | `true` |
| `mcp_sm2_sign` | `SHARED_MEMORY_MCP_SM2_SIGN` | `false` | `false` |
| `env_name` | `SHARED_MEMORY_ENV_NAME` | `dev` | `prod` |

`field_cipher.configure(settings)` 在 lifespan **就地**更新单例（见 §6.2.3）；**禁止**换对象。`auth.create_access_token` 每次读 `settings.jwt_alg`。

启动自检（lifespan，PR3）：`field_cipher_mode in (sm4, dual)` 且 `crypto_backend=software` 时，空的 `gm_field_sm4_key` / `gm_field_mac_key` → 拒绝启动。`audit_chain_enabled=true` 且 software 且需要 SM2 锚时，空的 `gm_audit_sm2_private` → 拒绝启动。`mode=off` 不检查 GM 密钥。

### 8.2 健康与合规探针

`GET /api/health/crypto`（`RequireRole("admin")`）：`backend`、`jwt_alg`、`jwt_accept`、`tee_required`、`tee_decision_age_s`、`field_cipher_mode`、`audit_chain_enabled`、`llm_sm_session`。不返回 PIN、密钥、quote、`wk`。`env_name=prod` 且 `backend=software` → 该端点 503 且进程本应已拒绝启动。

### 8.3 数据模型迁移

无 Alembic。PR4 必须同时改：

1. `init.sql`（空卷）
2. `backend/models.py` `AuditTrail` 列
3. `backend/models.py` `_migrate_existing_tables`：`ALTER TABLE audit_trail ADD COLUMN IF NOT EXISTS chain_epoch ...` 等；`CREATE TABLE IF NOT EXISTS audit_trail_anchors ...`；`CREATE TABLE IF NOT EXISTS model_measurements ...`
4. `AgentTrace` 增列 `attestation_id VARCHAR(64)`、`transcript_sm3 CHAR(64)`、`tee_required BOOLEAN`，同样走 `_migrate_existing_tables`；`trace_hook._lazy_recorder` 把 kwargs 写入这些列（未知 kwargs 仍忽略）

`chain_epoch`：启用=1，旧行=0 不参与。不做在线回填。

### 8.4 `produce_raw_batch`

**默认不加密**（与今天字节级一致）。仅当 `SHARED_MEMORY_FIELD_CIPHER_ENCRYPT_RAW=true` **且** Q5 已改 Java/`srcIpHash` 后开启。PR9 验收：flag 默认路径 payload == 现网。

---

## 9. 分阶段（代码 vs 采购）

硬件采购、密码机到货、CSV 机器、GPU CC 驱动 **不是代码 PR 能关闭的**。下面按「人周」只估代码；采购并行。

### L0-demo — 1–2 人周（可演示，不能申报密评，**不含** SM2 签发与真会话对端）

PR1 + PR2 + PR3 + PR4（flag 默认关）+ PR5（只 HS256 flag 管道）+ PR6（MD5/SM3 双读，encrypt 默认关）+ PR13。

演示：注入 `SHARED_MEMORY_GM_FIELD_SM4_KEY` / `GM_FIELD_MAC_KEY` 后健康探针显示 `backend=software`；KAT 绿；`field_cipher_mode=sm4` 往返（Kafka 持有的仍是同一 `field_cipher` 对象）；篡改 audit 被 verify 抓住（测 fixture 库，不必开生产 flag）。缺 GM 密钥则启动失败，不会静默明文。

### L0-contract — 另计人周（线格式已在本文冻结，实现才算「提示词不明文出界」）

PR7（`SmSessionCodec` + `mock_gateway.py`）+ PR8（`QuoteEnvelope` fixture）。Q2=SM2 后打开 PR5 的 `Sm2Algorithm` 签发。

### L1 — Tongsuo + SDF + 应用层 SM（仍可无 TEE）

- nginx Tongsuo 双证书；`docker-compose.gm.yml`：**不发布宿主 8001**；Kafka **新增 9096 SSL**，9092 不动。
- `SdfGmBackend`；SoftHSM job 仅 AES 冒烟。
- 会话接到私有化 HTTP 网关；Redis 缓存 SM4ENC。
- 密评骨架填产品型号。

### L2 — TEE 推理网关 + fail-closed

- 真 CSV/TDX quote；`gpu_cc_policy!=verified` 拒 GPU 模型。
- `SHARED_MEMORY_ENV_NAME=prod` + software → 拒绝启动。
- 无自有机器走方案 B。

**Rollback（全是 `SHARED_MEMORY_*`）**:

- `SHARED_MEMORY_FIELD_CIPHER_MODE=off|fernet`（密评禁止 fernet 新写）
- `SHARED_MEMORY_JWT_ALG=HS256` 且 `SHARED_MEMORY_JWT_ACCEPT=HS256`
- `SHARED_MEMORY_AUDIT_CHAIN_ENABLED=false`
- `SHARED_MEMORY_TEE_REQUIRED=false`、`SHARED_MEMORY_LLM_SM_SESSION=false`
- `SHARED_MEMORY_CRYPTO_BACKEND=software`（仅非 prod）

---

## 10. 测试

| 测试 | 内容 | 环境 |
|------|------|------|
| KAT SM3 | GB/T 32905 示例：`abc` → `66c7f0f4…4ba8e0` | CI |
| KAT SM4 | GB/T 32907 附录 **CBC** 向量（不用 32907 冒充 GCM） | CI |
| KAT HMAC-SM3 | 固定 key/msg 向量（实现锁定） | CI |
| KAT SM2 | GB/T 32918 签名验签；ZA 默认 ID | CI |
| SM2-JWS | 固定 header/payload → 已知 r\|\|s；未知 alg 在选钥前 401；HS256 密钥不得验 SM2 | CI |
| field_cipher 兼容 | `ENC:` 仍能解；新写 `SM4ENC:` v0x01 布局；mode=off 请求字节与现网一致 | CI |
| audit 链 | 顺序写入 verify ok；改 `reason` break；并发两协程不叉；epoch=0 跳过；hash 用 truncate 后 JSON | CI |
| JWT flag | 默认仍签发 HS256；ACCEPT 不含 HS256 时旧 token 401 | CI |
| LLMClient 抽出 | `test_emb_backfill_and_llm_redis.py`、`test_token_cost.py`、`test_trace_degraded.py`、`test_llm_cache_and_embedding.py` 绿 | CI |
| SM 会话 | flag 关：httpx body == 现网 JSON（含 `reasoning_split`）；flag 开：`mock_gateway` 能解并回包 | CI |
| 证明 fail-closed | fixture 错 model / `gpu_cc_policy=none` + GPU 模型 / HMAC 坏 → **零** outbound | CI |
| 决策缓存 | 第二次 chat 不换 nonce、不二次 GET /attestation | CI |
| 无真 TEE | 禁止 `/dev/tdx-guest` | CI |
| 降级 | `SHARED_MEMORY_TEE_REQUIRED=true` 时公网 `llm_base_url` 也不发 | CI |
| raw 加密 | 默认 `produce_raw_batch` 字节级与现网一致 | CI |

不做：在 CI 跑 vLLM、买密码机、起海光虚拟机。

---

## 11. 可观测性

现有：`metrics.inc_llm_tokens`、`trace_hook.emit_trace` → `AgentTrace`（tokens/latency/cache_hit/status）。扩展：

| 指标 | 类型 | 告警 |
|------|------|------|
| `tee_attestation_ok` / `_fail` | counter | fail 且 `TEE_REQUIRED` → 立即 |
| `tee_decision_age_seconds` | gauge | > TTL → warn（决策缓存，不是 nonce 年龄） |
| `gm_op_latency_ms{alg,op,backend}` | histogram | p95 预算 |
| `field_cipher_legacy_hits` | counter | 密评模式 >0 持续 → warn |
| `jwt_alg_issued{alg}` | counter | 密评出现 HS256 → 立即 |
| `audit_chain_break` | counter | 立即 |
| `llm_transport{mode}` | counter | — |
| `crypto_backend{name}` | gauge | production+software → 立即 |

`emit_trace` 增加并 **持久化到 `AgentTrace` 新列**（PR7/PR8 改 `models.AgentTrace` + `_migrate_existing_tables` + `_lazy_recorder`）：`attestation_id`、`transcript_sm3`、`tee_required`。不写 prompt。失败走 `status=degraded`。

日志：禁止打印 quote 原文、PIN、SM4 密钥、messages。证明失败打 `model_id` 与 error class。

---

## 12. 风险

| 严重度 | 风险 | 缓解 |
|--------|------|------|
| P0 | 加密 raw topic 但 Flink 不会解 → 检测全停 | flag 默认关；先影子双写；Q5 未决不合并强制加密 |
| P0 | 密评模式 software 后端蒙混过关 | 启动自检 + 健康探针告警 |
| P0 | 声称 CPU TEE 保护了 GPU 模型 | 文档与 Guard 双重拒绝无 GPU CC 的生产模型 |
| P1 | 浏览器 GMTLS 不可用导致「国密 HTTPS」演示失败 | 管理面 TLS1.3 + 应用层 SM；演示改用 `curl --tls-suite` / 奇安信浏览器 |
| P1 | 软件 SM2/SM4 性能拖垮 ingest | 字段加密只覆盖 ENCRYPT_FIELDS；会话密钥 AES-NI 对等的 SM4 指令或密码机 |
| P1 | 审计 fail-closed 把 SOC 写接口打满 5xx | 默认 fail-open；密评环境才开；缓冲 HMAC |
| P1 | 自建 RAS 被伪造 | 根证书来自 CPU 厂商；nonce；测量允许列表 |
| P2 | PyJWT 自定义 `alg=SM2` 与生态不兼容 | 仅本系统签发/验证；不接第三方 IdP |
| P2 | `gmssl` 包质量/许可证 | 抽象层可换 Tongsuo；L0 锁定版本 |
| P2 | 演示分低（矩阵=1） | 成功标准走对照表与 KAT，不走 UI 特效 |
| P2 | 采购周期长于揭榜答辩 | L0 先演示软件国密 + mock attestation；口头承认未过密评 |

---

## 13. 替代方案

| 方案 | 做法 | 优点 | 缺点 | 过等保/密评 |
|------|------|------|------|-------------|
| **A. 仅国密、不做 TEE** | L0+L1 停在 SDF + Tongsuo | 便宜、无 GPU CC 依赖 | 云 MaaS 或宿主机仍能读推理内存；「运算环境保密 / 可信验证」空 | 通信/存储项能做一部分；**不能**承诺 AI 数据不出现在明文内存 |
| **B. 云厂商机密计算托管 vLLM** | 阿里云/火山/腾讯等 CSV 或 TDX 实例；本仓库只做 Guard + 国密 | 无自购 CSV 机器；上市快 | 信任云 RAS；GPU CC 仍取决于实例规格；数据在云 | 国内云+商密模块有机会；须把云产品证书附进密评 |
| **C. 全栈进 TEE** | PG/Kafka/Flink/backend 全放机密虚机 | 叙事完整 | 不可运维、性能与生态（Kafka JVM、Flink、Qdrant）不现实；仍解不了 GPU | 过度设计，评审会问落地 |
| **D. 海外 AES-GCM + TLS1.3 + 仅 Intel TDX** | 标准机密计算故事 | 出海、论文、NVIDIA CC 文档全 | 国内密评算法不合规；政府采购 TDX 风险 | 国内密评不行 |

**推荐**: 揭榜挂帅走 **A 的 L0 立刻做 + L1 采购并行 + L2 用 CSV（有机器）或 B（无机器）**。D 只出现在海外交付分支。C 拒绝。

这与创新矩阵「不要单靠 #10 撑创新」一致：L0 是补漏 PR；L2 是客户有机密计算预算时才上的加分。

---

## 14. 文件级钩子

| 文件 | 现状 | 变更 |
|------|------|------|
| `backend/llm_client.py` | **不存在** | PR1 新建：只迁 `LLMClient`/`CostTracker`/`cost_tracker`/`estimate_tokens`/`_extract_text_content` |
| `backend/summary_compression.py` | 两客户端定义于此 | re-export 上述；**`EmbeddingClient` 留此** |
| `backend/crypto/*` | 不存在 | Protocol + `SoftwareGmBackend` + 以后 `SdfGmBackend` |
| `backend/crypto/session.py` | 不存在 | SM 会话 v=1 |
| `backend/tee/mock_gateway.py` | 不存在 | PR7 解密对端 |
| `backend/tee/attestation.py` / `quotes.py` / `fixtures/` | 不存在 | `QuoteEnvelope` |
| `backend/field_cipher.py` | import 时 Fernet | **同一单例** + `configure(settings)`；`SM4ENC:` v0x01 |
| `backend/auth.py` | 模块级 `ALGORITHM` | 删除常量；读 settings |
| `backend/auth_sm2.py` | 不存在 | `Sm2Algorithm`；Q2 前不签发 |
| `backend/audit_trail.py` | 无链 | epoch 顾问锁；truncate 后哈希 |
| `backend/models.py` | `AuditTrail`/`AgentTrace`/`_migrate_existing_tables` | 加列 + ALTER |
| `init.sql` | 无 hash 列 | 与 migrate 同步 |
| `backend/config.py` | 无 crypto 项 | §8.1 全表 |
| `backend/llm_enhancer.py` | `_biz_cache_key` MD5 | PR6 改 SM3 |
| `backend/trace_hook.py` | 固定列 | 持久化 attestation 字段 |
| `backend/kafka_producer.py` | raw 不加密 | 仅 PR9 flag |
| `backend/app.py` | `set_redis` / `cost_tracker` | lifespan `field_cipher.configure(settings)` + crypto 自检（缺 GM 密钥 abort） |
| `backend/requirements.txt` | 无 gmssl | `gmssl==3.2.2` |
| 单测四件套 | import `summary_compression` | re-export 保持绿 |
| `docker-compose.gm.yml` | 不存在 | 9096 SSL；**ports 覆盖掉 8001** |
| `flink-jobs/.../KafkaConfig.java` | 无 SSL | L1 **不**默认改；Q5/9096 opt-in 才动 |
| `mcp_guard/guard_server.py` | 行为签名 | 仅 `mcp_sm2_sign` |
| `cad.py` | 只查 api_key | TEE_REQUIRED 但 RAS 不可达 |

调用方不改业务：`agents/*`、`rag/{evidence_verifier,query_transform,retriever}.py`、`self_play/{red_agent,blue_learner,reviewer}.py`、`llm_enhancer.py`、`post_mortem_service.py`、`watchdog.py` 继续 `summary.llm.chat`。

---

## 15. 成功标准（做到才算落地）

- [ ] 仓库出现 `backend/llm_client.py`，`summary_compression.LLMClient is llm_client.LLMClient`
- [ ] GM/T 向量单测在无硬件 CI 全绿
- [ ] `field_cipher_mode=sm4` 且已配 `GM_FIELD_SM4_KEY`/`GM_FIELD_MAC_KEY` 时新数据无 `ENC:` 前缀；旧 `ENC:` 仍能解；缺密钥启动失败；`configure` 不改变单例 `id()`
- [ ] 审计链篡改检测单测绿；默认 flag 关时现有 `test_p0_ops_modules.py` 审计用例仍绿
- [ ] Q2=SM2 且 `SHARED_MEMORY_JWT_ACCEPT=SM2` 时拒绝 HS256；默认仍签发 HS256
- [ ] mock attestation 失败时 httpx **零调用**；决策缓存第二次不换 nonce
- [ ] `SHARED_MEMORY_LLM_SM_SESSION=true` 时 `mock_gateway` 能解整包 JSON（含 `reasoning_split`）；flag 关时 body 与现网逐字节一致
- [ ] `SHARED_MEMORY_CRYPTO_BACKEND=software` 的健康接口写明不能密评；`SHARED_MEMORY_ENV_NAME=prod` 拒绝 software
- [ ] 等保/密评对照表「不覆盖」行未改成「已满足」
- [ ] `SHARED_MEMORY_TEE_REQUIRED=false` 时现网 LLM 行为与今天一致

---

## Key Decisions

| # | 决策 | 选择 | 理由 |
|---|------|------|------|
| D1 | 用户点名的 `llm_client.py` | **先建文件再加安全钩子** | 文件不存在；抽出是独立可审 PR，避免安全改动和搬家混在一起 |
| D2 | TEE 主路径 | **海光 CSV 主，TDX+NVIDIA CC 备** | 政府采购与供应链；TDX 不能当政府唯一方案 |
| D3 | GPU | **无 GPU CC 不得宣称运算环境保密；密评模式缺 report 则 fail-closed** | CPU TEE 不管 HBM |
| D4 | v1 TCB 范围 | **只包推理网关 + vLLM** | Flink/PG/Kafka 进 TEE 不现实，也补不上 GPU 缺口 |
| D5 | 传输 | **v1 = SM2 加密随机 SM4 密钥 + CBC+HMAC wrap 整包 JSON；GMTLS 放 L1/L2** | 单 RTT、gmssl 能做；有 `mock_gateway` 才算交付 |
| D6 | 国密库 / 模式 | **L0 `gmssl==3.2.2` + SM4-CBC+HMAC-SM3；Protocol 无 GCM；L1 SDF（GM/T 0018）主，PKCS#11 厂商可选** | 纯 Python CI；`gmssl` 无 GCM；PKCS#11 1.4 无 SM |
| D7 | JWT | **剖面冻结为 §6.2.2 SM2-JWS；PR5 默认仍 HS256 + 拆掉 import 常量；Q2 未决不签发 SM2** | 线格式与产品开关分离 |
| D8 | 字段加密 | **`SM4ENC:` v0x01；单例 `configure` 就地更新，不换对象；raw 默认关** | Kafka 已 `import field_cipher`；换实例等于 flag 空转 |
| D9 | 审计 | **epoch 顾问锁；hash truncate 后字节；Q10=`audit_fail_closed_actions`；`_migrate_existing_tables`** | 并发与存量卷 |
| D10 | MCP SM2 | **默认不做** | 行为签名已落地 |
| D11 | 浏览器 GMTLS | **不作为 L0 交付** | 兼容性坑 |
| D12 | 节奏 | **L0-demo 1–2 人周 ≠ L0-contract** | 避免把 JWS/会话塞进「两周全绿」 |
| D13 | 口令哈希 | **保持 bcrypt** | 测评单元不同 |
| D14 | 云 mimo | **`TEE_REQUIRED` 禁止回落云 endpoint** | 否则证明形同虚设 |
| D15 | Embedding 出界 | **L0 接受讯飞 embedding；L1 同 Guard** | chat TEE 盖不住 |
| D16 | Kafka TLS | **新增 9096 SSL，不 flip 9092** | 保护 Flink/schema-registry/UI |
| D17 | 南北向 | **密评 overlay 不发布宿主 8001** | nginx 证书盖不住 FastAPI 旁路 |
| D18 | 证明缓存 | **决策缓存，禁止复用 nonce** | REPORTDATA 64B；backend 不在 TEE |
| D19 | `EmbeddingClient` | **PR1 不搬出 `summary_compression.py`** | 测试与职责边界 |

---

## Open Questions

工程已冻结、不再列为问题：L0 库=`gmssl==3.2.2`；模式=SM4-CBC+HMAC-SM3；HSM API=SDF 最小集；SM2-JWS 剖面=§6.2.2；会话=§6.1.3；QuoteEnvelope=§6.1.2。

| # | 问题 | 默认（未决前按此实现） | 备选 | 谁拍板 |
|---|------|------------------------|------|--------|
| Q1 | L2 硬件：自有海光 CSV，还是国内云 TDX/CSV？ | 可插拔 RAS URL + 测量允许列表，不绑厂商 SDK | 绑定某云 SDK | 采购 |
| Q2 | JWT **启用** SM2-JWS 还是继续 HS256 / 改 HMAC-SM3？ | **PR5 只交 flag + 仍签发 HS256**；剖面已按 SM2 写好 | 打开 `jwt_alg=SM2`；或改 HMAC-SM3（需另写剖面） | 密评咨询师 |
| Q3 | 密码机**品牌**（API 已冻结为 SDF） | 不写死品牌；联调走 §6.2.1 最小函数集 | 厂商私有 PKCS#11 适配 | 采购 |
| Q4 | 自建 RAS vs 云 attestation | PR8 fixture；L2 再接厂商 | 直接云 RAS | 安全架构 |
| Q5 | Flink raw：保持明文 `srcIp` / 上 `srcIpHash` / Java 解 SM4？ | **L0 不加密 raw**（PR9 flag 默认 false） | §6.2.3 盲化文件列表 | 数据面 |
| Q6 | 密评模式 LLM 缓存 | **开，SM3 键 + SM4ENC 值** | 关 | 运营 |
| Q7 | MCP SM2 抗抵赖 | **否** | 开 `mcp_sm2_sign` | 产品 |
| Q8 | 现场演示 GMTLS | **否** | 国密浏览器 | 演示 |
| Q9 | 私有化模型型号 | 度量进 `model_measurements`；不锁型号 | 继续云 mimo 则 L2 无意义 | 与 v6 候选表 |
| Q10 | 审计 fail-closed 范围 | **`audit_fail_closed_actions` 名单，默认空=全 open**；密评填 `case.*,order.*,...` | 全局 fail-closed | SOC 值班 |

Q2 阻塞 **签发** SM2（不阻塞 PR5 flag）。Q5 阻塞 PR9 开默认。Q1/Q3/Q9 是采购。

---

## PR Plan

默认 flag = 现网行为。每条可单独回滚。

**DAG（冻结）**:

```
PR13 ∥ PR1 ∥ PR2
PR2 → PR3 → PR6
PR2 → PR4
PR2 → PR5          # flag+HS256；SM2 签发等 Q2
PR1 → PR8          # 不依赖 PR2（fixture HMAC 可用测试键；合 PR2 后改走 GmCrypto）
PR1 + PR2 → PR7    # mock_gateway；transcript 列可先写 AgentTrace 不必等 PR4 链
PR2 → PR10
PR11 独立但必须列出全部 Kafka 客户端；验收含 8001 消失
PR3 + Q5 → PR9
PR8 → PR12
```

**L0-demo** = PR1–6 + 13。**L0-contract** = PR7 + PR8（+ Q2 后打开 SM2 签发）。

### PR1 — `feat(llm): extract LLMClient into backend/llm_client.py`

- **影响**: 新建 `llm_client.py`；`summary_compression.py` re-export；`EmbeddingClient` **不搬**。`app.py` 仍 `summary.llm.set_redis`。单测：`test_emb_backfill_and_llm_redis.py`、`test_llm_cache_and_embedding.py`、`test_token_cost.py`、`test_trace_degraded.py`（`_extract_text_content` / `CostTracker` 经 re-export）。
- **依赖**: 无
- **内容**: 零行为变化。禁止 TEE/国密。
- **验收**: 上述单测绿；`summary_compression.LLMClient is llm_client.LLMClient`。

### PR2 — `feat(crypto): GmCrypto SM4-CBC+HMAC-SM3 + KAT (gmssl==3.2.2)`

- **影响**: `backend/crypto/`；`requirements.txt`/`lock` 钉 `gmssl==3.2.2`；`config.py` `crypto_backend`。
- **依赖**: 无（∥ PR1）
- **内容**: Protocol **无** `sm4_gcm_*`。`SoftwareGmBackend` 标「不能密评」。无业务接入。
- **验收**: SM3/SM4-CBC/SM2/HMAC-SM3 KAT 绿。工厂在 `sdf` 未配置时 **报错** 不静默 software。

### PR3 — `feat(crypto): field_cipher SM4ENC v1 CBC+HMAC dual-read`

- **影响**: `field_cipher.py`、`config.py`、`app.py` lifespan、`tests/test_field_cipher.py`。
- **依赖**: PR2
- **内容**: 保留模块级 `field_cipher` 单例；新增 `configure`/`reset_from_settings` **就地**改 `_enabled`/`_mode`/密钥。lifespan 与测试只调用 `configure`，**禁止** `field_cipher = FieldCipher(...)` 换对象。§6.2.3 blob。**不改** `produce_raw_batch`。mode 默认 `off`。software + `mode=sm4` 缺 `SHARED_MEMORY_GM_FIELD_SM4_KEY` / `GM_FIELD_MAC_KEY` → 启动失败（单测覆盖）。
- **验收**: Fernet 旧向量能解；新向量锁定 hex；**mode=off 时 encrypt_message 输出 == 现网**（字节级）；`id(kafka 持有的 field_cipher) is id(field_cipher.field_cipher)` 在 `configure` 前后不变。

### PR4 — `feat(audit): SM3 chain with advisory lock + migrate`

- **影响**: `audit_trail.py`、`models.py`（`AuditTrail` **和** `_migrate_existing_tables`）、`init.sql`、`config.py`（含 `audit_fail_closed_actions`）、`test_p0_ops_modules.py`、新 chain 单测、`tools/verify_audit_chain.py`。
- **依赖**: PR2
- **内容**: epoch 顾问锁；hash **truncate 之后**；flag 默认关；Q10 名单。software 开链时读 `SHARED_MEMORY_GM_AUDIT_SM2_PRIVATE`，缺则 abort。
- **验收**: flag 关旧测试绿；并发两写不叉链；改 reason 则 break。

### PR5 — `feat(auth): JWT settings plumbing (HS256 only in this PR)`

- **影响**: `auth.py`（删除模块级 `ALGORITHM`/`SECRET_KEY`）、`routers/auth.py`、`config.py`、`auth_sm2.py`（类+向量，默认不注册签发）、JWT 单测。
- **依赖**: PR2（SM2 类）；**不**依赖 Q2 关闭即可合入
- **内容**: `jwt_alg`/`jwt_accept` 生效于 HS256。§6.2.2 剖面作为注释/未启用代码。未知 alg 在选钥前拒绝。
- **验收**: 默认 token 与现网可互换；`jwt_accept=SM2` 时 HS256 token 401；**本 PR 不要求签发 SM2**。字节级：默认 `jwt.encode` 算法名仍 HS256。

### PR6 — `feat(llm): SM3 cache keys + llm_enhancer MD5`

- **影响**: `llm_client.py`、`summary_compression.EmbeddingClient`、`llm_enhancer._biz_cache_key`、`config.py`、相关单测。
- **依赖**: PR1、PR2、PR3（encrypt 值复用 `SM4ENC:`）
- **内容**: `llm_cache_hash` 双读；`llm_cache_encrypt` 默认 false。enhancer MD5 → SM3（同 flag）。
- **验收**: 默认 md5 命中与现网一致（字节级 key 前缀 `llmcache:` 仍 32 hex MD5）。

### PR7 — `feat(llm): SmSessionCodec v1 + mock_gateway`

- **影响**: `crypto/session.py`、`tee/mock_gateway.py`、`llm_client.py`、`models.AgentTrace` + `_migrate_existing_tables` + `trace_hook`、`tests/test_sm_session_codec.py`。
- **依赖**: PR1、PR2（PR4 可选）
- **内容**: §6.1.3 整包 wrap；flag 默认关。
- **验收**: flag 关 body == 现网（含 `reasoning_split`）；flag 开 mock_gateway 解得原 JSON。

### PR8 — `feat(llm): TeeAttestationGuard + QuoteEnvelope fixtures`

- **影响**: `tee/attestation.py`、`tee/quotes.py`、`tee/fixtures/*.json`、`llm_client.py`、`config.py`、`cad.py`、`AgentTrace` 列（若 PR7 未加）、单测。
- **依赖**: PR1（可 ∥ PR2；fixture HMAC 测试键）
- **内容**: 决策缓存；`TEE_REQUIRED` 默认 false；GPU `none` fail-closed。
- **验收**: 坏 fixture → 零 httpx；第二次 chat 不重新取 nonce。

### PR9 — `feat(kafka): optional SM4 on produce_raw_batch (default off)`

- **影响**: `kafka_producer.py`；若 Q5=盲化：Flink `LogValidationJob`/`AnomalyDetectionJob`/`BehaviorAnomalyJob`/`CepPartialMatchFunction`、Avro。
- **依赖**: PR3、**Q5**
- **内容**: `SHARED_MEMORY_FIELD_CIPHER_ENCRYPT_RAW` 默认 false。
- **验收**: 默认 payload == 现网。

### PR10 — `feat(crypto): SdfGmBackend + health probe`

- **影响**: `crypto/sdf_backend.py`、`app.py` 启动自检、`routers` 健康接口。可选 SoftHSM job（AES-only skip SM）。
- **依赖**: PR2
- **内容**: GM/T 0018 最小集。`prod`+software 拒绝启动。
- **验收**: 无 `.so` 时错误明确；健康接口无 PIN。不把 SoftHSM 当 SM 联调。

### PR11 — `chore(compose): gm overlay — nginx dual-stack, Kafka :9096, drop host 8001`

- **影响**: `docker-compose.gm.yml`、`frontend/nginx-gm.conf`、`tools/gen-kafka-certs-sm2.sh`。文档列出仍走 9092 的客户端：`kafka_producer.py`、`kafka_consumer.py`、`edr_adapter.py`、`suricata_connector.py`、`KafkaConfig.java`、schema-registry、kafka-ui。**默认 `docker-compose.yml` 不改 9092。**
- **依赖**: 无代码强依赖；与 PR3 独立
- **内容**: 新增 9096；覆盖 `backend.ports` 为 `[]`（去掉 8001）；443/4443。
- **验收**: 默认 compose 不变；`docker compose -f docker-compose.yml -f docker-compose.gm.yml port backend 8000` 无宿主 8001。

### PR12 — `feat(tee): CSV/TDX overlay + model_measurements`

- **影响**: `docker-compose.tee.yml`、`model_measurements` 迁移、手册（GPU CC 残差）。
- **依赖**: PR8
- **内容**: 测量注入；无硬件可用 fixture RAS，材料标明模拟。
- **验收**: 测量不匹配 → 无 outbound。

### PR13 — `docs: 入库本方案`

- **影响**: `docs/upgrade-proposals/2026-q3-tee-gm-crypto.md`、`INDEX.md`、创新矩阵 #10 链接。
- **依赖**: 无（∥ PR1）
- **内容**: L0 ≠ 已过密评。
- **验收**: 封面有软件模块警告。

---

## References

- GB/T 22239-2019 网络安全等级保护基本要求（第三级）
- 《中华人民共和国密码法》
- GM/T 0054 信息系统密码应用基本要求；GM/T 0115 测评要求；GM/T 0116 测评过程指南
- GB/T 32918 SM2；GB/T 32905 SM3；GB/T 32907 SM4 分组；GB/T 36624 AEAD 模式；GB/T 35276 SM2 使用规范（默认用户标识）
- GM/T 0018 密码设备应用接口规范（SDF）；GM/T 0024 / GB/T 38636 TLCP/GMTLS
- RFC 7515 JWS compact
- 本仓库：`backend/summary_compression.py`、`backend/auth.py`、`backend/field_cipher.py`、`backend/audit_trail.py`、`backend/kafka_producer.py`、`backend/kafka_consumer.py`、`backend/config.py`、`frontend/nginx.conf`、`docker-compose.yml`、`tools/gen-kafka-certs.sh`、`backend/mcp_guard/guard_server.py`
- `docs/upgrade-proposals/2026-q3-tech-stack-upgrade-v5.md` §4.2（被取代的国密草图，无 TEE）
- `docs/upgrade-proposals/2026-q3-tech-stack-upgrade-v6.md` §4 等保三级 10 项自评
- `docs/upgrade-proposals/2026-q3-innovation-decision-matrix.md` #10
- `docs/upgrade-proposals/2026-q3-tool-behavior-signature.md`（MCP 行为签名，不重复）
- v5/v6 中 GA/T 2380-2026、新网安法罚款表：**行业解读，非法条原文**

---

> **本提案状态**: Draft rev 3（2026-09-05）。L0-demo 可在无硬件合入；L0-contract 须 `mock_gateway` + `QuoteEnvelope` fixture。密评/TEE「通过」以测评机构与实测硬件为准，不在本文承诺范围内。
