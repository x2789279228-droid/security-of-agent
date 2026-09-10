import os
from pathlib import Path

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://localhost:5432/shared_memory"
    redis_url: str = "redis://localhost:6379/0"

    # LLM
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    # Audit 路径默认关掉 thinking/reasoning（网关不认则自动剥离重试）
    llm_reasoning_effort: str = "none"

    # Embedding
    embedding_api_key: str = ""
    embedding_base_url: str = ""
    embedding_model: str = ""
    embedding_dim: int = 768

    # Service
    storage_backend: str = "redis"           # "redis" | "deque"
    sliding_window_size: int = 500
    sliding_window_minutes: int = 15         # 时间窗口（分钟）
    embedding_cache_ttl: int = 3600
    # LLM 响应缓存 TTL(秒): Redis 化后跨重启/跨容器共享; 默认 24h 收割"24h 内重复 prompt"
    llm_cache_ttl: int = 86400
    vector_search_threshold: float = 0.75

    # Qdrant 向量数据库 (RAG 知识库检索; 空则禁用 Qdrant, 回退 pgvector)
    qdrant_url: str = ""                     # 例: http://qdrant:6333
    qdrant_collection: str = "soc_knowledge_chunks"
    qdrant_memories_collection: str = "agent_memories"   # agent 记忆向量 collection
    qdrant_vector_size: int = 0              # 0 则取 embedding_dim
    qdrant_enabled: bool = True              # True=优先用 Qdrant 检索, 不可用时回退 pgvector
    qdrant_timeout: float = 5.0

    # RAG 混合检索 (dense + BM25 sparse + RRF + cross-encoder)
    rag_hybrid_enabled: bool = True
    rag_hybrid_collection: str = ""          # 空则用 {qdrant_collection}_v2
    rag_rrf_k: int = 60
    rag_prefetch: int = 20                   # 每路召回条数，融合后再截 top_k
    rag_bm25_backend: str = "builtin"        # builtin | fastembed
    rag_query_rewrite: str = "rules"         # off | rules | llm
    rag_hyde: str = "empty_only"             # off | empty_only | always
    rag_rerank_enabled: bool = True
    rag_rerank_url: str = ""                 # 空=不用 Infinity/CE，走特征重排；例 http://soc-bge-rerank:7997/rerank
    rag_rerank_api_key: str = ""             # 空且目标为本地 Infinity 时不带 Bearer
    rag_rerank_model: str = "BAAI/bge-reranker-v2-m3"
    rag_rerank_top_n: int = 20

    # Log Ingestion
    log_batch_size: int = 20                 # 累积多少条触发自动分析
    log_batch_interval: int = 300            # 或间隔多少秒触发（5分钟）

    # Security
    jwt_secret: str = ""
    allowed_origins: str = '["http://localhost:3001", "http://127.0.0.1:3001"]'
    rate_limit_per_minute: int = 120
    # HTTP 全局限流白名单的"追加项"(逗号分隔路径前缀, 见 http_guards.RATE_LIMIT_WHITELIST)
    # 默认白名单已覆盖全部业务域/运营只读端点; 此处只用于现场临时放开某个前缀, 无需改代码
    rate_limit_whitelist: str = ""
    admin_user: str = "admin"
    admin_password: str = ""

    # Response Engine Transport
    response_transport_mode: str = "auto"    # "stub" | "ssh" | "auto"
    response_ssh_host: str = ""              # Windows 宿主机 IP
    response_ssh_port: int = 22              # SSH 端口
    response_ssh_user: str = ""              # SSH 用户名
    response_ssh_key_file: str = ""          # SSH 私钥路径（容器内）
    response_ssh_key: str = ""               # SSH 私钥内容（直接填入，自动写入文件）

    # Kafka 消息总线
    kafka_bootstrap: str = "localhost:9092"
    kafka_topic_raw: str = "security-logs-raw"
    kafka_topic_validated: str = "security-logs-validated"
    kafka_topic_rejected: str = "security-logs-rejected"
    kafka_topic_enriched: str = "security-events-enriched"
    kafka_topic_alerts: str = "security-alerts"
    kafka_topic_audit_queue: str = "security-audit-queue"
    kafka_topic_audit_results: str = "security-audit-results"
    kafka_topic_cep_partial: str = "security-cep-partial"
    kafka_topic_cep_patterns: str = "security-cep-patterns"
    kafka_topic_sigma_hit: str = "security-sigma-hit"   # pySigma 聚合候选 → Flink 阈值窗口
    kafka_topic_behavior_alerts: str = "security-behavior-alerts"  # L4 Flink 行为基线
    # Kafka 三解耦: HTTP 网关处理队列 (Python 权威检测的排队消费通道)
    kafka_topic_ingest_process: str = "security-events-ingest"
    # Python 从 ingest-process 队列消费做全量检测(启=权威); 置 false 可退回到旧 Flink enriched/alerts 驱动
    python_process_ingest_queue: bool = True
    # 旧 Flink enriched handler 不再补排 LLM 审计(Python 主导权威时关闭双 LLM 成本与双审计)
    kafka_flink_secondary_llm: bool = False
    # 审计溢出 topic：内存队列满且 Redis PQ 失败时，P0/P1 持久化到此，禁止静默丢弃
    kafka_topic_audit_overflow: str = "security-audit-overflow"
    kafka_consumer_group: str = "soc-backend"
    kafka_enabled: bool = False              # True=Kafka 模式, False=兼容旧 HTTP 直连模式
    # Confluent Schema Registry (跨运行时 Schema 契约, 见 schema_registry.py)
    schema_registry_url: str = "http://schema-registry:8081"
    # Flink JobManager REST (管道状态聚合, 见 routers/kafka.py)
    flink_jobmanager_url: str = "http://flink-jobmanager:8081"

    # ── OpenTelemetry (标准 trace 体系 → otel-collector → Tempo) ──
    otel_enabled: bool = True
    otel_endpoint: str = "http://otel-collector:4317"
    env_name: str = "dev"

    # ── Temporal (4 层 Agent 编排: 可靠性/长任务/可视化) ──
    temporal_enabled: bool = False        # True=用 Temporal 编排, False=回退 async 兜底
    temporal_host: str = "temporal:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "audit-pipeline"
    # r6: 单 workflow 执行硬上限(秒); 超时由 Temporal 终止,避免永久 RUNNING
    temporal_workflow_execution_timeout_s: int = 900
    # Temporal llm_agent 在飞上限(只计 Agent 工作流, 不含 llm_single)
    audit_inflight_max: int = 4
    # 兼容旧名: Agent 工作流槽; 默认等于 audit_inflight_max
    audit_llm_agent_inflight_max: int = 4
    # start_workflow 墙钟超时, 防止 worker 卡在 Temporal 任务分发
    audit_temporal_start_timeout_s: float = 5.0
    # 运行中 stuck 收口阈值(分钟); analyzed=false 超过该时长 → fallback reap
    stuck_audit_reap_minutes: int = 5
    # LLM 通道分层: 软/硬预算水位(%); 硬水位下仍保留 P0 最小 LLM hop
    audit_soft_budget_pct: float = 70.0
    audit_hard_budget_pct: float = 95.0
    # P0 预留日预算比例(0-0.5); 软门禁不消耗该预留
    audit_p0_reserve_pct: float = 0.25
    # FastPath 强信号后是否降为复盘轻车道
    audit_fastpath_demote: bool = True
    # 优先级队列: inflight 满时 P0/P1 等待时长(秒); 分档 TTL 见下方
    audit_pq_ttl_s: int = 900
    audit_pq_ttl_p0_s: int = 3600
    audit_pq_ttl_p1_s: int = 1800
    audit_pq_ttl_p2_s: int = 300
    # PQ 拉取间隔(秒) / 每轮条数 — 入站 ~12 ev/s 时 5/s 会净堆积
    audit_pq_drain_interval_s: float = 0.2
    audit_pq_drain_batch: int = 20
    # Agent 槽满时跳过队头 P0, 继续抽 P1 llm_single, 避免 P1 dequeue=0
    audit_pq_skip_blocked_agent: bool = True
    # P1 默认不走 Temporal
    audit_p1_use_temporal: bool = False
    # 结论缓存 (同签名短期内复用)
    audit_cache_ttl_s: int = 600
    # 流量型事件(DDOS/PORT_SCAN)默认规则收口, 不进 LLM
    audit_volumetric_skip_llm: bool = True
    audit_llm_single_timeout_s: float = 15.0
    audit_max_rounds_agent: int = 1
    # 有界审计 worker(取代无界 create_task + 双 Semaphore)
    audit_workers: int = 12
    audit_queue_max: int = 2000
    # P0/P1 内存队列满时永不 overflow 丢弃：Redis PQ → Kafka overflow → 进程内 P0 兜底 deque
    audit_p0_never_drop: bool = True
    audit_p1_never_drop: bool = True
    # ── Ingest 事件驱动 Phase 1（同进程分层，不拆微服务）──
    ingest_http_queued_status: int = 202          # Kafka 入队成功返回码；同步回退仍 200
    ingest_parallel_detect: bool = True           # anomaly + sigma 并行；失败隔离
    ingest_store_batch_size: int = 50             # Kafka 消费批落库条数
    ingest_store_batch_flush_ms: int = 100        # 未满批也按墙钟 flush
    ingest_fastpath_retries: int = 2              # FastPath on_threat_detected 失败重试次数
    audit_timeout_p0_s: float = 90.0
    audit_timeout_p1_s: float = 45.0
    audit_timeout_p2_s: float = 20.0
    audit_timeout_p3_s: float = 10.0
    audit_max_rounds_deep: int = 2
    audit_max_rounds_standard: int = 1
    # DB 双池: OLTP 短租(ingest/API/audit SQL); BG 给索引/调度
    db_pool_oltp_size: int = 24
    db_pool_oltp_overflow: int = 8
    db_pool_oltp_timeout_s: float = 5.0
    db_pool_bg_size: int = 8
    db_pool_bg_overflow: int = 4
    db_pool_bg_timeout_s: float = 10.0
    # 全平台 LLM HTTP 并发(Audit + enhancer + RAG); 每进程
    llm_global_concurrency: int = 8
    llm_p0_reserve: int = 2
    llm_slot_timeout_s: float = 30.0
    llm_429_retry_s: float = 1.0
    # EventBus SSE
    event_bus_max_subscribers: int = 256
    event_bus_queue_max: int = 500

    # Sigma 检测引擎: pySigma=真 Sigma(pySigma+SQLite backend 读 rules/*.yml), legacy=原纯 dict 匹配
    sigma_engine: str = "pySigma"

    # 数据源认证
    source_api_keys: str = '{"soc-syslog-2024":"syslog-adapter","soc-api-2024":"api-client","soc-simulator-2024":"log-simulator"}'

    # SSH 防火墙适配器 (Linux iptables)
    fw_ssh_host: str = ""
    fw_ssh_port: int = 22
    fw_ssh_user: str = ""
    fw_ssh_password: str = ""
    fw_use_sudo: bool = True

    # MCP Guard 网关
    mcp_guard_enabled: bool = True       # 启用 4 层 Guard 检查
    security_guard_enabled: bool = True  # 启用 SecurityGuard (意图/频率/序列)

    # ── Tool 行为签名 (UEBA-for-AI) ──
    # persist=写 PG；enabled=检测器；mode=confirm(enforce) 偏离需确认，deny=拒绝，shadow=只告警
    tool_call_log_persist: bool = True
    tool_signature_enabled: bool = True
    tool_signature_mode: str = "confirm"         # confirm|enforce | deny | shadow
    tool_signature_min_samples: int = 30
    tool_signature_warn_threshold: float = 0.6
    tool_signature_confirm_threshold: float = 0.8
    tool_signature_deny_threshold: float = 0.95
    tool_signature_log_retention_days: int = 180
    tool_signature_weights: str = "param:0.35,seq:0.25,time:0.15,caller:0.25"

    # ── 案例自动派单 ──
    # 命中这些 priority 的自动聚合案例 → 自动派生工单并推进到 responding (逗号分隔)
    case_auto_order_priorities: str = "high,critical"
    # 自动工单默认指派人（空则保持 pending 无负责人）
    case_default_assignee: str = "admin"

    # resolved 案例停留超过该小时数仍未人工 closed → scheduler 自动 closed (0=不自动关闭)
    case_auto_close_hours: int = 24
    # 自动响应成功后，案例空闲超过该分钟 → 完成工单并 resolved（0=立即收口，负值=关闭此功能）
    case_auto_resolve_idle_minutes: int = 10

    # stuck 事件自动清理阈值（分钟）；0=启动时不自动清理
    stuck_auto_reset_minutes: int = 30

    # ── 安全执行层 (SafeExecutor) ──
    execution_mode: str = "live"             # dry_run | mock | live
    protected_assets: str = ""               # 受保护 IP/CIDR（逗号分隔）
    protected_assets_labels: str = ""        # 对应标签（逗号分隔）
    fw_ssh_user_readonly: str = ""           # 只读 SSH 账号（nmap/查询用）
    ttl_scan_interval: int = 30             # TTL 过期扫描间隔（秒）

    # ── 控制面安全（审批 HMAC / JWT 吊销 / 来源限制）──
    control_hmac_key: str = ""               # 空则回退 jwt_secret
    approval_ttl_minutes: int = 15
    approval_ttl_critical_minutes: int = 10
    api_allowlist: str = ""                  # 逗号分隔 IP/CIDR，空=不启用
    api_allowlist_allow_loopback: bool = True
    trust_proxy: bool = False
    service_token: str = ""                  # X-SOC-Service-Token；空=不启用
    mtls_enforce: bool = False               # 要求 X-SSL-Client-Verify=SUCCESS

    # ── 终端遏制 (containment) ──
    dns_sinkhole_ipv4: str = "127.0.0.2"
    dns_sinkhole_ipv6: str = "::ffff:127.0.0.2"
    ldap_url: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_base_dn: str = ""
    graph_tenant: str = ""
    graph_client_id: str = ""
    graph_client_secret: str = ""
    forensic_snapshot_timeout_s: int = 15
    forensic_include_dump: bool = False
    forensic_dump_max_mb: int = 64
    kill_process_max_matches: int = 20

    # ── NDR 流量采集 ──
    capture_enabled: bool = False            # 启用网络流量采集
    capture_interface: str = "eth0"          # 抓包网卡
    capture_bpf_filter: str = ""             # BPF 过滤表达式（空=全量）
    capture_method: str = "libpcap"          # libpcap | dpdk | af_packet
    capture_snap_len: int = 262144           # 每包最大捕获字节
    pcap_storage_path: str = "/data/pcap"    # PCAP 文件存储目录
    pcap_rotation_mb: int = 100              # 单文件上限 (MB)
    pcap_rotation_sec: int = 3600            # 单文件最长时长 (秒)
    pcap_retention_days: int = 7             # 热存储保留天数
    flow_idle_timeout: int = 300             # 流空闲超时 (秒)
    flow_active_timeout: int = 3600          # 流最大存活 (秒)
    sensor_id: str = "sensor-01"             # 探针标识

    # ── 加密流量识别 ──
    ja3_db_path: str = ""                    # JA3 已知指纹库路径（CSV）
    mitm_enabled: bool = False               # 启用 TLS 解密代理
    mitm_listen_port: int = 8443             # 解密代理监听端口
    mitm_ca_cert: str = ""                   # CA 证书路径
    mitm_ca_key: str = ""                    # CA 私钥路径
    tls_risk_self_signed: float = 0.8        # 自签名证书风险权重
    tls_risk_expired: float = 0.6            # 过期证书风险权重
    tls_risk_unknown_ja3: float = 0.4        # 未知 JA3 指纹风险权重

    # ── EDR 融合 ──
    edr_enabled: bool = False                # 启用 EDR 数据接入
    sysmon_kafka_topic: str = "edr-sysmon"   # Sysmon 日志 Kafka Topic
    winevent_kafka_topic: str = "edr-winevent"  # Windows Event Log Topic
    edr_correlation_window: int = 300        # 跨源关联时间窗口 (秒)

    # ── 威胁情报 ──
    intel_enabled: bool = False              # 启用威胁情报拉取
    intel_poll_interval: int = 60            # 默认拉取间隔 (分钟)
    misp_url: str = ""                       # MISP 实例地址
    misp_api_key: str = ""                   # MISP API Key
    misp_verify_ssl: bool = True
    taxii_url: str = ""                      # TAXII 服务器地址
    taxii_user: str = ""
    taxii_password: str = ""
    ioc_match_threshold: float = 0.8         # IOC 匹配置信度阈值

    # ── 沙箱检测 ──
    sandbox_enabled: bool = False            # 启用沙箱联动
    sandbox_type: str = "cape"               # cape | cuckoo
    sandbox_api_url: str = "http://localhost:8090"  # CAPE/Cuckoo API
    sandbox_api_key: str = ""
    sandbox_timeout: int = 300               # 分析超时 (秒)
    sandbox_auto_submit: bool = False        # 高危告警自动提交样本
    sandbox_auto_threshold: float = 0.8      # 自动提交置信度阈值

    # ── NDR Kafka Topics ──
    kafka_topic_flows: str = "ndr-flows"
    kafka_topic_tls: str = "ndr-tls-sessions"
    kafka_topic_pcap_meta: str = "ndr-pcap-meta"

    # ── LLM 增强器 (P0.S 引入) ──
    # 三大模块各自开关;默认 false 保留纯规则路径,任何时候关闭即降级
    llm_traffic_enabled: bool = False              # 流量大模型
    llm_phishing_enabled: bool = False             # 钓鱼大模型
    llm_data_security_enabled: bool = False        # 数据安全大模型
    # NDR 扩展模块 LLM 开关
    llm_encrypted_traffic_enabled: bool = False    # 加密流量 LLM 语义判定
    llm_edr_enabled: bool = False                  # EDR 跨源关联 LLM 叙事
    llm_intel_enabled: bool = False                # 威胁情报 LLM 上下文摘要
    llm_sandbox_enabled: bool = False              # 沙箱行为 LLM 解读
    # 模块日预算 (¥/天).任一模块超限 → 该模块降级,不挤占其它模块
    llm_traffic_budget_jpy_per_day: int = 5
    llm_phishing_budget_jpy_per_day: int = 75
    llm_data_security_budget_jpy_per_day: int = 5
    llm_encrypted_traffic_budget_jpy_per_day: int = 5
    llm_edr_budget_jpy_per_day: int = 5
    llm_intel_budget_jpy_per_day: int = 3
    llm_sandbox_budget_jpy_per_day: int = 5
    # 全局 LLM 增强器并发上限 — 已并入 llm_global_concurrency; 保留作 alias
    llm_enhancer_concurrency: int = 8
    # LLM 增强器单次超时 (秒)
    llm_enhancer_timeout_sec: int = 15

    # ── Red vs Blue Self-Play ──
    self_play_enabled: bool = True
    self_play_default_rounds: int = 8
    self_play_inject: bool = False          # True=把仿真事件送进生产 ingest(打上 _self_play)
    self_play_use_llm: bool = False         # False=课程目录规划,不烧 LLM
    self_play_wait_audit: bool = False      # True=等待 Audit-LLM 结论(演示/论文 full 模式)
    self_play_wait_audit_s: float = 8.0
    self_play_decoy_ratio: float = 0.2
    self_play_max_inflight: int = 1
    self_play_rag_top_k: int = 8
    self_play_llm_timeout_s: float = 20.0
    self_play_review_enabled: bool = True
    self_play_review_fp_max: float = 0.05
    self_play_review_llm: bool = True
    self_play_review_replay: bool = True
    self_play_shadow_hours: float = 24.0
    self_play_review_interval_s: int = 900
    self_play_review_batch: int = 20
    self_play_diverse_env: bool = False     # True=随机拓扑,默认仍 10 主机固定
    self_play_background_traffic: bool = False

    # ── 因果攻击链 (PC / GES, 批式, 不进 Flink 热路径) ──
    causal_enabled: bool = True
    causal_bin_minutes: int = 30
    causal_alpha: float = 0.05
    causal_min_windows: int = 40
    causal_learn_interval_s: int = 900
    causal_lookback_hours: int = 48

    # ── 每日学习闭环 (learn_loop: 收割→统计/聚类/序列→提议→自动应用) ──
    learn_loop_enabled: bool = True
    learn_loop_hourly_enabled: bool = False      # True=每小时走 run_cycle(hourly); False=保持原 generate_tuning_suggestions
    learn_loop_hour_utc: int = 2                 # 每日 UTC 触发钟点
    learn_loop_minute: int = 15                  # 每日 UTC 触发分钟
    learn_loop_lookback_hours: int = 24          # 收割窗口回溯小时
    learn_loop_auto_apply: bool = True           # 白名单动作自动应用
    learn_loop_cluster_min_size: int = 3         # 聚类最小簇大小
    learn_loop_jaccard: float = 0.5              # 事件聚类 Jaccard 阈值
    learn_loop_markov_min_count: int = 5         # 序列转移最小计数
    learn_loop_markov_min_p: float = 0.4         # 序列转移最小条件概率
    learn_loop_prior_clip: float = 0.2           # 信誉先验单侧 clip（±0.2）
    learn_loop_harvest_cases_limit: int = 500    # 收割案例上限
    learn_loop_harvest_events_limit: int = 5000  # 收割事件扫描上限

    # ── 演示流量（默认关；仅仿真事件打 _demo，不写生产 Sigma）──
    demo_traffic_enabled: bool = False
    demo_traffic_interval_s: int = 300

    # ── LLM 成本控制 (P0.T 引入) ──
    # 上不封顶: 0 = 无上限(默认, LLM审计永不因预算降级); >0 = 日预算额(设备回退时)
    # 上不封顶: 0 = 无上限(默认, LLM 审计永不因预算降级); >0 = 显式日额度(如需回退硬门禁)
    llm_daily_budget_tokens: int = 0
    # 统一开关: True=无上限，所有 LLM 预算只记账不关肘(审计/增强/维度), False=恢复预算门禁(回退)
    llm_budget_unlimited: bool = True
              # 每日全局 token 预算, 超限降级
    llm_price_input_per_1k_tokens: float = 0.0            # 输入每千 token 单价(¥), 0=不估算费用
    llm_price_output_per_1k_tokens: float = 0.0           # 输出每千 token 单价(¥), 0=不估算费用

    class Config:
        env_file = ".env"
        env_prefix = "SHARED_MEMORY_"


def _load_project_root_env() -> None:
    """从项目根目录加载 .env 并注入 os.environ，兼容乱码注释/非 UTF-8 行。

    背景：pydantic-settings 的 env_file='.env' 只从运行 CWD 查找，且 python-dotenv
    在 .env 含非 UTF-8(GBK)中文注释时整文件解析失败。此函数逐行按 ASCII 安全解析
    只提取 KEY=VALUE，跳过注释/乱码行，兼容「本机以 backend/ 为 CWD」。
    已存在环境变量(如 docker 注入)不覆盖。
    """
    import re
    for cand in (Path(__file__).resolve().parent.parent / ".env", Path.cwd() / ".env"):
        if not cand.exists():
            continue
        try:
            raw = cand.read_bytes().splitlines()
        except Exception:
            continue
        for ln in raw:
            if not all(b < 128 for b in ln):    # 跳过含非 ASCII(中文注释/乱码)行
                continue
            line = ln.decode("latin-1").strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if m:
                k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
                if k not in os.environ:
                    os.environ[k] = v


_load_project_root_env()
settings = Settings()
