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
    vector_search_threshold: float = 0.75

    # Qdrant 向量数据库 (RAG 知识库检索; 空则禁用 Qdrant, 回退 pgvector)
    qdrant_url: str = ""                     # 例: http://qdrant:6333
    qdrant_collection: str = "soc_knowledge_chunks"
    qdrant_memories_collection: str = "agent_memories"   # agent 记忆向量 collection
    qdrant_vector_size: int = 0              # 0 则取 embedding_dim
    qdrant_enabled: bool = True              # True=优先用 Qdrant 检索, 不可用时回退 pgvector
    qdrant_timeout: float = 5.0

    # Log Ingestion
    log_batch_size: int = 20                 # 累积多少条触发自动分析
    log_batch_interval: int = 300            # 或间隔多少秒触发（5分钟）

    # Security
    jwt_secret: str = ""
    allowed_origins: str = '["http://localhost:3001", "http://127.0.0.1:3001"]'
    rate_limit_per_minute: int = 120
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

    # ── 安全执行层 (SafeExecutor) ──
    execution_mode: str = "live"             # dry_run | mock | live
    protected_assets: str = ""               # 受保护 IP/CIDR（逗号分隔）
    protected_assets_labels: str = ""        # 对应标签（逗号分隔）
    fw_ssh_user_readonly: str = ""           # 只读 SSH 账号（nmap/查询用）
    ttl_scan_interval: int = 30             # TTL 过期扫描间隔（秒）

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
    # 全局 LLM 增强器并发上限 (保护 LLM API)
    llm_enhancer_concurrency: int = 5
    # LLM 增强器单次超时 (秒)
    llm_enhancer_timeout_sec: int = 15

    # ── LLM 成本控制 (P0.T 引入) ──
    llm_daily_budget_tokens: int = 5_000_000              # 每日全局 token 预算, 超限降级
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
