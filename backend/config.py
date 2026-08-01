from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://admin:admin123@localhost:5432/shared_memory"
    redis_url: str = "redis://localhost:6379/0"

    # LLM
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""

    # Embedding
    embedding_api_key: str = ""
    embedding_base_url: str = ""
    embedding_model: str = ""
    embedding_dim: int = 1024

    # Service
    storage_backend: str = "redis"           # "redis" | "deque"
    sliding_window_size: int = 500
    sliding_window_minutes: int = 15         # 时间窗口（分钟）
    embedding_cache_ttl: int = 3600
    vector_search_threshold: float = 0.75

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
    kafka_consumer_group: str = "soc-backend"
    kafka_enabled: bool = False              # True=Kafka 模式, False=兼容旧 HTTP 直连模式

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

    class Config:
        env_file = ".env"
        env_prefix = "SHARED_MEMORY_"

settings = Settings()
