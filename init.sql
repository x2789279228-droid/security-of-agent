CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS memories (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(50) NOT NULL DEFAULT 'shared',
    content TEXT NOT NULL,
    embedding vector,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memories_agent ON memories(agent_id);
CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memories_embedding ON memories USING hnsw(embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);

CREATE TABLE IF NOT EXISTS conversations (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    agent_id VARCHAR(50) NOT NULL,
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_conv_session ON conversations(session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_conv_agent ON conversations(agent_id);

CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    src_ip VARCHAR(45) DEFAULT '',
    dst_ip VARCHAR(45) DEFAULT '',
    protocol VARCHAR(20) DEFAULT '',
    action VARCHAR(20) DEFAULT '',
    message TEXT DEFAULT '',
    raw_data JSONB DEFAULT '{}',
    analyzed BOOLEAN DEFAULT FALSE,
    status VARCHAR(30) DEFAULT 'new',
    case_id INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_session ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_analyzed ON security_events(analyzed);
CREATE INDEX IF NOT EXISTS idx_security_status ON security_events(status);
CREATE INDEX IF NOT EXISTS idx_security_case ON security_events(case_id);

-- ── 增量迁移：为安全事件添加 anomaly_score 独立列 + 索引 (P0 修复) ──
-- 让 event_store.get_unreviewed_anomalies 能在 SQL 层直接过滤，
-- 避免"近 50 条未审核事件均低分 → AgentD 漏报"的隐患。
-- 已存在则跳过（IF NOT EXISTS 兼容），并回填 raw_data._anomaly_score 到该列。
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS anomaly_score REAL DEFAULT 0.0;
CREATE INDEX IF NOT EXISTS idx_security_anomaly_score ON security_events(anomaly_score);

-- 历史数据回填：把 raw_data 中的 _anomaly_score 提取到独立列
-- 仅回填 anomaly_score=0 但 raw_data._anomaly_score > 0 的记录，避免重复执行覆盖
UPDATE security_events
SET anomaly_score = CAST(raw_data->>'_anomaly_score' AS REAL)
WHERE raw_data ? '_anomaly_score'
  AND COALESCE(anomaly_score, 0) = 0
  AND CAST(raw_data->>'_anomaly_score' AS REAL) IS NOT NULL;

-- 增量迁移：为安全事件添加 status / case_id 列（事件运营闭环）
-- 与 backend/models.py SecurityEvent 保持同步；已存在则跳过
-- 注: security_cases 表由后端 SQLAlchemy 创建，故此处不加外键约束
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'new';
CREATE INDEX IF NOT EXISTS idx_security_status ON security_events(status);
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS case_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_security_case ON security_events(case_id);

CREATE TABLE IF NOT EXISTS memory_tree_nodes (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    parent_id INTEGER REFERENCES memory_tree_nodes(id),
    depth INTEGER DEFAULT 0,
    node_type VARCHAR(20) DEFAULT 'leaf',
    content TEXT,
    summary TEXT,
    importance REAL DEFAULT 0.5,
    compression_route VARCHAR(20) DEFAULT 'none',
    token_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tree_session ON memory_tree_nodes(session_id);
CREATE INDEX IF NOT EXISTS idx_tree_parent ON memory_tree_nodes(parent_id);
CREATE INDEX IF NOT EXISTS idx_tree_type ON memory_tree_nodes(node_type);

CREATE TABLE IF NOT EXISTS knowledge_docs (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    source VARCHAR(50) DEFAULT 'internal',
    threat_types JSONB DEFAULT '[]',
    severity VARCHAR(20) DEFAULT 'medium',
    tags JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id SERIAL PRIMARY KEY,
    doc_id INTEGER REFERENCES knowledge_docs(id) ON DELETE CASCADE,
    chunk_id VARCHAR(100) UNIQUE,
    content TEXT NOT NULL,
    title VARCHAR(200) DEFAULT '',
    source VARCHAR(50) DEFAULT '',
    threat_types JSONB DEFAULT '[]',
    severity VARCHAR(20) DEFAULT 'medium',
    tags JSONB DEFAULT '[]',
    embedding vector,
    token_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_doc ON knowledge_chunks(doc_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_chunk ON knowledge_chunks(chunk_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_embedding ON knowledge_chunks USING hnsw(embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_threat ON knowledge_chunks USING gin(threat_types);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_severity ON knowledge_chunks(severity);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_source ON knowledge_chunks(source);

CREATE TABLE IF NOT EXISTS response_logs (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100) DEFAULT '',
    event_id INTEGER DEFAULT 0,
    threat_type VARCHAR(50) DEFAULT '',
    threat_confidence REAL DEFAULT 0.0,
    threat_severity VARCHAR(20) DEFAULT 'info',
    src_ip VARCHAR(45) DEFAULT '',
    policy_name VARCHAR(100) DEFAULT '',
    action_name VARCHAR(50) DEFAULT '',
    action_params JSONB DEFAULT '{}',
    action_success BOOLEAN DEFAULT FALSE,
    action_result JSONB DEFAULT '{}',
    rollback_token VARCHAR(100) DEFAULT '',
    auto_execute BOOLEAN DEFAULT FALSE,
    approval_id VARCHAR(100) DEFAULT '',
    approval_status VARCHAR(20) DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_response_logs_session ON response_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_response_logs_event ON response_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_response_logs_threat ON response_logs(threat_type);
CREATE INDEX IF NOT EXISTS idx_response_logs_ip ON response_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_response_logs_action ON response_logs(action_name);

-- ════════════════════════════════════════════
-- NDR 流量采集与协议解析
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS network_flows (
    id SERIAL PRIMARY KEY,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INTEGER DEFAULT 0,
    dst_port INTEGER DEFAULT 0,
    protocol VARCHAR(20) DEFAULT 'TCP',
    direction VARCHAR(10) DEFAULT 'outbound',
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    packets_in INTEGER DEFAULT 0,
    packets_out INTEGER DEFAULT 0,
    duration_ms REAL DEFAULT 0.0,
    tcp_flags VARCHAR(20) DEFAULT '',
    app_protocol VARCHAR(30) DEFAULT '',
    country_src VARCHAR(5) DEFAULT '',
    country_dst VARCHAR(5) DEFAULT '',
    asn_src VARCHAR(20) DEFAULT '',
    asn_dst VARCHAR(20) DEFAULT '',
    sensor_id VARCHAR(50) DEFAULT '',
    flow_start TIMESTAMP WITH TIME ZONE,
    flow_end TIMESTAMP WITH TIME ZONE,
    raw_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flows_src ON network_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON network_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_port ON network_flows(dst_port);
CREATE INDEX IF NOT EXISTS idx_flows_protocol ON network_flows(protocol);
CREATE INDEX IF NOT EXISTS idx_flows_app ON network_flows(app_protocol);
CREATE INDEX IF NOT EXISTS idx_flows_sensor ON network_flows(sensor_id);
CREATE INDEX IF NOT EXISTS idx_flows_start ON network_flows(flow_start);
CREATE INDEX IF NOT EXISTS idx_flows_created ON network_flows(created_at DESC);

CREATE TABLE IF NOT EXISTS tls_sessions (
    id SERIAL PRIMARY KEY,
    flow_id INTEGER REFERENCES network_flows(id),
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    dst_port INTEGER DEFAULT 443,
    sni VARCHAR(300) DEFAULT '',
    ja3_hash VARCHAR(64) DEFAULT '',
    ja3s_hash VARCHAR(64) DEFAULT '',
    ja4_hash VARCHAR(64) DEFAULT '',
    tls_version VARCHAR(10) DEFAULT '',
    cipher_suite VARCHAR(100) DEFAULT '',
    cert_subject VARCHAR(500) DEFAULT '',
    cert_issuer VARCHAR(500) DEFAULT '',
    cert_serial VARCHAR(100) DEFAULT '',
    cert_not_before TIMESTAMP WITH TIME ZONE,
    cert_not_after TIMESTAMP WITH TIME ZONE,
    cert_san JSONB DEFAULT '[]',
    cert_is_self_signed BOOLEAN DEFAULT FALSE,
    cert_chain_valid BOOLEAN DEFAULT TRUE,
    alpn VARCHAR(50) DEFAULT '',
    is_expired BOOLEAN DEFAULT FALSE,
    risk_score REAL DEFAULT 0.0,
    risk_reasons JSONB DEFAULT '[]',
    sensor_id VARCHAR(50) DEFAULT '',
    session_start TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tls_flow ON tls_sessions(flow_id);
CREATE INDEX IF NOT EXISTS idx_tls_src ON tls_sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_tls_dst ON tls_sessions(dst_ip);
CREATE INDEX IF NOT EXISTS idx_tls_sni ON tls_sessions(sni);
CREATE INDEX IF NOT EXISTS idx_tls_ja3 ON tls_sessions(ja3_hash);
CREATE INDEX IF NOT EXISTS idx_tls_ja3s ON tls_sessions(ja3s_hash);
CREATE INDEX IF NOT EXISTS idx_tls_expired ON tls_sessions(is_expired);
CREATE INDEX IF NOT EXISTS idx_tls_sensor ON tls_sessions(sensor_id);
CREATE INDEX IF NOT EXISTS idx_tls_start ON tls_sessions(session_start);

CREATE TABLE IF NOT EXISTS pcap_files (
    id SERIAL PRIMARY KEY,
    file_path VARCHAR(500) NOT NULL,
    file_size INTEGER DEFAULT 0,
    sensor_id VARCHAR(50) DEFAULT '',
    interface VARCHAR(50) DEFAULT '',
    packet_count INTEGER DEFAULT 0,
    flow_count INTEGER DEFAULT 0,
    capture_start TIMESTAMP WITH TIME ZONE,
    capture_end TIMESTAMP WITH TIME ZONE,
    bpf_filter VARCHAR(500) DEFAULT '',
    status VARCHAR(20) DEFAULT 'capturing',
    storage_tier VARCHAR(10) DEFAULT 'hot',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pcap_sensor ON pcap_files(sensor_id);
CREATE INDEX IF NOT EXISTS idx_pcap_status ON pcap_files(status);
CREATE INDEX IF NOT EXISTS idx_pcap_start ON pcap_files(capture_start);

-- ════════════════════════════════════════════
-- EDR 融合
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS edr_events (
    id SERIAL PRIMARY KEY,
    source_type VARCHAR(30) NOT NULL,
    event_id INTEGER DEFAULT 0,
    computer_name VARCHAR(200) DEFAULT '',
    user_name VARCHAR(200) DEFAULT '',
    process_name VARCHAR(500) DEFAULT '',
    process_id INTEGER DEFAULT 0,
    parent_process VARCHAR(500) DEFAULT '',
    command_line TEXT DEFAULT '',
    image_hash VARCHAR(128) DEFAULT '',
    src_ip VARCHAR(45) DEFAULT '',
    dst_ip VARCHAR(45) DEFAULT '',
    dst_port INTEGER DEFAULT 0,
    file_path VARCHAR(1000) DEFAULT '',
    registry_key VARCHAR(1000) DEFAULT '',
    event_data JSONB DEFAULT '{}',
    severity VARCHAR(20) DEFAULT 'info',
    mitre_technique VARCHAR(50) DEFAULT '',
    correlation_key VARCHAR(100) DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_edr_source ON edr_events(source_type);
CREATE INDEX IF NOT EXISTS idx_edr_event_id ON edr_events(event_id);
CREATE INDEX IF NOT EXISTS idx_edr_computer ON edr_events(computer_name);
CREATE INDEX IF NOT EXISTS idx_edr_process ON edr_events(process_name);
CREATE INDEX IF NOT EXISTS idx_edr_hash ON edr_events(image_hash);
CREATE INDEX IF NOT EXISTS idx_edr_src_ip ON edr_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_edr_severity ON edr_events(severity);
CREATE INDEX IF NOT EXISTS idx_edr_mitre ON edr_events(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_edr_corr ON edr_events(correlation_key);
CREATE INDEX IF NOT EXISTS idx_edr_created ON edr_events(created_at DESC);

-- ════════════════════════════════════════════
-- 威胁情报
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS threat_iocs (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(30) NOT NULL,
    ioc_value VARCHAR(1000) NOT NULL,
    threat_type VARCHAR(50) DEFAULT '',
    severity VARCHAR(20) DEFAULT 'medium',
    confidence REAL DEFAULT 0.0,
    source VARCHAR(100) DEFAULT '',
    stix_id VARCHAR(200) DEFAULT '',
    mitre_attack_id VARCHAR(50) DEFAULT '',
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    tags JSONB DEFAULT '[]',
    context JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_type ON threat_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON threat_iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_threat ON threat_iocs(threat_type);
CREATE INDEX IF NOT EXISTS idx_ioc_severity ON threat_iocs(severity);
CREATE INDEX IF NOT EXISTS idx_ioc_source ON threat_iocs(source);
CREATE INDEX IF NOT EXISTS idx_ioc_stix ON threat_iocs(stix_id);
CREATE INDEX IF NOT EXISTS idx_ioc_active ON threat_iocs(is_active);

CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    feed_type VARCHAR(30) NOT NULL,
    url VARCHAR(1000) DEFAULT '',
    api_key VARCHAR(500) DEFAULT '',
    collection VARCHAR(200) DEFAULT '',
    poll_interval_min INTEGER DEFAULT 60,
    last_poll_at TIMESTAMP WITH TIME ZONE,
    last_poll_status VARCHAR(20) DEFAULT 'idle',
    last_poll_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feed_enabled ON threat_intel_feeds(enabled);

-- ════════════════════════════════════════════
-- 零日 / 沙箱检测
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS sandbox_tasks (
    id SERIAL PRIMARY KEY,
    task_id VARCHAR(100) DEFAULT '',
    sample_hash VARCHAR(128) DEFAULT '',
    sample_name VARCHAR(500) DEFAULT '',
    sample_type VARCHAR(50) DEFAULT '',
    source VARCHAR(50) DEFAULT 'manual',
    source_event_id INTEGER DEFAULT 0,
    sandbox_type VARCHAR(30) DEFAULT 'cape',
    status VARCHAR(30) DEFAULT 'pending',
    priority INTEGER DEFAULT 1,
    behavior_summary TEXT DEFAULT '',
    verdict VARCHAR(30) DEFAULT '',
    score REAL DEFAULT 0.0,
    mitre_techniques JSONB DEFAULT '[]',
    network_iocs JSONB DEFAULT '[]',
    file_iocs JSONB DEFAULT '[]',
    process_tree JSONB DEFAULT '[]',
    screenshots JSONB DEFAULT '[]',
    report_url VARCHAR(1000) DEFAULT '',
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sandbox_task ON sandbox_tasks(task_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_hash ON sandbox_tasks(sample_hash);
CREATE INDEX IF NOT EXISTS idx_sandbox_source ON sandbox_tasks(source);
CREATE INDEX IF NOT EXISTS idx_sandbox_event ON sandbox_tasks(source_event_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_status ON sandbox_tasks(status);
CREATE INDEX IF NOT EXISTS idx_sandbox_verdict ON sandbox_tasks(verdict);
CREATE INDEX IF NOT EXISTS idx_sandbox_submitted ON sandbox_tasks(submitted_at);

-- ════════════════════════════════════════════
-- 安全运营 — 资产管理 (P0.A)
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    asset_key VARCHAR(100) UNIQUE NOT NULL,
    asset_type VARCHAR(30) NOT NULL,
    ip VARCHAR(45) DEFAULT '' ,
    hostname VARCHAR(200) DEFAULT '',
    os VARCHAR(80) DEFAULT '',
    services JSONB DEFAULT '[]',
    business_owner VARCHAR(100) DEFAULT '',
    tech_owner VARCHAR(100) DEFAULT '',
    business_unit VARCHAR(100) DEFAULT '',
    criticality VARCHAR(20) DEFAULT 'medium',
    environment VARCHAR(20) DEFAULT 'prod',
    tags JSONB DEFAULT '[]',
    exposure VARCHAR(20) DEFAULT 'internal',
    source VARCHAR(30) DEFAULT 'manual',
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE,
    last_scan_id INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(business_owner);
CREATE INDEX IF NOT EXISTS idx_assets_active ON assets(is_active);
CREATE INDEX IF NOT EXISTS idx_assets_business_unit ON assets(business_unit);

CREATE TABLE IF NOT EXISTS asset_changes (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    change_type VARCHAR(30),
    diff JSONB,
    source VARCHAR(30),
    changed_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_changes_asset ON asset_changes(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_changes_created ON asset_changes(created_at DESC);

CREATE TABLE IF NOT EXISTS asset_discovery_tasks (
    id SERIAL PRIMARY KEY,
    task_id VARCHAR(50) UNIQUE,
    scope VARCHAR(200),
    scanner VARCHAR(30),
    status VARCHAR(20) DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    new_count INTEGER DEFAULT 0,
    changed_count INTEGER DEFAULT 0,
    result JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_discovery_status ON asset_discovery_tasks(status);
CREATE INDEX IF NOT EXISTS idx_discovery_created ON asset_discovery_tasks(created_at DESC);

-- ════════════════════════════════════════════
-- 安全运营 — 数据源持久化 (P0.G)
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS data_sources (
    id SERIAL PRIMARY KEY,
    api_key_hash VARCHAR(128) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    source_type VARCHAR(30) DEFAULT 'generic',
    enabled BOOLEAN DEFAULT TRUE,
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE,
    total_events BIGINT DEFAULT 0,
    rejected_events BIGINT DEFAULT 0,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by VARCHAR(100),
    metadata JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sources_enabled ON data_sources(enabled);
CREATE INDEX IF NOT EXISTS idx_sources_name ON data_sources(name);

CREATE TABLE IF NOT EXISTS data_source_rejections (
    id BIGSERIAL PRIMARY KEY,
    api_key_prefix VARCHAR(40),
    reason VARCHAR(40),
    source_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rejections_created ON data_source_rejections(created_at DESC);

-- ════════════════════════════════════════════
-- 安全运营 — 操作审计 trail (P0.H)
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS audit_trail (
    id BIGSERIAL PRIMARY KEY,
    actor VARCHAR(100) NOT NULL,
    actor_role VARCHAR(50) DEFAULT '',
    action VARCHAR(60) NOT NULL,
    target_type VARCHAR(30),
    target_id VARCHAR(60),
    before JSONB,
    after JSONB,
    ip VARCHAR(45),
    user_agent VARCHAR(200),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_trail_actor ON audit_trail(actor);
CREATE INDEX IF NOT EXISTS idx_trail_target ON audit_trail(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_trail_action ON audit_trail(action);
CREATE INDEX IF NOT EXISTS idx_trail_created ON audit_trail(created_at DESC);

-- ════════════════════════════════════════════
-- 安全运营 — 运营 KPI 快照 (P0.B)
-- ════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS kpi_snapshots (
    id SERIAL PRIMARY KEY,
    snapshot_date DATE NOT NULL,
    period VARCHAR(10) NOT NULL,
    metric_key VARCHAR(60) NOT NULL,
    metric_value FLOAT,
    dimensions JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    -- 不加 UNIQUE: 同一 metric_key 需按 dimensions(如 priority) 存多行,
    -- 且 jsonb 无 btree 操作符类无法参与唯一约束; 去重由应用层 upsert 保证
);
CREATE INDEX IF NOT EXISTS idx_kpi_date ON kpi_snapshots(snapshot_date);
CREATE INDEX IF NOT EXISTS idx_kpi_key ON kpi_snapshots(metric_key);

INSERT INTO memories (agent_id, content, metadata) VALUES
('shared', '系统初始化：共享记忆服务层已就绪。', '{"type": "system", "init": true}')
ON CONFLICT DO NOTHING;

-- P: idempotency - unique event_id from upstream (Flink UUID)
-- Replaces the old Redis 24h dedup: exactly-once replay lands once.
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_id VARCHAR(64);
CREATE UNIQUE INDEX IF NOT EXISTS uq_security_events_event_id ON security_events(event_id);
