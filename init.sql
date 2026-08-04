CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS memories (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(50) NOT NULL DEFAULT 'shared',
    content TEXT NOT NULL,
    embedding vector(1024),
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
    status VARCHAR(20) DEFAULT 'open',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_session ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_analyzed ON security_events(analyzed);

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
    embedding vector(1024),
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

INSERT INTO memories (agent_id, content, metadata) VALUES
('shared', '系统初始化：共享记忆服务层已就绪。', '{"type": "system", "init": true}')
ON CONFLICT DO NOTHING;
