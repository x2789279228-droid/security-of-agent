from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean, Float, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncAttrs
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import DeclarativeBase
from pgvector.sqlalchemy import Vector

from config import settings

# JSON 列用 MutableDict 包装，确保嵌套修改（raw_data["key"]=v）能被 SQLAlchemy 追踪
MutableJSON = MutableDict.as_mutable(JSON)

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=10,          # 常驻连接数（支撑 5 并发审计 + API 请求）
    max_overflow=20,       # 峰值溢出连接
    pool_pre_ping=True,    # 取连接前检测存活
    pool_recycle=1800,     # 30分钟回收连接
)
async_session = async_sessionmaker(engine, expire_on_commit=False)

class Base(AsyncAttrs, DeclarativeBase):
    pass

class Memory(Base):
    __tablename__ = "memories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(50), nullable=False, default="shared")
    content = Column(Text, nullable=False)
    embedding = Column(Vector(None))
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), nullable=False)
    agent_id = Column(String(50), nullable=False)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    protocol = Column(String(20))
    action = Column(String(20))
    message = Column(Text)
    raw_data = Column(MutableJSON, default=dict)
    analyzed = Column(Boolean, default=False, index=True)
    status = Column(String(30), default="new", index=True)  # new|acknowledged|investigating|resolved|closed|false_positive
    case_id = Column(Integer, ForeignKey("security_cases.id"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class MemoryTreeNode(Base):
    """记忆树节点 — 安全审计版：纯关联索引，不做内容压缩"""
    __tablename__ = "memory_tree_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), nullable=False, index=True)
    parent_id = Column(Integer, ForeignKey("memory_tree_nodes.id"), nullable=True, index=True)
    depth = Column(Integer, default=0)
    node_type = Column(String(20), default="leaf")  # "leaf" | "summary"(分组)
    content = Column(Text, nullable=True)            # 原始内容（永远保留）
    summary = Column(Text, nullable=True)            # 分组标签（非压缩摘要）
    importance = Column(Float, default=1.0)          # 所有节点同等重要=1.0
    compression_route = Column(String(20), default="independent")  # 关联分组ID
    token_count = Column(Integer, default=0)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class KnowledgeDoc(Base):
    """知识库文档"""
    __tablename__ = "knowledge_docs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    source = Column(String(50), default="internal")
    threat_types = Column(JSONB, default=list)
    severity = Column(String(20), default="medium")
    tags = Column(JSONB, default=list)
    metadata_ = Column("metadata", JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class KnowledgeChunk(Base):
    """知识库分块（含向量）"""
    __tablename__ = "knowledge_chunks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    doc_id = Column(Integer, ForeignKey("knowledge_docs.id"), nullable=False, index=True)
    chunk_id = Column(String(100), unique=True, index=True)
    content = Column(Text, nullable=False)
    title = Column(String(200), default="")
    source = Column(String(50), default="")
    threat_types = Column(JSONB, default=list)
    severity = Column(String(20), default="medium")
    tags = Column(JSONB, default=list)
    embedding = Column(Vector(None))
    token_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ResponseLog(Base):
    """响应日志 — 全量审计记录"""
    __tablename__ = "response_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), default="", index=True)
    event_id = Column(Integer, default=0, index=True)
    threat_type = Column(String(50), default="", index=True)
    threat_confidence = Column(Float, default=0.0)
    threat_severity = Column(String(20), default="info")
    src_ip = Column(String(45), default="", index=True)
    policy_name = Column(String(100), default="")
    action_name = Column(String(50), default="", index=True)
    action_params = Column(MutableJSON, default=dict)
    action_success = Column(Boolean, default=False)
    action_result = Column(MutableJSON, default=dict)
    rollback_token = Column(String(100), default="")
    auto_execute = Column(Boolean, default=False)
    approval_id = Column(String(100), default="")
    approval_status = Column(String(20), default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AgentTrace(Base):
    """Agent 轨迹 — LLM 调用留痕（审计流水线各环节）"""
    __tablename__ = "llm_traces"

    id = Column(Integer, primary_key=True, autoincrement=True)
    caller = Column(String(50), default="unknown", index=True)      # audit_pipeline | evidence_verifier | ...
    operation = Column(String(50), default="chat", index=True)      # decompose | execute | review | verify | ...
    model = Column(String(100), default="")
    event_id = Column(Integer, default=0, index=True)
    session_id = Column(String(100), default="", index=True)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    latency_ms = Column(Float, default=0.0)
    cache_hit = Column(Boolean, default=False)
    status = Column(String(20), default="success", index=True)      # success | error
    error_type = Column(String(50), default="")
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PipelineSpan(Base):
    """流水线阶段 Span — 全链路追踪"""
    __tablename__ = "pipeline_spans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    span_id = Column(String(20), default="", index=True)
    event_id = Column(Integer, default=0, index=True)
    session_id = Column(String(100), default="", index=True)
    stage = Column(String(30), default="", index=True)       # ingest | decomposer | executor | ...
    status = Column(String(20), default="running", index=True)  # running | success | error | timeout
    start_time = Column(Float, default=0.0)
    end_time = Column(Float, default=0.0)
    latency_ms = Column(Float, default=0.0)
    error = Column(Text, default="")
    metadata_ = Column("metadata", MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class DiagnosticReport(Base):
    """看门狗诊断报告 — 全链路自动诊断结果"""
    __tablename__ = "diagnostic_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    trigger_reason = Column(String(200), default="")
    trigger_stage = Column(String(50), default="", index=True)
    severity = Column(String(20), default="medium", index=True)  # critical | high | medium | low
    stage_metrics = Column(MutableJSON, default=dict)
    root_cause = Column(Text, default="")
    recommendations = Column(MutableJSON, default=list)
    llm_analysis = Column(Text, default="")
    affected_event_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class EvalRun(Base):
    """质量评估运行 — 一次检索/忠实度评估"""
    __tablename__ = "eval_runs"

    id = Column(String(64), primary_key=True)
    run_type = Column(String(50), nullable=False, index=True)       # rag | faithfulness
    subject_id = Column(String(100), default="", index=True)
    evaluator = Column(String(50), default="heuristic")
    status = Column(String(20), default="completed")
    prompt_version = Column(String(50), default="")
    retrieval_strategy = Column(String(50), default="")
    query = Column(Text, default="")
    answer = Column(Text, default="")
    ground_truth = Column(Text, default="")
    contexts = Column(JSON, default=list)
    input_payload = Column(JSON, default=dict)
    output_payload = Column(JSON, default=dict)
    error = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PhishingRecord(Base):
    """钓鱼检测记录"""
    __tablename__ = "phishing_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_type = Column(String(20), nullable=False, index=True)  # email / web / domain
    target = Column(String(500), default="")
    risk_level = Column(String(20), default="safe", index=True)      # safe / suspicious / phishing
    confidence = Column(Float, default=0.0)
    score = Column(Float, default=0.0)
    indicators = Column(JSON, default=list)
    summary = Column(Text, default="")
    suggested_actions = Column(JSON, default=list)
    raw_input = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PhishingDrill(Base):
    """钓鱼演练活动"""
    __tablename__ = "phishing_drills"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    drill_type = Column(String(20), default="email")                 # email / sms
    template_subject = Column(String(500), default="")
    template_body = Column(Text, default="")
    target_count = Column(Integer, default=0)
    status = Column(String(20), default="draft", index=True)         # draft / running / completed
    sent_count = Column(Integer, default=0)
    opened_count = Column(Integer, default=0)
    clicked_count = Column(Integer, default=0)
    reported_count = Column(Integer, default=0)
    start_time = Column(DateTime(timezone=True), nullable=True)
    end_time = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PhishingDrillRecord(Base):
    """钓鱼演练目标记录"""
    __tablename__ = "phishing_drill_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    drill_id = Column(Integer, ForeignKey("phishing_drills.id"), nullable=False, index=True)
    target_identifier = Column(String(200), default="")              # 邮箱 / 手机号
    sent_at = Column(DateTime(timezone=True), nullable=True)
    opened_at = Column(DateTime(timezone=True), nullable=True)
    clicked_at = Column(DateTime(timezone=True), nullable=True)
    reported_at = Column(DateTime(timezone=True), nullable=True)
    verdict = Column(String(20), default="pending", index=True)      # pending / sent / opened / clicked / reported
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class EvalScore(Base):
    """质量评估指标得分"""
    __tablename__ = "eval_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("eval_runs.id"), index=True)
    metric = Column(String(50), nullable=False)
    score = Column(Float, default=0.0)
    threshold = Column(Float, default=0.5)
    passed = Column(Boolean, default=False)
    reason = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ════════════════════════════════════════════
# 事件运营闭环模型
# ════════════════════════════════════════════

class SecurityCase(Base):
    """安全案例 — 多条告警事件的聚合容器"""
    __tablename__ = "security_cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_number = Column(String(30), unique=True, index=True)   # CASE-20260801-001
    title = Column(String(300), default="")
    status = Column(String(30), default="open", index=True)
    # open → investigating → pending_approval → responding → resolved → closed
    priority = Column(String(20), default="medium", index=True)  # critical|high|medium|low
    threat_type = Column(String(50), default="")
    severity = Column(String(20), default="medium")
    confidence = Column(Float, default=0.0)
    src_ips = Column(MutableJSON, default=list)
    dst_ips = Column(MutableJSON, default=list)
    event_ids = Column(MutableJSON, default=list)
    event_count = Column(Integer, default=0)
    assignee = Column(String(100), default="")
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    disposition = Column(Text, default="")              # 最终处置结论
    disposition_by = Column(String(100), default="")
    disposition_at = Column(DateTime(timezone=True), nullable=True)
    tags = Column(MutableJSON, default=list)
    metadata_ = Column("metadata", MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime(timezone=True), nullable=True)


class WorkOrder(Base):
    """工单 — 持久化任务跟踪（处置/审批/复盘/回滚）"""
    __tablename__ = "work_orders"

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_number = Column(String(30), unique=True, index=True)  # WO-20260801-001
    case_id = Column(Integer, ForeignKey("security_cases.id"), nullable=True, index=True)
    order_type = Column(String(30), default="disposition", index=True)
    # disposition | approval | review | rollback
    title = Column(String(300), default="")
    description = Column(Text, default="")
    status = Column(String(30), default="pending", index=True)
    # pending → assigned → in_progress → completed → cancelled
    priority = Column(String(20), default="medium")
    assignee = Column(String(100), default="")
    created_by = Column(String(100), default="system")
    approval_status = Column(String(20), default="")    # pending|approved|rejected（审批类工单）
    approved_by = Column(String(100), default="")
    approved_at = Column(DateTime(timezone=True), nullable=True)
    reject_reason = Column(Text, default="")
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    sla_breached = Column(Boolean, default=False)
    result = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)


class PostMortem(Base):
    """复盘报告 — 案例关闭后的结构化复盘"""
    __tablename__ = "post_mortems"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("security_cases.id"), unique=True, index=True)
    title = Column(String(300), default="")
    summary = Column(Text, default="")
    timeline = Column(MutableJSON, default=list)         # [{time, event, detail}]
    root_cause = Column(Text, default="")
    impact_assessment = Column(Text, default="")
    lessons_learned = Column(MutableJSON, default=list)
    action_items = Column(MutableJSON, default=list)     # [{item, owner, deadline, done}]
    false_positive_count = Column(Integer, default=0)
    detection_gaps = Column(Text, default="")
    rule_improvements = Column(MutableJSON, default=list)
    author = Column(String(100), default="")
    reviewer = Column(String(100), default="")
    status = Column(String(20), default="draft", index=True)  # draft|reviewed|published
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class FeedbackRecord(Base):
    """误报/反馈记录 — 运营人员对检测结论的纠正"""
    __tablename__ = "feedback_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True, index=True)
    case_id = Column(Integer, ForeignKey("security_cases.id"), nullable=True, index=True)
    feedback_type = Column(String(30), default="false_positive", index=True)
    # false_positive | true_positive | missed_threat | rule_suggestion
    original_conclusion = Column(String(50), default="")
    operator_conclusion = Column(String(50), default="")
    reason = Column(Text, default="")
    rule_id = Column(String(30), default="", index=True)
    rule_suggestion = Column(Text, default="")
    submitted_by = Column(String(100), default="")
    status = Column(String(20), default="submitted", index=True)
    # submitted → reviewed → applied | dismissed
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)


class RuleVersion(Base):
    """规则版本 — Sigma 规则 / 响应策略的版本管理"""
    __tablename__ = "rule_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_type = Column(String(30), default="sigma", index=True)  # sigma | response_policy
    rule_id = Column(String(50), default="", index=True)         # SIG-001 / C2通信自动封禁
    version = Column(Integer, default=1)
    content = Column(MutableJSON, default=dict)
    change_summary = Column(Text, default="")
    changed_by = Column(String(100), default="")
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_session():
    async with async_session() as session:
        yield session
