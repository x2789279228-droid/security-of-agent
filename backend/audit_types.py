"""
Audit-LLM 数据结构定义

核心类型:
  - SubTask:     Decomposer 输出的子任务
  - ToolCall:    Tool Builder 构造的具体工具调用
  - ToolResult:  工具调用的返回结果
  - AuditResult: Executor 综合后的审计结论
  - FinalVerdict: Reviewer 的最终裁决
"""
from dataclasses import dataclass, field
from typing import Any, Optional


# ── 审核深度等级 ──

AUDIT_DEPTH_QUICK = "quick"         # 快速过：非异常 + info/low
AUDIT_DEPTH_STANDARD = "standard"   # 标准：异常分>0.4 或 medium/high
AUDIT_DEPTH_DEEP = "deep"           # 深度：异常分>0.7 或 critical/攻击链匹配

AUDIT_DEPTH_LEVELS = [AUDIT_DEPTH_QUICK, AUDIT_DEPTH_STANDARD, AUDIT_DEPTH_DEEP]


# ── 子任务类型 ──

SUBTASK_QUERY_EVENTS = "query_events"       # 查询关联事件
SUBTASK_ANALYZE_IP = "analyze_ip"            # IP 基线分析
SUBTASK_FIND_CHAINS = "find_chains"          # 攻击链匹配
SUBTASK_CHECK_MEMORY = "check_memory"        # 向量记忆检索
SUBTASK_KNOWLEDGE_SEARCH = "knowledge_search"  # 安全知识库检索 (RAG)
SUBTASK_DEEP_ANALYZE = "deep_analyze"        # LLM 深度分析
SUBTASK_RECHECK = "recheck"                   # 复核
SUBTASK_GET_WINDOW = "get_window"            # 滑动窗口上下文
SUBTASK_ENTITY_LINK = "entity_link"          # 实体图关联
SUBTASK_TIMELINE = "timeline"                # 时间线重建


# ── 工具名称 ──

TOOL_EVENT_STORE_QUERY = "event_store.query"
TOOL_EVENT_STORE_GET = "event_store.get_by_id"
TOOL_ANOMALY_BASELINE = "anomaly.baseline"
TOOL_CORRELATION_CHAINS = "correlation.chains"
TOOL_CORRELATION_TEMPORAL = "correlation.temporal"
TOOL_CORRELATION_ENTITY_LINK = "correlation.entity_link"
TOOL_VECTOR_SEARCH = "vector.search"
TOOL_KNOWLEDGE_SEARCH = "knowledge.search"
TOOL_MEMORY_TREE_RELATED = "memory_tree.related"
TOOL_SLIDING_WINDOW = "sliding_window.get"
TOOL_SLIDING_EVICTED = "sliding_window.evicted"


@dataclass
class SubTask:
    """Decomposer 输出的子任务"""
    task_id: str
    type: str                     # SUBTASK_* 常量
    params: dict = field(default_factory=dict)
    priority: int = 3             # 1-5, 5最高
    depends_on: list[str] = field(default_factory=list)  # 依赖的其他task_id
    description: str = ""         # 给Tool Builder/Executor的自然语言说明

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "type": self.type,
            "params": self.params,
            "priority": self.priority,
            "depends_on": self.depends_on,
            "description": self.description,
        }


@dataclass
class ToolCall:
    """Tool Builder 构造的具体工具调用"""
    call_id: str
    task_id: str                  # 对应的子任务 ID
    tool: str                     # TOOL_* 常量
    args: dict = field(default_factory=dict)   # 工具参数
    priority: int = 3

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "task_id": self.task_id,
            "tool": self.tool,
            "args": self.args,
            "priority": self.priority,
        }


@dataclass
class ToolResult:
    """工具调用的返回结果"""
    call_id: str
    task_id: str
    tool: str
    success: bool
    data: Any = None
    error: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "task_id": self.task_id,
            "tool": self.tool,
            "success": self.success,
            "data_preview": str(self.data)[:200] if self.data else None,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class AuditResult:
    """Executor 综合后的审计结论"""
    threat_detected: bool = False
    threat_type: str = ""          # C2/DDoS/数据外泄/横向移动/勒索软件/其他
    confidence: float = 0.0        # 0-1
    severity: str = ""
    summary: str = ""
    evidence: list[dict] = field(default_factory=list)      # 关键证据摘要
    affected_entities: dict = field(default_factory=dict)    # src_ip, dst_ip
    suggested_actions: list[str] = field(default_factory=list)
    needs_human_review: bool = False
    tool_results: list[ToolResult] = field(default_factory=list)  # 所有工具返回

    # Grounding 强化字段
    grounding_score: float = 1.0          # 程序化 grounding 验证综合分 (0-1)
    kb_verification: dict = field(default_factory=dict)  # 知识库交叉验证结果
    schema_valid: bool = True             # 结构化输出验证是否通过

    # PR1 否决闸
    verdict: str = ""                     # confirmed / suspicious / false_positive / insufficient_evidence
    discarded_claims: list[dict] = field(default_factory=list)
    hop_trace: list[dict] = field(default_factory=list)
    non_llm_signals: dict = field(default_factory=dict)

    # 深度分析输出（前置合成模式：deep_analyze 在 synthesize 之前执行，
    # 其结论注入到汇总 prompt 中作为额外上下文，亦独立保留供前端展示）
    deep_analysis: str = ""

    def to_dict(self) -> dict:
        return {
            "threat_detected": self.threat_detected,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "severity": self.severity,
            "summary": self.summary[:200],
            "evidence_count": len(self.evidence),
            "affected_entities": self.affected_entities,
            "suggested_actions": self.suggested_actions[:3],
            "needs_human_review": self.needs_human_review,
            "tool_calls": len(self.tool_results),
            "grounding_score": self.grounding_score,
            "kb_supported": self.kb_verification.get("supported", 0),
            "schema_valid": self.schema_valid,
            "has_deep_analysis": bool(self.deep_analysis),
            "verdict": self.verdict,
            "discarded_claim_count": len(self.discarded_claims),
            "non_llm_signal": bool((self.non_llm_signals or {}).get("has_signal")),
            "hop_trace": list(self.hop_trace or []),
        }


@dataclass
class FinalVerdict:
    """Reviewer 的最终裁决"""
    conclusion: str = ""            # "threat_confirmed" / "false_positive" / "suspicious"
    confidence: float = 0.0
    missed_threats: list[dict] = field(default_factory=list)   # Executor 遗漏的
    evidence_chain: list[str] = field(default_factory=list)    # 证据链追溯
    human_intervention: bool = False
    final_summary: str = ""
    reviewer_notes: str = ""
    abstain: bool = False

    def to_dict(self) -> dict:
        return {
            "conclusion": self.conclusion,
            "confidence": self.confidence,
            "missed_count": len(self.missed_threats),
            "evidence_chain": self.evidence_chain[:5],
            "human_intervention": self.human_intervention,
            "final_summary": self.final_summary[:200],
            "abstain": self.abstain,
        }
