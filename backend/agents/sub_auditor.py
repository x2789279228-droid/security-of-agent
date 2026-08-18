"""
子审核器 (SubAuditor) — Grounding 强化版

防幻觉三层机制:
  1. Prompt 强制 Grounding:
     - evidence_ids: 引用事件 ID（已有）
     - evidence_quotes: 引用事件原始字段值（新增）
  2. Pydantic 结构化验证:
     - 用 SubAuditorOutputSchema 校验 LLM 输出
     - 格式不合法自动重试 1 次
  3. 程序化 Grounding 验证:
     - GroundingVerifier 检查 quotes 是否真的出现在事件中
     - 检查 IP/severity 一致性

ChunkVerdict 新增:
  - grounding_report: 程序化 grounding 验证结果
  - evidence_quotes: 每条断言引用的原始字段值
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from summary_compression import summary
# D3: 继承 BaseAuditComponent 统一 LLM 调用入口的 trace
from .base import BaseAuditComponent

logger = logging.getLogger(__name__)


@dataclass
class ChunkVerdict:
    """单块审核结论（Grounding 强化版）"""
    chunk_id: str
    threat_detected: bool

    threat_claims: list[dict] = field(default_factory=list)
    # 每条 = {"type", "confidence", "evidence_ids", "evidence_quotes", "severity", "summary"}

    confidence: float = 0.0
    severity: str = "info"
    summary: str = ""
    suspicious_entities: list[str] = field(default_factory=list)
    alert: str = ""

    # 防幻觉状态
    unsubstantiated: bool = False
    hallucination_risk: float = 0.0
    all_event_ids_in_chunk: list[int] = field(default_factory=list)

    # Grounding 验证结果（程序化，非 LLM）
    grounding_report: Optional[dict] = None
    grounding_score: float = 1.0        # 0-1, 程序化验证综合分

    # 结构化验证状态
    schema_valid: bool = True
    schema_errors: list[str] = field(default_factory=list)

    raw_llm_output: str = ""

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "threat_detected": self.threat_detected,
            "threat_claims": self.threat_claims,
            "confidence": self.confidence,
            "severity": self.severity,
            "summary": self.summary[:200],
            "suspicious_entities": self.suspicious_entities,
            "alert": self.alert,
            "hallucination_risk": self.hallucination_risk,
            "unsubstantiated": self.unsubstantiated,
            "grounding_score": self.grounding_score,
            "schema_valid": self.schema_valid,
            "evidence_ids_available": bool(self.all_event_ids_in_chunk),
        }

    def validate_evidence(self) -> dict:
        """验证证据完整性（ID 存在性 + Grounding 分数）"""
        chunk_ids = set(self.all_event_ids_in_chunk)
        valid = 0
        invalid = 0
        issues = []

        for claim in self.threat_claims:
            ev_ids = claim.get("evidence_ids", [])
            if not ev_ids:
                invalid += 1
                issues.append(f"断言「{claim.get('summary','')[:50]}」无证据ID")
                continue

            missing = [eid for eid in ev_ids if eid not in chunk_ids]
            if missing:
                invalid += 1
                issues.append(
                    f"断言引用的事件 ID {missing} 不在本块中"
                    f"（块内 ID: {sorted(chunk_ids)[:5]}...）"
                )
            else:
                # 进一步检查 evidence_quotes 是否存在
                quotes = claim.get("evidence_quotes", [])
                if not quotes:
                    issues.append(
                        f"断言「{claim.get('summary','')[:50]}」有证据ID但无字段引用"
                    )
                valid += 1

        total = len(self.threat_claims)
        self.hallucination_risk = invalid / max(total, 1)
        self.unsubstantiated = invalid > 0 and total > 0

        # 综合 grounding 分数到幻觉风险
        if self.grounding_score < 0.5:
            self.hallucination_risk = max(
                self.hallucination_risk, 1.0 - self.grounding_score
            )

        return {
            "total_claims": total,
            "valid_claims": valid,
            "invalid_claims": invalid,
            "hallucination_risk": self.hallucination_risk,
            "grounding_score": self.grounding_score,
            "issues": issues,
        }


class SubAuditor(BaseAuditComponent):
    """子审核器（Grounding 强化版）

    D3: 继承 BaseAuditComponent 而非 BaseAgent，避免被强制实现 process()，
    保留以 audit(chunk) 为主 API 的语义，同时复用统一的 llm_chat trace 入口。
    """

    MAX_RETRIES = 1  # 结构化验证失败时最多重试次数

    def __init__(self):
        super().__init__(
            agent_id="sub_auditor",
            display_name="子审核器 (SubAuditor)",
        )

    async def audit(
        self,
        chunk,
        knowledge_chunks: list[dict] | None = None,
    ) -> ChunkVerdict:
        """审核单个事件块 — 强制 Grounding + 结构化验证

        Args:
            chunk: 待审核事件块 (AuditChunk)
            knowledge_chunks: 可选的安全知识库片段列表（来自 RAG 检索），
                              用于启用 GroundingVerifier Layer 4 知识库一致性校验。
                              为 None 时 Layer 4 视为"无知识库可验证"，返回一致性通过。
        """
        block_text = chunk.to_prompt_block()
        event_count = len(chunk.events)
        all_ids = [e.get("id", e.get("event_id")) for e in chunk.events if e.get("id")]

        logger.info(
            f"SubAuditor auditing chunk {chunk.chunk_id}: "
            f"{event_count} events, IDs={all_ids[:5]}..., "
            f"kb_chunks={len(knowledge_chunks) if knowledge_chunks else 0}"
        )

        prompt = self._build_prompt(block_text)

        # D3: 统一使用 self.llm_chat（已合并 set_trace_context 调用）
        # 不再手动 from trace_hook import set_trace_context

        # 首次调用 + 结构化验证 + 可选重试
        parsed = None
        schema_errors = []
        raw_result = ""

        for attempt in range(1 + self.MAX_RETRIES):
            if attempt > 0:
                # 重试时追加纠错指令
                retry_prompt = (
                    f"{prompt}\n\n## ⚠️ 上次输出格式错误\n"
                    f"错误: {'; '.join(schema_errors)}\n"
                    f"请严格按 JSON 格式重新输出。"
                )
                # D3: 使用 self.llm_chat 统一 trace 入口
                raw_result = await self.llm_chat([
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": retry_prompt},
                ])
            else:
                # D3: 使用 self.llm_chat 统一 trace 入口
                raw_result = await self.llm_chat([
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": prompt},
                ])

            from audit_schemas import validate_sub_auditor_output
            parsed, schema_errors = validate_sub_auditor_output(raw_result)

            if not schema_errors:
                break
            logger.warning(
                f"SubAuditor schema validation failed (attempt {attempt+1}): "
                f"{schema_errors}"
            )

        if parsed is None:
            return ChunkVerdict(
                chunk_id=chunk.chunk_id,
                threat_detected=False,
                summary="JSON 解析失败",
                confidence=0.0,
                hallucination_risk=1.0,
                unsubstantiated=True,
                schema_valid=False,
                schema_errors=schema_errors or ["JSON 解析失败"],
                raw_llm_output=raw_result,
            )

        claims = parsed.get("threat_claims", [])
        verdict = ChunkVerdict(
            chunk_id=chunk.chunk_id,
            threat_detected=parsed.get("threat_detected", False) and len(claims) > 0,
            threat_claims=claims,
            confidence=parsed.get("confidence", 0.0),
            severity=parsed.get("severity", "info"),
            summary=parsed.get("summary", ""),
            suspicious_entities=parsed.get("suspicious_entities", []),
            alert=parsed.get("alert", ""),
            all_event_ids_in_chunk=all_ids,
            schema_valid=len(schema_errors) == 0,
            schema_errors=schema_errors,
            raw_llm_output=raw_result,
        )

        # 程序化 Grounding 验证
        try:
            from grounding_verifier import grounding_verifier
            grounding = grounding_verifier.verify_chunk(
                claims, chunk.events,
                knowledge_chunks=knowledge_chunks or [],
                chunk_id=chunk.chunk_id,
            )
            verdict.grounding_report = {
                "overall_score": grounding.overall_score,
                "grounded": grounding.grounded_claims,
                "partially": grounding.partially_grounded,
                "ungrounded": grounding.ungrounded_claims,
                "indicators": grounding.hallucination_indicators[:5],
            }
            verdict.grounding_score = grounding.overall_score

            if grounding.ungrounded_claims > 0:
                logger.warning(
                    f"Chunk {chunk.chunk_id}: {grounding.ungrounded_claims} "
                    f"ungrounded claims, score={grounding.overall_score:.2f}"
                )
                for ind in grounding.hallucination_indicators[:3]:
                    logger.warning(f"  Grounding issue: {ind}")
        except Exception as e:
            logger.warning(f"Grounding verification failed: {e}")

        # ID 存在性验证
        validation = verdict.validate_evidence()
        if validation["invalid_claims"] > 0:
            logger.warning(
                f"Chunk {chunk.chunk_id}: {validation['invalid_claims']} "
                f"invalid claims, risk={verdict.hallucination_risk:.2f}"
            )

        # 疑似威胁但无证据 — 由 schema 改造带来的软惩罚机制：
        # threat_detected=True 且 threat_claims=[] 表示 LLM 判定有威胁但无具体断言，
        # 这可能是合理的"疑似"表达，也可能是 LLM 规避 schema 而做的弱化输出。
        # 设置 0.5 幻觉风险下限，强制人工复核，但不当场视为"完全幻觉"。
        if verdict.threat_detected and not verdict.threat_claims:
            verdict.hallucination_risk = max(verdict.hallucination_risk, 0.5)
            verdict.unsubstantiated = True
            logger.info(
                f"Chunk {chunk.chunk_id}: threat_detected=True but no claims "
                f"(疑似无证据), hallucination_risk floored to 0.5"
            )

        if verdict.threat_detected:
            logger.info(
                f"Chunk {chunk.chunk_id}: {len(claims)} claims, "
                f"grounding={verdict.grounding_score:.2f}, "
                f"risk={verdict.hallucination_risk:.2f}"
            )

        return verdict

    def _system_prompt(self) -> str:
        return (
            "你是严谨的安全分析专家。"
            "严格遵循输出格式。每条断言必须附带事件ID和原始字段引用。"
            "没有证据不要编造。引用必须逐字来自事件数据。"
        )

    def _build_prompt(self, block_text: str) -> str:
        return f"""请逐条分析以下事件块。

{block_text}

## Grounding 强制要求（违反任何一条将导致结论被丢弃）
1. 每条威胁判定必须包含 "evidence_ids": [事件ID列表]
2. 每条威胁判定必须包含 "evidence_quotes": ["从事件原始数据中逐字引用的片段"]
   - 引用必须来自事件的 message、src_ip、dst_ip 等字段的原始文本
   - 禁止改写、概括或编造引用内容
   - 示例: 如果事件 message 是 "SSH暴力破解攻击已拦截"，则引用 "SSH暴力破解攻击已拦截"
3. 没有事件 ID + 字段引用支撑的断言将被程序化验证器自动丢弃

## 输出格式（严格 JSON，不要输出其他内容）
{{
    "threat_detected": true/false,
    "threat_claims": [
        {{
            "type": "C2/DDoS/数据外泄/横向移动/端口扫描/暴力破解/其他",
            "confidence": 0.0-1.0,
            "evidence_ids": [事件ID1, 事件ID2],
            "evidence_quotes": ["从事件原始数据逐字引用的片段1", "片段2"],
            "severity": "critical/high/medium/low/info",
            "summary": "该威胁的具体描述（必须引用事件内容）"
        }}
    ],
    "confidence": 0.0-1.0,
    "severity": "critical/high/medium/low/info",
    "summary": "该块综合分析",
    "suspicious_entities": ["IP/用户"],
    "alert": "一句话告警（如有）"
}}

## 注意
1. 没有威胁时 threat_detected=false, threat_claims=[]
2. evidence_quotes 中的每个字符串必须能在事件原始数据中找到原文
3. 宁可少报也不捏造证据"""


sub_auditor = SubAuditor()
