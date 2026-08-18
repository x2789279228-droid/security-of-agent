"""
grounding_verifier.py — 程序化字段级溯源验证器

安全审计 AI 平台的幻觉检测核心组件。
通过多层程序化验证（完全同步、无 LLM 调用），确保 LLM 生成的威胁声明
确实基于原始事件数据，而非模型幻觉。

验证层级：
  Layer 1: 证据 ID 存在性验证 — evidence_ids 是否在事件块中存在
  Layer 2: 字段值溯源验证（核心） — evidence_quotes 是否能在引用事件中找到原文
  Layer 3: 实体一致性验证 — summary 中提及的 IP/severity 是否与事件数据一致
  Layer 4: 知识库一致性验证 — 威胁类型是否有 RAG 知识库支撑

设计原则：
  - 纯程序化硬校验，不依赖任何 LLM 推理
  - 仅使用标准库，无外部依赖
  - 大小写不敏感的子串匹配，容忍 LLM 的微小格式差异
  - 加权综合评分，区分"完全溯源"/"部分溯源"/"无溯源"三档

用法：
    from grounding_verifier import grounding_verifier

    report = grounding_verifier.verify_chunk(
        claims=threat_claims,
        events=chunk_events,
        knowledge_chunks=rag_results,  # 可选
    )
    if report.overall_score < 0.6:
        # 触发人工复核或拒绝该审计结论
        ...
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── 事件字段列表：Layer 2 溯源搜索的目标字段 ──
# 这些是事件 dict 中所有可能包含引用文本的字符串字段
_EVENT_STRING_FIELDS = ("message", "src_ip", "dst_ip", "event_type", "severity", "protocol")

# ── IP 地址正则：Layer 3 从 summary 中提取 IP ──
_IP_PATTERN = re.compile(r"\d+\.\d+\.\d+\.\d+")

# ── 严重度关键词映射：Layer 3 从 summary 中提取严重度描述 ──
# 将中英文严重度表述统一映射到标准值
_SEVERITY_KEYWORDS: dict[str, str] = {
    # 英文
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    # 中文
    "严重": "critical",
    "紧急": "critical",
    "高危": "high",
    "高": "high",
    "中危": "medium",
    "中": "medium",
    "低危": "low",
    "低": "low",
    "信息": "info",
}

# ── 综合评分权重 ──
_WEIGHT_ID_VALIDITY = 0.15      # Layer 1: ID 存在性
_WEIGHT_GROUNDING_RATIO = 0.40  # Layer 2: 字段值溯源（核心）
_WEIGHT_ENTITY_CONSISTENCY = 0.15  # Layer 3: 实体一致性
_WEIGHT_KNOWLEDGE = 0.10        # Layer 4: 知识库支撑
_WEIGHT_FRESHNESS = 0.10        # Layer 5: 证据新鲜度
_WEIGHT_CHAIN_INTEGRITY = 0.10  # Layer 6+7: 跨源一致性 + 链完整性

# ── 判定阈值 ──
_VERDICT_GROUNDED_THRESHOLD = 0.8
_VERDICT_PARTIAL_THRESHOLD = 0.4


# ═══════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════

@dataclass
class ClaimGroundingReport:
    """单条威胁声明的溯源验证结果"""

    claim_type: str               # 威胁类型（来自 claim 的 type 字段）
    claim_summary: str            # 摘要文本（截断至 200 字符）
    evidence_ids: list[int]       # 声明引用的证据 ID 列表

    # Layer 1: ID 存在性
    ids_valid: bool               # 所有 ID 是否存在于事件块中
    missing_ids: list[int]        # 未找到的 ID

    # Layer 2: 字段值溯源
    total_quotes: int             # 引用文本总数
    grounded_quotes: int          # 成功溯源的引用数
    ungrounded_quotes: list[str]  # 未能在事件中找到原文的引用
    grounding_ratio: float        # 溯源率 0-1

    # Layer 3: 实体一致性
    mentioned_ips: list[str]      # summary 中提及的 IP 地址
    verified_ips: list[str]       # 在引用事件中确认存在的 IP
    phantom_ips: list[str]        # 提及但事件中不存在的"幻影 IP"
    entity_consistency: float     # 实体一致性得分 0-1

    # Layer 4: 知识库一致性
    knowledge_supported: bool     # 威胁类型是否有知识库支撑

    # Layer 5: 证据新鲜度
    stale_evidence_ids: list[int] = field(default_factory=list)  # 过期证据 ID
    freshness_score: float = 1.0  # 新鲜度得分 0-1

    # Layer 6: 跨源冲突
    cross_source_conflicts: list[str] = field(default_factory=list)  # 冲突描述
    source_consistency: float = 1.0  # 跨源一致性 0-1

    # Layer 7: 证据链完整性
    chain_breaks: list[str] = field(default_factory=list)  # 断裂描述
    chain_integrity: float = 1.0  # 链完整性 0-1

    # 综合评分
    # 注：原代码此处缺少默认值，导致 ClaimGroundingReport 在 dataclass 装饰时
    # raise TypeError: non-default argument follows default argument。
    # 这使 grounding_verifier 模块无法被 import，SubAuditor 中的 verify_chunk
    # 调用全部被 except 静默吞掉 — Layer 1-7 程序化校验实际从未生效。
    # 补默认值后回归正常路径；正确值会在 _verify_single_claim 中被显式覆盖。
    grounding_score: float = 1.0  # 加权综合得分 0-1
    verdict: str = "ungrounded"   # "grounded" | "partially_grounded" | "ungrounded"


@dataclass
class GroundingReport:
    """事件块内所有威胁声明的完整溯源报告"""

    chunk_id: str
    claims: list[ClaimGroundingReport]
    total_claims: int
    grounded_claims: int          # verdict == "grounded" 的数量
    partially_grounded: int       # verdict == "partially_grounded" 的数量
    ungrounded_claims: int        # verdict == "ungrounded" 的数量
    overall_score: float          # 所有声明的平均综合得分 0-1
    hallucination_indicators: list[str]  # 人类可读的幻觉风险警告


# ═══════════════════════════════════════════
# 核心验证器
# ═══════════════════════════════════════════

class GroundingVerifier:
    """
    程序化字段级溯源验证器

    对 LLM 生成的每条威胁声明执行四层硬校验，
    不依赖任何 LLM 推理，确保审计结论可追溯到原始数据。
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger(f"{__name__}.GroundingVerifier")

    # ───────────────────────────────────────
    # 公开接口
    # ───────────────────────────────────────

    def verify_chunk(
        self,
        claims: list[dict],
        events: list[dict],
        knowledge_chunks: list[dict] | None = None,
        chunk_id: str = "",
    ) -> GroundingReport:
        """
        对一个事件块内的所有威胁声明执行溯源验证

        Args:
            claims: 威胁声明列表，每条包含:
                    type, confidence, evidence_ids, evidence_quotes, severity, summary
            events: 事件块中的实际事件列表，每条包含:
                    id, event_type, severity, src_ip, dst_ip, message, protocol
            knowledge_chunks: 可选，RAG 检索到的知识库片段列表，
                              每条包含 threat_types (list[str])
            chunk_id: 事件块标识，用于报告标记

        Returns:
            GroundingReport — 完整溯源报告
        """
        if knowledge_chunks is None:
            knowledge_chunks = []

        self._logger.info(
            "开始溯源验证: chunk=%s, claims=%d, events=%d, knowledge=%d",
            chunk_id or "(未命名)", len(claims), len(events), len(knowledge_chunks),
        )

        # 构建事件 ID 索引，加速 Layer 1/2/3 的查找
        event_index = self._build_event_index(events)

        claim_reports: list[ClaimGroundingReport] = []
        hallucination_indicators: list[str] = []

        for idx, claim in enumerate(claims):
            report = self._verify_single_claim(
                claim=claim,
                event_index=event_index,
                knowledge_chunks=knowledge_chunks,
                claim_index=idx,
            )
            claim_reports.append(report)

            # 收集幻觉风险指标
            indicators = self._collect_indicators(report, idx)
            hallucination_indicators.extend(indicators)

        # 汇总统计
        grounded_count = sum(1 for r in claim_reports if r.verdict == "grounded")
        partial_count = sum(1 for r in claim_reports if r.verdict == "partially_grounded")
        ungrounded_count = sum(1 for r in claim_reports if r.verdict == "ungrounded")
        overall_score = (
            sum(r.grounding_score for r in claim_reports) / len(claim_reports)
            if claim_reports
            else 1.0  # 无声明时视为无风险
        )

        full_report = GroundingReport(
            chunk_id=chunk_id,
            claims=claim_reports,
            total_claims=len(claim_reports),
            grounded_claims=grounded_count,
            partially_grounded=partial_count,
            ungrounded_claims=ungrounded_count,
            overall_score=round(overall_score, 4),
            hallucination_indicators=hallucination_indicators,
        )

        self._logger.info(
            "溯源验证完成: chunk=%s, overall=%.3f, grounded=%d/%d, 警告=%d条",
            chunk_id or "(未命名)",
            full_report.overall_score,
            grounded_count,
            full_report.total_claims,
            len(hallucination_indicators),
        )

        return full_report

    # ───────────────────────────────────────
    # 单条声明验证（四层）
    # ───────────────────────────────────────

    def _verify_single_claim(
        self,
        claim: dict,
        event_index: dict[int, dict],
        knowledge_chunks: list[dict],
        claim_index: int,
    ) -> ClaimGroundingReport:
        """对单条威胁声明执行全部四层验证"""

        claim_type = claim.get("type", "未知")
        summary = claim.get("summary", "")
        evidence_ids = claim.get("evidence_ids", [])
        evidence_quotes = claim.get("evidence_quotes", [])
        claim_severity = claim.get("severity", "")

        # ── Layer 1: 证据 ID 存在性验证 ──
        ids_valid, missing_ids = self._verify_id_existence(evidence_ids, event_index)

        # ── Layer 2: 字段值溯源验证（核心层） ──
        # 仅搜索 evidence_ids 引用的事件，而非全量事件
        referenced_events = [
            event_index[eid] for eid in evidence_ids if eid in event_index
        ]
        (
            total_quotes,
            grounded_count,
            ungrounded,
            grounding_ratio,
        ) = self._verify_field_grounding(evidence_quotes, referenced_events)

        # ── Layer 3: 实体一致性验证 ──
        (
            mentioned_ips,
            verified_ips,
            phantom_ips,
            entity_consistency,
        ) = self._verify_entity_consistency(
            summary=summary,
            claim_severity=claim_severity,
            referenced_events=referenced_events,
        )

        # ── Layer 4: 知识库一致性验证 ──
        knowledge_supported = self._verify_knowledge_consistency(
            claim_type=claim_type,
            knowledge_chunks=knowledge_chunks,
        )

        # ── 综合评分 ──
        # id_validity 使用比例而非布尔值，允许"部分 ID 缺失"的中间态
        id_validity_ratio = (
            (len(evidence_ids) - len(missing_ids)) / len(evidence_ids)
            if evidence_ids
            else 1.0
        )
        knowledge_score = 1.0 if knowledge_supported else 0.0

        # ── Layer 5: 证据新鲜度 ──
        stale_ids, freshness = self._verify_evidence_freshness(
            evidence_ids, event_index
        )

        # ── Layer 6: 跨源冲突 ──
        conflicts, source_consistency = self._verify_cross_source_consistency(
            referenced_events
        )

        # ── Layer 7: 证据链完整性 ──
        chain_breaks, chain_integrity = self._verify_chain_integrity(
            evidence_ids, event_index
        )

        grounding_score = (
            id_validity_ratio * _WEIGHT_ID_VALIDITY
            + grounding_ratio * _WEIGHT_GROUNDING_RATIO
            + entity_consistency * _WEIGHT_ENTITY_CONSISTENCY
            + knowledge_score * _WEIGHT_KNOWLEDGE
            + freshness * _WEIGHT_FRESHNESS
            + (source_consistency * 0.5 + chain_integrity * 0.5) * _WEIGHT_CHAIN_INTEGRITY
        )
        grounding_score = round(min(max(grounding_score, 0.0), 1.0), 4)

        # 判定档位
        if grounding_score >= _VERDICT_GROUNDED_THRESHOLD:
            verdict = "grounded"
        elif grounding_score >= _VERDICT_PARTIAL_THRESHOLD:
            verdict = "partially_grounded"
        else:
            verdict = "ungrounded"

        self._logger.debug(
            "声明[%d] (%s) 验证: score=%.3f, verdict=%s, "
            "ids_ok=%s, grounding=%.2f, entity=%.2f, knowledge=%s",
            claim_index, claim_type, grounding_score, verdict,
            ids_valid, grounding_ratio, entity_consistency, knowledge_supported,
        )

        return ClaimGroundingReport(
            claim_type=claim_type,
            claim_summary=summary[:200],
            evidence_ids=evidence_ids,
            ids_valid=ids_valid,
            missing_ids=missing_ids,
            total_quotes=total_quotes,
            grounded_quotes=grounded_count,
            ungrounded_quotes=ungrounded,
            grounding_ratio=round(grounding_ratio, 4),
            mentioned_ips=mentioned_ips,
            verified_ips=verified_ips,
            phantom_ips=phantom_ips,
            entity_consistency=round(entity_consistency, 4),
            knowledge_supported=knowledge_supported,
            stale_evidence_ids=stale_ids,
            freshness_score=round(freshness, 4),
            cross_source_conflicts=conflicts,
            source_consistency=round(source_consistency, 4),
            chain_breaks=chain_breaks,
            chain_integrity=round(chain_integrity, 4),
            grounding_score=grounding_score,
            verdict=verdict,
        )

    # ───────────────────────────────────────
    # Layer 1: 证据 ID 存在性
    # ───────────────────────────────────────

    def _verify_id_existence(
        self,
        evidence_ids: list[int],
        event_index: dict[int, dict],
    ) -> tuple[bool, list[int]]:
        """
        检查声明引用的每个 evidence_id 是否存在于事件块中

        安全逻辑：LLM 可能凭空捏造不存在的事件 ID 来伪装证据充分，
        这是最基础的幻觉检测——引用的证据必须真实存在。

        Returns:
            (ids_valid, missing_ids)
        """
        if not evidence_ids:
            # 无证据引用本身就是高风险信号，但 ID 验证层视为空集通过
            return True, []

        missing = [eid for eid in evidence_ids if eid not in event_index]
        return len(missing) == 0, missing

    # ───────────────────────────────────────
    # Layer 2: 字段值溯源（核心层）
    # ───────────────────────────────────────

    def _verify_field_grounding(
        self,
        evidence_quotes: list[str],
        referenced_events: list[dict],
    ) -> tuple[int, int, list[str], float]:
        """
        验证 evidence_quotes 中的每段引用文本是否确实出现在引用事件的原始字段中

        安全逻辑：这是反幻觉的核心防线。LLM 可能生成看似合理但实际不存在的
        "引用"——例如编造一条从未出现过的攻击 payload 或日志消息。
        通过子串匹配（大小写不敏感）验证每段引用是否有原文支撑。

        匹配策略：
          - 对每段 quote，遍历所有引用事件的所有字符串字段
          - 使用大小写不敏感的子串匹配（容忍 LLM 的大小写差异）
          - 空白字符归一化（将连续空白压缩为单个空格），容忍格式微调

        Returns:
            (total_quotes, grounded_count, ungrounded_quotes, grounding_ratio)
        """
        total = len(evidence_quotes)
        if total == 0:
            # 无引用文本：无法证伪，溯源率视为 1.0（空真）
            # 但上层会通过 hallucination_indicators 标记"缺少引用"的风险
            return 0, 0, [], 1.0

        if not referenced_events:
            # 有引用但无可用事件（所有 ID 均缺失）：全部视为无溯源
            return total, 0, list(evidence_quotes), 0.0

        # 预构建：将所有引用事件的所有字符串字段值拼接为搜索语料库
        # 对每个字段值做小写 + 空白归一化处理
        corpus = self._build_search_corpus(referenced_events)

        grounded_count = 0
        ungrounded: list[str] = []

        for quote in evidence_quotes:
            if self._quote_exists_in_corpus(quote, corpus):
                grounded_count += 1
            else:
                ungrounded.append(quote)

        ratio = grounded_count / total
        return total, grounded_count, ungrounded, ratio

    def _build_search_corpus(self, events: list[dict]) -> list[str]:
        """
        将事件的所有字符串字段值提取并归一化，构建搜索语料库

        归一化规则：小写 + 连续空白压缩为单空格 + 首尾去空白
        """
        corpus: list[str] = []
        for event in events:
            for field_name in _EVENT_STRING_FIELDS:
                value = event.get(field_name)
                if value is not None:
                    normalized = self._normalize_text(str(value))
                    if normalized:
                        corpus.append(normalized)
        return corpus

    def _quote_exists_in_corpus(self, quote: str, corpus: list[str]) -> bool:
        """
        检查单段引用是否在语料库中存在（大小写不敏感子串匹配）

        对 quote 同样做归一化处理后再匹配，
        避免 LLM 输出的引号、多余空格等格式差异导致误判。
        """
        normalized_quote = self._normalize_text(quote)
        if not normalized_quote:
            # 空引用或纯空白引用：视为已溯源（无意义引用不惩罚）
            return True

        for text in corpus:
            if normalized_quote in text:
                return True
        return False

    @staticmethod
    def _normalize_text(text: str) -> str:
        """文本归一化：小写 + 空白压缩 + 首尾去空白"""
        text = text.lower().strip()
        text = re.sub(r"\s+", " ", text)
        return text

    @staticmethod
    def _normalize_timestamp(ts) -> float | None:
        """
        将事件时间戳归一为 epoch seconds (float)，用于比较

        支持的输入类型：
          - int/float (epoch seconds 或 epoch millis)
          - ISO 8601 字符串 (含可选时区 / 'Z' 后缀)，例如：
            "2026-08-01T12:00:00+00:00" / "2026-08-01T12:00:00Z" / "2026-08-01 12:00:00"
          - datetime 对象

        事件来源说明：tool_registry._event_store_query 在所有路径上均输出
        `created_at.isoformat()` 形式的字符串（见 event_store.py:204），
        因此 Layer 5 / Layer 7 必须支持 ISO 字符串解析，否则两层均为死代码。
        """
        if ts is None:
            return None
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.timestamp()
        if isinstance(ts, (int, float)):
            return ts / 1000.0 if ts > 1e12 else float(ts)
        if isinstance(ts, str):
            s = ts.strip()
            if not s:
                return None
            # fromisoformat 不支持 'Z' 后缀，统一替换为 +00:00
            s = s.replace("Z", "+00:00")
            # 无时区信息时假定 UTC，避免本地时区偏移污染比较结果
            try:
                dt = datetime.fromisoformat(s)
            except ValueError:
                # 兜底尝试 SQL/常见格式
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        dt = datetime.strptime(s, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        return None

    # ───────────────────────────────────────
    # Layer 3: 实体一致性
    # ───────────────────────────────────────

    def _verify_entity_consistency(
        self,
        summary: str,
        claim_severity: str,
        referenced_events: list[dict],
    ) -> tuple[list[str], list[str], list[str], float]:
        """
        验证 summary 中提及的实体（IP、严重度）是否与引用事件数据一致

        安全逻辑：LLM 常在 summary 中提及"幻影实体"——例如声称
        "攻击者 10.0.0.99 发起了 C2 通信"，但引用事件中根本没有这个 IP。
        这种实体层面的幻觉最具欺骗性，因为整体叙事看起来合理。

        验证内容：
          1. IP 一致性：summary 中的 IP 必须作为 src_ip 或 dst_ip 存在于引用事件
          2. 严重度一致性：summary 中提及的严重度描述应与引用事件的实际严重度兼容

        Returns:
            (mentioned_ips, verified_ips, phantom_ips, entity_consistency)
        """
        # ── IP 验证 ──
        mentioned_ips = self._extract_ips(summary)

        # 收集引用事件中所有实际存在的 IP（src + dst）
        event_ips: set[str] = set()
        for event in referenced_events:
            src = event.get("src_ip", "")
            dst = event.get("dst_ip", "")
            if src:
                event_ips.add(src.strip())
            if dst:
                event_ips.add(dst.strip())

        verified_ips: list[str] = []
        phantom_ips: list[str] = []
        for ip in mentioned_ips:
            if ip in event_ips:
                verified_ips.append(ip)
            else:
                phantom_ips.append(ip)

        # ── 严重度验证 ──
        severity_consistent = self._check_severity_consistency(
            summary=summary,
            claim_severity=claim_severity,
            referenced_events=referenced_events,
        )

        # ── 计算综合实体一致性得分 ──
        entity_consistency = self._compute_entity_score(
            mentioned_ips=mentioned_ips,
            verified_ips=verified_ips,
            severity_consistent=severity_consistent,
            summary=summary,
        )

        return mentioned_ips, verified_ips, phantom_ips, entity_consistency

    def _extract_ips(self, text: str) -> list[str]:
        """从文本中提取所有 IP 地址（去重，保持出现顺序）"""
        raw_matches = _IP_PATTERN.findall(text)
        # 去重但保序
        seen: set[str] = set()
        result: list[str] = []
        for ip in raw_matches:
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
        return result

    def _check_severity_consistency(
        self,
        summary: str,
        claim_severity: str,
        referenced_events: list[dict],
    ) -> bool:
        """
        检查 summary 中提及的严重度是否与引用事件的实际严重度兼容

        策略：
          - 从 summary 中提取严重度关键词
          - 如果 summary 未提及任何严重度，视为一致（不惩罚）
          - 如果提及了，检查引用事件中是否存在对应严重度的事件
          - 允许"向上兼容"：事件是 critical，summary 说 high 也算一致
            （安全审计中低估比高估危害小）

        Returns:
            True = 一致或未提及, False = 不一致
        """
        summary_lower = summary.lower()

        # 从 summary 中提取严重度关键词
        mentioned_severity: str | None = None
        # 按优先级排序匹配（先匹配长词避免"高"误匹配"高危"的子串）
        for keyword in sorted(_SEVERITY_KEYWORDS.keys(), key=len, reverse=True):
            if keyword in summary_lower:
                mentioned_severity = _SEVERITY_KEYWORDS[keyword]
                break

        if mentioned_severity is None:
            # summary 未提及严重度，无法证伪
            return True

        if not referenced_events:
            # 无引用事件可验证，但 claim 有 severity 声明
            # 如果 claim 自身的 severity 字段与 summary 一致，则通过
            return claim_severity.lower().strip() == mentioned_severity

        # 严重度等级序（用于"向上兼容"判断）
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        mentioned_level = severity_order.get(mentioned_severity, -1)

        # 收集引用事件中的实际严重度
        event_severities: set[str] = set()
        for event in referenced_events:
            sev = str(event.get("severity", "")).lower().strip()
            if sev:
                event_severities.add(sev)

        # 精确匹配：summary 提及的严重度直接存在于事件中
        if mentioned_severity in event_severities:
            return True

        # 向上兼容：事件中存在 >= summary 所述严重度的事件
        # 例如事件是 critical，summary 说 "high"，这不算幻觉（只是保守描述）
        for sev in event_severities:
            event_level = severity_order.get(sev, -1)
            if event_level >= mentioned_level and mentioned_level >= 0:
                return True

        # 严重度不一致：summary 声称的严重度在事件中找不到支撑
        self._logger.debug(
            "严重度不一致: summary提及=%s, 事件实际=%s",
            mentioned_severity, event_severities,
        )
        return False

    def _compute_entity_score(
        self,
        mentioned_ips: list[str],
        verified_ips: list[str],
        severity_consistent: bool,
        summary: str,
    ) -> float:
        """
        计算实体一致性综合得分

        组合 IP 验证和严重度验证：
          - 有 IP 提及 + 有严重度提及：ip_ratio * 0.6 + severity * 0.4
          - 仅有 IP 提及：ip_ratio
          - 仅有严重度提及：severity_score
          - 均无提及：1.0（无实体可验证，不惩罚）
        """
        has_ip_check = len(mentioned_ips) > 0
        # 判断 summary 是否提及了严重度关键词
        summary_lower = summary.lower()
        has_severity_mention = any(
            kw in summary_lower for kw in _SEVERITY_KEYWORDS
        )

        if not has_ip_check and not has_severity_mention:
            return 1.0

        ip_ratio = len(verified_ips) / len(mentioned_ips) if mentioned_ips else 1.0
        severity_score = 1.0 if severity_consistent else 0.0

        if has_ip_check and has_severity_mention:
            return ip_ratio * 0.6 + severity_score * 0.4
        elif has_ip_check:
            return ip_ratio
        else:
            return severity_score

    # ───────────────────────────────────────
    # Layer 4: 知识库一致性
    # ───────────────────────────────────────

    def _verify_knowledge_consistency(
        self,
        claim_type: str,
        knowledge_chunks: list[dict],
    ) -> bool:
        """
        检查声明的威胁类型是否有 RAG 知识库支撑

        安全逻辑：如果 RAG 检索到了相关知识片段，那么声明的威胁类型
        应当与知识库中的威胁类型有交集。完全不匹配可能意味着 LLM
        凭空捏造了一种不适用于当前场景的威胁类型。

        注意：当无知识库片段可用时（未执行 RAG 检索或检索为空），
        返回 True（不惩罚），因为缺少知识库不等于声明错误。

        Returns:
            True = 知识库支撑或无知识库可验证, False = 有知识库但不匹配
        """
        if not knowledge_chunks:
            # 无知识库数据，无法验证，不惩罚
            return True

        # 收集知识库中所有威胁类型（小写归一化）
        knowledge_threat_types: set[str] = set()
        for chunk in knowledge_chunks:
            threat_types = chunk.get("threat_types", [])
            if isinstance(threat_types, list):
                for tt in threat_types:
                    knowledge_threat_types.add(str(tt).lower().strip())
            elif isinstance(threat_types, str):
                knowledge_threat_types.add(threat_types.lower().strip())

        if not knowledge_threat_types:
            # 知识库片段中无威胁类型标注，无法验证
            return True

        # 检查 claim_type 是否与知识库中的威胁类型匹配
        # 使用大小写不敏感匹配 + 子串包含（容忍"DDoS" vs "ddos攻击"的差异）
        claim_lower = claim_type.lower().strip()
        for kt in knowledge_threat_types:
            if claim_lower == kt or claim_lower in kt or kt in claim_lower:
                return True

        self._logger.debug(
            "知识库不匹配: claim_type=%s, knowledge_types=%s",
            claim_type, knowledge_threat_types,
        )
        return False

    # ───────────────────────────────────────
    # 辅助方法
    # ───────────────────────────────────────

    @staticmethod
    def _build_event_index(events: list[dict]) -> dict[int, dict]:
        """
        构建事件 ID → 事件 dict 的索引

        安全考虑：如果事件缺少 id 字段或 id 非整数，跳过该事件并记录警告。
        """
        index: dict[int, dict] = {}
        for event in events:
            event_id = event.get("id")
            if event_id is None:
                logger.warning("事件缺少 id 字段，已跳过: %s", str(event)[:100])
                continue
            try:
                event_id_int = int(event_id)
            except (ValueError, TypeError):
                logger.warning("事件 id 非整数，已跳过: id=%r", event_id)
                continue
            index[event_id_int] = event
        return index

    def _collect_indicators(
        self,
        report: ClaimGroundingReport,
        claim_index: int,
    ) -> list[str]:
        """
        从单条声明的验证结果中提取人类可读的幻觉风险警告

        这些警告会汇总到 GroundingReport.hallucination_indicators，
        供人工复核界面展示。
        """
        indicators: list[str] = []
        prefix = f"声明[{claim_index}] ({report.claim_type})"

        # Layer 1 警告：ID 缺失
        if report.missing_ids:
            indicators.append(
                f"{prefix}: 引用了不存在的事件 ID {report.missing_ids}，"
                f"可能是捏造的证据编号"
            )

        # Layer 2 警告：引用文本无溯源
        if report.ungrounded_quotes:
            # 展示前 3 条未溯源引用，避免信息过载
            sample = report.ungrounded_quotes[:3]
            more = len(report.ungrounded_quotes) - len(sample)
            sample_str = "; ".join(f'"{q[:60]}"' for q in sample)
            suffix = f"（另有 {more} 条）" if more > 0 else ""
            indicators.append(
                f"{prefix}: {len(report.ungrounded_quotes)}/{report.total_quotes} "
                f"条引用文本无法在事件原文中找到: {sample_str}{suffix}"
            )

        # Layer 2 警告：完全缺少引用文本
        if report.total_quotes == 0 and report.evidence_ids:
            indicators.append(
                f"{prefix}: 引用了 {len(report.evidence_ids)} 个事件 ID "
                f"但未提供任何引用文本，无法验证证据真实性"
            )

        # Layer 3 警告：幻影 IP
        if report.phantom_ips:
            indicators.append(
                f"{prefix}: summary 中提及的 IP {report.phantom_ips} "
                f"在引用事件中不存在，疑似幻觉实体"
            )

        # Layer 3 警告：实体一致性极低
        if report.entity_consistency < 0.5 and (
            report.mentioned_ips or report.entity_consistency == 0.0
        ):
            indicators.append(
                f"{prefix}: 实体一致性得分仅 {report.entity_consistency:.2f}，"
                f"summary 描述与事件数据严重不符"
            )

        # Layer 4 警告：知识库不支持
        if not report.knowledge_supported:
            indicators.append(
                f"{prefix}: 威胁类型 '{report.claim_type}' "
                f"在 RAG 知识库中无匹配，可能是不适用的威胁分类"
            )

        # 综合警告：整体评分极低
        if report.verdict == "ungrounded":
            indicators.append(
                f"{prefix}: 综合溯源得分 {report.grounding_score:.3f} "
                f"低于阈值 {_VERDICT_PARTIAL_THRESHOLD}，判定为无溯源，"
                f"高度疑似幻觉"
            )

        return indicators

    # ───────────────────────────────────────
    # Layer 5: 证据新鲜度
    # ───────────────────────────────────────

    # 证据有效期：超过 24 小时的证据视为过期
    _EVIDENCE_TTL_SECONDS = 86400

    def _verify_evidence_freshness(
        self,
        evidence_ids: list[int],
        event_index: dict[int, dict],
    ) -> tuple[list[int], float]:
        """
        检查引用证据的时间戳是否在有效期内

        安全逻辑：LLM 可能引用数小时甚至数天前的旧事件作为当前威胁的证据，
        导致基于过期情报做出响应决策。

        Returns:
            (stale_ids, freshness_score)
        """
        import time as _time
        if not evidence_ids:
            return [], 1.0

        now = _time.time()
        stale_ids = []
        for eid in evidence_ids:
            event = event_index.get(eid)
            if not event:
                continue
            ts = event.get("timestamp") or event.get("created_at")
            ts_sec = self._normalize_timestamp(ts)
            if ts_sec is None:
                continue
            age = now - ts_sec
            if age > self._EVIDENCE_TTL_SECONDS:
                stale_ids.append(eid)

        freshness = 1.0 - (len(stale_ids) / max(len(evidence_ids), 1))
        return stale_ids, max(freshness, 0.0)

    # ───────────────────────────────────────
    # Layer 6: 跨源冲突
    # ───────────────────────────────────────

    def _verify_cross_source_consistency(
        self,
        referenced_events: list[dict],
    ) -> tuple[list[str], float]:
        """
        检测引用事件之间是否存在跨源冲突

        安全逻辑：不同数据源可能对同一事件给出矛盾描述。
        例如源 A 报告 "登录成功"，源 B 报告 "登录失败"（同一 IP 同一时间）。

        检测维度：
        1. 同一 src_ip 的 severity 矛盾（info vs critical）
        2. 同一 src_ip 的 event_type 矛盾（USER_LOGIN vs BRUTE_FORCE）

        Returns:
            (conflicts, source_consistency)
        """
        if len(referenced_events) < 2:
            return [], 1.0

        conflicts = []
        # 按 src_ip 分组
        by_ip: dict[str, list[dict]] = {}
        for evt in referenced_events:
            src = evt.get("src_ip", "")
            if src:
                by_ip.setdefault(src, []).append(evt)

        conflict_count = 0
        for ip, events in by_ip.items():
            if len(events) < 2:
                continue
            severities = {str(e.get("severity", "")).lower() for e in events}
            event_types = {str(e.get("event_type", "")).upper() for e in events}

            # severity 矛盾：同时有 info 和 critical/high
            if "info" in severities and ("critical" in severities or "high" in severities):
                conflicts.append(
                    f"IP {ip}: severity 矛盾 ({severities})，"
                    f"同一源同时有 info 和高危事件"
                )
                conflict_count += 1

            # event_type 矛盾：LOGIN 和 BRUTE_FORCE 同时出现
            login_types = {"USER_LOGIN", "SUSPICIOUS_LOGIN"}
            attack_types = {"BRUTE_FORCE", "PORT_SCAN", "C2_BEACON"}
            if (event_types & login_types) and (event_types & attack_types):
                conflicts.append(
                    f"IP {ip}: 行为矛盾 ({event_types})，"
                    f"同一源同时有正常登录和攻击事件"
                )
                conflict_count += 1

        total_pairs = sum(len(evts) * (len(evts) - 1) // 2 for evts in by_ip.values())
        consistency = 1.0 - (conflict_count / max(total_pairs, 1))
        return conflicts, max(consistency, 0.0)

    # ───────────────────────────────────────
    # Layer 7: 证据链完整性
    # ───────────────────────────────────────

    def _verify_chain_integrity(
        self,
        evidence_ids: list[int],
        event_index: dict[int, dict],
    ) -> tuple[list[str], float]:
        """
        检测证据链的连续性和时序逻辑

        安全逻辑：攻击链证据应按时间顺序排列。
        如果引用的事件 ID 存在但时间戳乱序，可能表示 LLM 拼凑了不相关的事件。

        检测维度：
        1. ID 连续性：引用的 ID 是否大致连续（允许间隔，但不应跳跃过大）
        2. 时序一致性：事件时间戳是否按引用顺序递增

        Returns:
            (chain_breaks, chain_integrity)
        """
        if len(evidence_ids) < 2:
            return [], 1.0

        breaks = []

        # 时序一致性检查
        timestamps = []
        for eid in evidence_ids:
            event = event_index.get(eid)
            if event:
                ts = event.get("timestamp") or event.get("created_at")
                timestamps.append(self._normalize_timestamp(ts))
            else:
                timestamps.append(None)

        # 检查时序递增（忽略 None）
        valid_ts = [(i, t) for i, t in enumerate(timestamps) if t is not None]
        time_reversals = 0
        for j in range(1, len(valid_ts)):
            if valid_ts[j][1] < valid_ts[j - 1][1]:
                idx_prev = evidence_ids[valid_ts[j - 1][0]]
                idx_curr = evidence_ids[valid_ts[j][0]]
                breaks.append(
                    f"时序倒置: 事件 #{idx_curr} 早于 #{idx_prev}，"
                    f"证据链时间顺序不一致"
                )
                time_reversals += 1

        # ID 跳跃检查（相邻 ID 差距 > 100 视为断裂）
        for j in range(1, len(evidence_ids)):
            gap = abs(evidence_ids[j] - evidence_ids[j - 1])
            if gap > 100:
                breaks.append(
                    f"ID 跳跃: #{evidence_ids[j-1]} → #{evidence_ids[j]} "
                    f"(间隔 {gap})，证据链可能不连续"
                )

        total_checks = max(len(evidence_ids) - 1, 1)
        integrity = 1.0 - (len(breaks) / (total_checks * 2))  # 每个检查点最多 2 种断裂
        return breaks, max(integrity, 0.0)


# ── 全局单例 ──
# 无状态设计，可安全共享；所有验证方法均为纯函数，无副作用
grounding_verifier = GroundingVerifier()
