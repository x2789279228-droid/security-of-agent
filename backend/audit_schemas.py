"""
结构化输出验证 — 用 Pydantic 模型强制校验 LLM 输出

解决问题：
  当前所有 LLM 输出解析都是 json.loads + try/except，
  格式错误时静默降级，无法发现 LLM 的结构性幻觉。

三层验证：
  1. JSON 可解析性（json.loads）
  2. 结构完整性（Pydantic 模型验证）
  3. 语义一致性（字段值域检查）

用法：
    from audit_schemas import validate_sub_auditor_output
    result, errors = validate_sub_auditor_output(llm_raw_text)
    if errors:
        # 重试或降级
"""
import json
import logging
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_THREAT_TYPES = {
    "C2", "DDoS", "数据外泄", "横向移动", "勒索软件",
    "端口扫描", "暴力破解", "SQL注入", "XSS", "恶意软件",
    "权限提升", "未授权访问", "其他", "混合",
}
VALID_CONCLUSIONS = {"threat_confirmed", "false_positive", "suspicious"}


# ═══════════════════════════════════════════
# SubAuditor 输出模型
# ═══════════════════════════════════════════

class ThreatClaimSchema(BaseModel):
    """单条威胁断言 — 强制 Grounding 字段"""
    type: str = Field(..., description="威胁类型")
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_ids: list[int] = Field(..., description="支撑该断言的事件 ID 列表")
    evidence_quotes: list[str] = Field(
        default_factory=list,
        description="从原始事件中引用的具体字段值（如 message 片段、IP 地址）",
    )
    severity: str = Field(..., description="严重度")
    summary: str = Field(..., description="断言描述")

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_SEVERITIES:
            raise ValueError(f"无效 severity: {v}，必须是 {VALID_SEVERITIES}")
        return v

    @field_validator("evidence_ids")
    @classmethod
    def check_evidence_ids(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError("evidence_ids 不能为空 — 每条断言必须有证据")
        return v


class SubAuditorOutputSchema(BaseModel):
    """SubAuditor LLM 输出的结构化验证"""
    threat_detected: bool
    threat_claims: list[ThreatClaimSchema] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str
    summary: str
    suspicious_entities: list[str] = Field(default_factory=list)
    alert: str = ""

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        return v.lower().strip()

    # 注：原先 threat_detected=True 且 threat_claims=[] 时强制 raise，
    # 反幻觉设计意图正确，但实践会逼迫 LLM 为通过 schema 而捏造 claim
    # （伪造 evidence_ids 与 evidence_quotes），反而破坏 GroundingVerifier 的输入。
    # 改为允许通过 — 上层 sub_auditor.audit 通过 hallucination_risk 阈值机制
    # 对"疑似威胁但无证据"语义进行软惩罚，避免诱发 LLM 幻觉。


# ═══════════════════════════════════════════
# Executor 汇总输出模型
# ═══════════════════════════════════════════

class SynthesisOutputSchema(BaseModel):
    """Executor 汇总结论的结构化验证"""
    threat_detected: bool
    threat_type: str = ""
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str
    summary: str
    affected_entities: dict = Field(default_factory=dict)
    suggested_actions: list[str] = Field(default_factory=list)
    needs_human_review: bool = False
    evidence_summary: str = ""

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_SEVERITIES:
            raise ValueError(f"无效 severity: {v}")
        return v


# ═══════════════════════════════════════════
# Reviewer 输出模型
# ═══════════════════════════════════════════

class HallucinationCheckSchema(BaseModel):
    """Reviewer 的幻觉检查结果"""
    has_unsubstantiated_claims: bool = False
    unsubstantiated_details: list[str] = Field(default_factory=list)
    data_consistency: str = "consistent"
    confidence_overinflation: bool = False


class ReviewerOutputSchema(BaseModel):
    """Reviewer LLM 输出的结构化验证"""
    conclusion: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    hallucination_check: HallucinationCheckSchema = Field(
        default_factory=HallucinationCheckSchema
    )
    missed_threats: list[dict] = Field(default_factory=list)
    evidence_chain: list[str] = Field(default_factory=list)
    human_intervention: bool = False
    final_summary: str = ""
    reviewer_notes: str = ""

    @field_validator("conclusion")
    @classmethod
    def check_conclusion(cls, v: str) -> str:
        v = v.strip()
        if v not in VALID_CONCLUSIONS:
            raise ValueError(f"无效 conclusion: {v}，必须是 {VALID_CONCLUSIONS}")
        return v


# ═══════════════════════════════════════════
# 验证函数（带 JSON 提取 + 重试逻辑）
# ═══════════════════════════════════════════

def extract_json(text: str) -> Optional[dict]:
    """
    从 LLM 输出中提取 JSON

    处理常见情况：
    - 纯 JSON
    - ```json ... ``` 代码块
    - JSON 前后有解释文字
    - 单引号 / 尾逗号 / 未加引号键（通过 stabilizer.json_repair 兜底）
    """
    text = text.strip()

    # 尝试直接解析
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 尝试提取 ```json ... ``` 代码块
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 尝试找到第一个 { 和最后一个 }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    # 兜底: 使用 stabilizer 的 JsonRepair 修复畸形 JSON
    try:
        from stabilizer.json_repair import JsonRepair
        repaired, _ = JsonRepair().repair(text)
        if repaired is not None:
            return repaired
    except Exception:
        pass

    return None


def validate_sub_auditor_output(raw_text: str) -> tuple[Optional[dict], list[str]]:
    """
    验证 SubAuditor 的 LLM 输出

    Returns:
        (parsed_dict, errors) — errors 为空表示验证通过
    """
    errors = []

    parsed = extract_json(raw_text)
    if parsed is None:
        return None, ["JSON 解析失败：无法从 LLM 输出中提取有效 JSON"]

    try:
        model = SubAuditorOutputSchema(**parsed)
        return model.model_dump(), []
    except Exception as e:
        errors.append(f"结构验证失败: {e}")
        return parsed, errors


def validate_synthesis_output(raw_text: str) -> tuple[Optional[dict], list[str]]:
    """验证 Executor 汇总输出"""
    errors = []

    parsed = extract_json(raw_text)
    if parsed is None:
        return None, ["JSON 解析失败"]

    try:
        model = SynthesisOutputSchema(**parsed)
        return model.model_dump(), []
    except Exception as e:
        errors.append(f"结构验证失败: {e}")
        return parsed, errors


def validate_reviewer_output(raw_text: str) -> tuple[Optional[dict], list[str]]:
    """验证 Reviewer 输出"""
    errors = []

    parsed = extract_json(raw_text)
    if parsed is None:
        return None, ["JSON 解析失败"]

    try:
        model = ReviewerOutputSchema(**parsed)
        return model.model_dump(), []
    except Exception as e:
        errors.append(f"结构验证失败: {e}")
        return parsed, errors
