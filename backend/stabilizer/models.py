"""Stabilizer 数据结构：描述 LLM 原始输出到稳定工具调用 dict 的修复过程。

适配平台 Audit-LLM 管线，不依赖外部 pydantic 模型，
输出为纯 dict 结构（tool_name + parameters）。
"""
from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class RepairStep:
    """单步修复动作记录。"""
    stage: str          # json_parse / tool_resolve / param_coerce / schema_check
    action: str         # 具体动作描述
    success: bool
    before: Any = None
    after: Any = None
    note: str = ""


@dataclass
class StabilizerResult:
    """Stabilizer 最终输出。

    成功时 request 为 dict:
        {
            "tool_name": "event_store.query",
            "parameters": {...},
            "tool_match_method": "exact" | "prefix" | "fuzzy",
        }
    """
    success: bool
    request: Optional[dict] = None
    error: Optional[str] = None
    error_type: Optional[str] = None       # json_error / unknown_tool / param_invalid / ...
    feedback_to_llm: Optional[str] = None  # 失败时构造给 LLM 的中文修正提示
    repair_steps: list = field(default_factory=list)

    @property
    def repairs_applied(self) -> int:
        """实际生效的修复步数。"""
        return sum(1 for s in self.repair_steps if s.success and s.action != "no_change")
