"""安全检查结果数据结构。

所有安全检查模块统一返回 CheckResult，便于编排器汇总决策。
"""
from dataclasses import dataclass, field


@dataclass
class CheckResult:
    """单项安全检查的结果。"""
    check_name: str       # 检查名称（如 "调用意图审查"）
    passed: bool          # 是否通过
    message: str          # 结果描述
    details: dict = field(default_factory=dict)  # 附加详情
