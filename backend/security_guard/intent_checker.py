"""调用意图审查：判断安全动作是否与威胁等级匹配。

核心问题：响应引擎执行安全动作前，需确认该动作对当前威胁等级是否合理。
检查维度：
  1. 威胁等级 vs 允许动作矩阵
  2. 调用理由是否合理（不能为空、不能太简单）
"""
from .check_result import CheckResult


class IntentChecker:
    """调用意图审查器：威胁等级与动作匹配性检查。"""

    # 威胁等级 → 允许执行的动作列表
    # critical: 所有动作均可执行
    # high: 允许封禁、隔离、限速、告警
    # medium: 仅允许限速和告警
    # low/info: 仅允许告警
    THREAT_ACTION_MATRIX = {
        "critical": ["block_ip", "isolate_host", "terminate_process", "rate_limit", "alert_only"],
        "high": ["block_ip", "isolate_host", "rate_limit", "alert_only"],
        "medium": ["rate_limit", "alert_only"],
        "low": ["alert_only"],
        "info": ["alert_only"],
    }

    # 无意义理由黑名单（防止 LLM 生成敷衍理由）
    TRIVIAL_REASONS = {"test", "测试", "tmp", "临时", "无", "none", "null", ""}

    def check(self, action_name: str, threat_info: dict) -> CheckResult:
        """检查动作意图是否合理。

        Args:
            action_name: 要执行的安全动作名称
            threat_info: 威胁上下文信息，包含 threat_level, reason 等字段

        Returns:
            CheckResult: 检查结果
        """
        threat_level = threat_info.get("threat_level", "unknown")
        reason = threat_info.get("reason", "")

        issues = []

        # ---- 检查1：调用理由是否合理 ----
        if not reason or len(reason.strip()) < 3:
            issues.append("调用理由为空或过于简单，无法判断执行必要性")
        elif reason.strip().lower() in self.TRIVIAL_REASONS:
            issues.append(f"调用理由 '{reason}' 不像是正式的安全处置理由")

        # ---- 检查2：威胁等级与动作匹配性 ----
        if threat_level != "unknown":
            allowed_actions = self.THREAT_ACTION_MATRIX.get(threat_level, [])
            if allowed_actions and action_name not in allowed_actions:
                issues.append(
                    f"威胁等级 '{threat_level}' 不允许执行动作 '{action_name}'，"
                    f"该等级仅允许: {allowed_actions}"
                )
        else:
            # 未知威胁等级视为不可信，仅允许告警
            if action_name != "alert_only":
                issues.append(
                    f"威胁等级未知(unknown)，不允许执行 '{action_name}'，仅允许 alert_only"
                )

        if issues:
            return CheckResult(
                check_name="调用意图审查",
                passed=False,
                message="调用意图不合理: " + "; ".join(issues),
                details={"issues": issues, "threat_level": threat_level, "action": action_name},
            )

        return CheckResult(
            check_name="调用意图审查",
            passed=True,
            message=f"调用意图合理（威胁等级:{threat_level} 动作:{action_name}）",
            details={"threat_level": threat_level, "action": action_name, "reason": reason},
        )
