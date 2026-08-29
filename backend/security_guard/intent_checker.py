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
    # send_alert 与 alert_only 同义（策略层用 send_alert，护栏矩阵统一认可）
    THREAT_ACTION_MATRIX = {
        "critical": [
            "block_ip", "isolate_host", "terminate_process",
            "rate_limit", "alert_only", "send_alert",
        ],
        "high": [
            "block_ip", "isolate_host", "rate_limit", "alert_only", "send_alert",
        ],
        "medium": ["rate_limit", "alert_only", "send_alert"],
        "low": ["alert_only", "send_alert"],
        "info": ["alert_only", "send_alert"],
    }

    ALERT_ACTIONS = frozenset({"alert_only", "send_alert"})
    VALID_LEVELS = frozenset({"critical", "high", "medium", "low", "info"})

    # 无意义理由黑名单（防止 LLM 生成敷衍理由）
    TRIVIAL_REASONS = {"test", "测试", "tmp", "临时", "无", "none", "null", ""}

    @classmethod
    def resolve_threat_level(cls, threat_info: dict) -> str:
        """兼容 severity / threat_level 两种字段。"""
        raw = (
            threat_info.get("threat_level")
            or threat_info.get("severity")
            or "unknown"
        )
        level = str(raw).strip().lower()
        return level if level in cls.VALID_LEVELS else "unknown"

    @classmethod
    def resolve_reason(cls, threat_info: dict) -> str:
        """兼容 reason / message；必要时合成可审计理由。"""
        reason = str(threat_info.get("reason") or "").strip()
        if reason and len(reason) >= 3 and reason.lower() not in cls.TRIVIAL_REASONS:
            return reason
        message = str(threat_info.get("message") or "").strip()
        if message and len(message) >= 3 and message.lower() not in cls.TRIVIAL_REASONS:
            return message
        threat_type = threat_info.get("threat_type") or threat_info.get("event") or "UNKNOWN"
        severity = threat_info.get("severity") or threat_info.get("threat_level") or "unknown"
        try:
            conf = float(threat_info.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0.0
        return (
            f"Policy response for {threat_type}: "
            f"severity={severity} confidence={conf:.2f}"
        )

    def check(self, action_name: str, threat_info: dict) -> CheckResult:
        """检查动作意图是否合理。

        Args:
            action_name: 要执行的安全动作名称
            threat_info: 威胁上下文信息，包含 threat_level, reason 等字段

        Returns:
            CheckResult: 检查结果
        """
        threat_level = self.resolve_threat_level(threat_info)
        reason = self.resolve_reason(threat_info)

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
            # 未知威胁等级视为不可信，仅允许告警类动作
            if action_name not in self.ALERT_ACTIONS:
                issues.append(
                    f"威胁等级未知(unknown)，不允许执行 '{action_name}'，"
                    f"仅允许 {sorted(self.ALERT_ACTIONS)}"
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
