"""
响应策略引擎 (Response Policy Engine)

将威胁事件匹配到预定义的响应策略，决定执行哪些动作。
策略支持按威胁类型、严重度、置信度、源IP信誉度等多维度匹配。

策略结构:
  {
      "threat_type": "C2_BEACON",           # 匹配的威胁类型
      "min_confidence": 0.7,                # 最低置信度
      "min_severity": "high",               # 最低严重度
      "actions": [                           # 要执行的动作列表
          {"name": "block_ip", "params": {"duration_minutes": 120}},
          {"name": "send_alert", "params": {"severity": "critical"}},
      ],
      "auto_execute": true,                 # 是否自动执行（false则需审批）
      "require_approval": false,            # 是否强制审批
  }

策略优先级:
  1. 精确匹配 threat_type (优先级最高)
  2. 通配匹配 threat_type (如 ANY)
  3. 按 min_confidence + min_severity 综合匹配
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from .response_registry import response_registry, APPROVAL_REQUIRED

logger = logging.getLogger(__name__)


@dataclass
class ResponsePolicy:
    """单条响应策略"""
    name: str
    threat_type: str                        # "C2_BEACON" | "ANY" 表示匹配所有
    actions: list[dict]                     # [{"name": "block_ip", "params": {...}}, ...]
    min_confidence: float = 0.5
    min_severity: str = "medium"            # info/low/medium/high/critical
    auto_execute: bool = True
    require_approval: bool = False
    priority: int = 10
    description: str = ""
    cooldown_minutes: int = 30              # 同一IP同一策略的冷却时间

    def matches(self, threat_type: str, confidence: float, severity: str) -> bool:
        """检查该策略是否匹配给定威胁"""
        if self.threat_type != "ANY" and self.threat_type != threat_type:
            return False
        if confidence < self.min_confidence:
            return False

        severity_order = ["info", "low", "medium", "high", "critical"]
        try:
            if severity_order.index(severity) < severity_order.index(self.min_severity):
                return False
        except ValueError:
            pass

        return True

    def needs_approval(self) -> bool:
        """该策略是否需要人工审批"""
        if self.require_approval:
            return True
        # 检查是否有高危动作
        for act in self.actions:
            name = act.get("name", "")
            if response_registry.needs_approval(name):
                return True
        return False


@dataclass
class ThreatActionMap:
    """威胁→动作映射结果"""
    policy_name: str
    threat_type: str
    confidence: float
    severity: str
    actions: list[dict]                    # 待执行的动作列表
    needs_approval: bool
    auto_execute: bool
    matched: bool


# ── 默认策略集 ──

DEFAULT_POLICIES = [
    ResponsePolicy(
        name="C2通信自动封禁",
        threat_type="C2_BEACON",
        min_confidence=0.6,
        min_severity="high",
        actions=[
            {"name": "block_ip", "params": {"duration_minutes": 120}},
            {"name": "rate_limit", "params": {"bandwidth_kbps": 100}},
            {"name": "send_alert", "params": {"severity": "critical"}},
        ],
        auto_execute=True,
        priority=100,
        cooldown_minutes=60,
        description="检测到C2回连：封禁IP + 限速 + 告警",
    ),
    ResponsePolicy(
        name="数据外泄紧急隔离",
        threat_type="DATA_EXFIL",
        min_confidence=0.7,
        min_severity="critical",
        actions=[
            {"name": "block_ip", "params": {"duration_minutes": 1440}},
            {"name": "isolate_host", "params": {}},
            {"name": "send_alert", "params": {"severity": "critical"}},
        ],
        auto_execute=False,           # 高危操作需审批
        require_approval=True,
        priority=90,
        cooldown_minutes=120,
        description="数据外泄：封禁IP + 隔离主机（需审批）",
    ),
    ResponsePolicy(
        name="暴力破解自动阻断",
        threat_type="BRUTE_FORCE",
        min_confidence=0.5,
        min_severity="medium",
        actions=[
            {"name": "block_ip", "params": {"duration_minutes": 30}},
            {"name": "send_alert", "params": {"severity": "high"}},
        ],
        auto_execute=True,
        priority=80,
        cooldown_minutes=15,
        description="暴力破解：封禁IP30分钟 + 告警",
    ),
    ResponsePolicy(
        name="端口扫描限速",
        threat_type="PORT_SCAN",
        min_confidence=0.4,
        min_severity="low",
        actions=[
            {"name": "rate_limit", "params": {"bandwidth_kbps": 500}},
            {"name": "send_alert", "params": {"severity": "medium"}},
        ],
        auto_execute=True,
        priority=70,
        cooldown_minutes=10,
        description="端口扫描：限速 + 告警",
    ),
    ResponsePolicy(
        name="恶意软件主机隔离",
        threat_type="MALWARE_DETECT",
        min_confidence=0.6,
        min_severity="high",
        actions=[
            {"name": "isolate_host", "params": {}},
            {"name": "send_alert", "params": {"severity": "critical"}},
        ],
        auto_execute=False,
        require_approval=True,
        priority=90,
        cooldown_minutes=120,
        description="恶意软件：隔离主机（需审批）",
    ),
    ResponsePolicy(
        name="DDoS流量自动防护",
        threat_type="DDoS_TRAFFIC",
        min_confidence=0.5,
        min_severity="high",
        actions=[
            {"name": "rate_limit", "params": {"bandwidth_kbps": 100}},
            {"name": "block_ip", "params": {"duration_minutes": 60}},
            {"name": "send_alert", "params": {"severity": "critical"}},
        ],
        auto_execute=True,
        priority=85,
        cooldown_minutes=30,
        description="DDoS攻击：限速 + 封禁 + 告警",
    ),
    ResponsePolicy(
        name="横向移动主机隔离",
        threat_type="LATERAL_MOVE",
        min_confidence=0.6,
        min_severity="high",
        actions=[
            {"name": "isolate_host", "params": {}},
            {"name": "send_alert", "params": {"severity": "critical"}},
        ],
        auto_execute=False,
        require_approval=True,
        priority=85,
        cooldown_minutes=60,
        description="横向移动：隔离主机（需审批）",
    ),
    ResponsePolicy(
        name="通用威胁告警",
        threat_type="ANY",              # 兜底策略
        min_confidence=0.3,
        min_severity="info",
        actions=[
            {"name": "send_alert", "params": {"severity": "medium"}},
        ],
        auto_execute=True,
        priority=10,
        description="通用兜底：发送告警通知",
    ),
]


class PolicyEngine:
    """响应策略引擎"""

    def __init__(self):
        self._policies: list[ResponsePolicy] = []
        # Cooldown tracking: {policy_name: {src_ip: timestamp}}
        self._cooldowns: dict[str, dict[str, float]] = {}

    def load_defaults(self):
        """加载默认策略"""
        self._policies = DEFAULT_POLICIES
        logger.info(f"Loaded {len(self._policies)} default response policies")

    def add_policy(self, policy: ResponsePolicy):
        self._policies.append(policy)
        self._policies.sort(key=lambda p: p.priority, reverse=True)
        logger.info(f"Added policy: {policy.name} (priority={policy.priority})")

    def remove_policy(self, name: str):
        self._policies = [p for p in self._policies if p.name != name]

    def get_policies(self) -> list[ResponsePolicy]:
        return list(self._policies)

    def get_policy(self, name: str) -> Optional[ResponsePolicy]:
        for p in self._policies:
            if p.name == name:
                return p
        return None

    def match(
        self,
        threat_type: str,
        confidence: float,
        severity: str,
        src_ip: str = "",
    ) -> ThreatActionMap:
        """
        匹配威胁到策略

        Args:
            threat_type: 威胁类型
            confidence: 置信度 0-1
            severity: 严重度
            src_ip: 源IP (用于冷却检查)

        Returns:
            ThreatActionMap
        """
        import time

        for policy in self._policies:
            if not policy.matches(threat_type, confidence, severity):
                continue

            # Cooldown 检查
            if src_ip:
                cooldown_map = self._cooldowns.get(policy.name, {})
                last_run = cooldown_map.get(src_ip, 0)
                elapsed = time.time() - last_run
                if elapsed < policy.cooldown_minutes * 60:
                    logger.info(
                        f"Policy '{policy.name}' in cooldown for {src_ip} "
                        f"({elapsed:.0f}s < {policy.cooldown_minutes*60}s)"
                    )
                    continue

            # 更新 cooldown
            if src_ip:
                self._cooldowns.setdefault(policy.name, {})[src_ip] = time.time()

            needs_approval = policy.needs_approval()

            logger.info(
                f"Policy matched: '{policy.name}' → {threat_type} "
                f"conf={confidence:.2f} sev={severity} "
                f"auto={policy.auto_execute} approval={needs_approval}"
            )

            return ThreatActionMap(
                policy_name=policy.name,
                threat_type=threat_type,
                confidence=confidence,
                severity=severity,
                actions=policy.actions,
                needs_approval=needs_approval,
                auto_execute=policy.auto_execute,
                matched=True,
            )

        return ThreatActionMap(
            policy_name="",
            threat_type=threat_type,
            confidence=confidence,
            severity=severity,
            actions=[],
            needs_approval=False,
            auto_execute=False,
            matched=False,
        )

    def clear_cooldowns(self):
        """清除所有冷却状态（用于测试/人工重置）"""
        self._cooldowns.clear()
        logger.info("All policy cooldowns cleared")


policy_engine = PolicyEngine()
policy_engine.load_defaults()
