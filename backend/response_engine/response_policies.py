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
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .response_registry import response_registry, APPROVAL_REQUIRED

logger = logging.getLogger(__name__)


class MatchStatus(str, Enum):
    """策略匹配一等公民状态 — 禁止再用「matched=False + debug」静默放过。"""
    MATCHED = "matched"
    MATCHED_CATEGORY = "matched_category"   # L3 预留
    MATCHED_BEHAVIOR = "matched_behavior"   # L4 预留
    UNCERTAIN = "uncertain"
    SKIPPED = "skipped"                     # 冷却
    FILTERED = "filtered"                   # 白名单 / 双轨（编排层也可写）
    NO_ACTION = "no_action"                 # 明确良性


# 明确无攻击语义：不走 Uncertain 短封
BENIGN_TYPES = frozenset({
    "USER_LOGIN",
    "FILE_ACCESS",
    "DNS_QUERY",
})

UNCERTAIN_POLICY_NAME = "未知威胁保守遏制"
_ACTIONABLE = frozenset({
    MatchStatus.MATCHED,
    MatchStatus.MATCHED_CATEGORY,
    MatchStatus.MATCHED_BEHAVIOR,
    MatchStatus.UNCERTAIN,
})


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
    policy_id: str = ""                     # YAML id，如 POL-C2-BEACON
    category: str = ""                      # L3 父类（可空）
    enabled: bool = True
    role: str = ""                          # "" | "uncertain_template"
    source_path: str = ""

    def _passes_thresholds(self, confidence: float, severity: str) -> bool:
        if confidence < self.min_confidence:
            return False
        severity_order = ["info", "low", "medium", "high", "critical"]
        try:
            if severity_order.index(severity) < severity_order.index(self.min_severity):
                return False
        except ValueError:
            pass
        return True

    def is_leaf_policy(self) -> bool:
        tt = str(self.threat_type or "").strip()
        return bool(tt) and tt not in ("__UNCERTAIN__",) and self.role != "uncertain_template"

    def is_category_policy(self) -> bool:
        """父类策略：配置了 category，且没有具体 leaf threat_type。"""
        tt = str(self.threat_type or "").strip()
        return bool(self.category) and tt == ""

    def matches(self, threat_type: str, confidence: float, severity: str) -> bool:
        """leaf 精确匹配（category-only 策略在此返回 False）。

        threat_type 大小写不敏感比较（修复 "DDOS_TRAFFIC" 无法命中
        "DDoS_TRAFFIC" 策略的历史 bug）。
        """
        if not self.enabled:
            return False
        if self.role == "uncertain_template":
            return False
        if self.is_category_policy():
            return False
        tt = str(threat_type or "").strip().upper()
        if self.threat_type != "ANY" and self.threat_type.upper() != tt:
            return False
        return self._passes_thresholds(confidence, severity)

    def matches_category(self, category: str, confidence: float, severity: str) -> bool:
        """父类 category 匹配。"""
        if not self.enabled or self.role == "uncertain_template":
            return False
        if not self.is_category_policy():
            return False
        cat = str(category or "").strip().upper()
        if not cat or self.category.upper() != cat:
            return False
        return self._passes_thresholds(confidence, severity)

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

    def to_dict(self) -> dict:
        return {
            "id": self.policy_id,
            "name": self.name,
            "threat_type": self.threat_type,
            "category": self.category,
            "actions": self.actions,
            "min_confidence": self.min_confidence,
            "min_severity": self.min_severity,
            "auto_execute": self.auto_execute,
            "require_approval": self.require_approval,
            "priority": self.priority,
            "cooldown_minutes": self.cooldown_minutes,
            "description": self.description,
            "enabled": self.enabled,
            "role": self.role,
        }


def policy_from_dict(data: dict) -> ResponsePolicy:
    """从 YAML/API 归一化 dict 构造 ResponsePolicy。"""
    return ResponsePolicy(
        name=str(data.get("name") or ""),
        threat_type=str(data.get("threat_type") or ""),
        actions=list(data.get("actions") or []),
        min_confidence=float(data.get("min_confidence", 0.5)),
        min_severity=str(data.get("min_severity") or "medium"),
        auto_execute=bool(data.get("auto_execute", True)),
        require_approval=bool(data.get("require_approval", False)),
        priority=int(data.get("priority", 10)),
        description=str(data.get("description") or ""),
        cooldown_minutes=int(data.get("cooldown_minutes", 30)),
        policy_id=str(data.get("id") or data.get("policy_id") or ""),
        category=str(data.get("category") or ""),
        enabled=bool(data.get("enabled", True)),
        role=str(data.get("role") or ""),
        source_path=str(data.get("_source_path") or data.get("source_path") or ""),
    )


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
    match_status: MatchStatus = MatchStatus.NO_ACTION
    skip_reason: str = ""
    category: str = ""

    def __post_init__(self):
        # 兼容旧调用方: UNCERTAIN 也视为 matched=True（要处置）
        if self.match_status in _ACTIONABLE:
            self.matched = True
        elif self.match_status in (
            MatchStatus.SKIPPED, MatchStatus.NO_ACTION, MatchStatus.FILTERED,
        ):
            self.matched = False


def _uncertain_actions() -> list[dict]:
    return [
        {"name": "block_ip", "params": {"duration_minutes": 5}},
        {"name": "send_alert", "params": {"severity": "high", "priority": "p1"}},
    ]


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
        min_confidence=0.55,
        min_severity="high",
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
        name="数据外泄紧急告警",
        threat_type="DATA_EXFIL",
        min_confidence=0.4,
        min_severity="medium",
        actions=[
            {"name": "send_alert", "params": {"severity": "critical"}},
        ],
        auto_execute=True,
        require_approval=False,
        priority=88,
        cooldown_minutes=30,
        description="数据外泄：至少发送告警（隔离走审批策略）",
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
        name="横向移动主机隔离(别名)",
        threat_type="LATERAL_MOVEMENT",
        min_confidence=0.55,
        min_severity="high",
        actions=[
            {"name": "isolate_host", "params": {}},
            {"name": "send_alert", "params": {"severity": "critical"}},
        ],
        auto_execute=False,
        require_approval=True,
        priority=85,
        cooldown_minutes=60,
        description="横向移动(LATERAL_MOVEMENT)：隔离主机（需审批）",
    ),
    ResponsePolicy(
        name="行为基线异常遏制",
        threat_type="BEHAVIOR_ANOMALY",
        min_confidence=0.5,
        min_severity="high",
        actions=[
            {"name": "block_ip", "params": {"duration_minutes": 15}},
            {"name": "send_alert", "params": {"severity": "high"}},
        ],
        auto_execute=True,
        priority=95,
        cooldown_minutes=15,
        description="L4 代码种子：Flink 行为基线 15 分钟封禁（YAML 优先）",
    ),
    ResponsePolicy(
        name="通用威胁告警",
        threat_type="ANY",
        min_confidence=0.3,
        min_severity="info",
        actions=[
            {"name": "send_alert", "params": {"severity": "medium"}},
            {"name": "block_ip", "params": {"duration_minutes": 60}},
        ],
        auto_execute=True,
        priority=10,
        # L1: Uncertain 开启时不参与未知类型匹配；仅 RESPONSE_UNCERTAIN_ENABLED=false 时作紧急回退
        description="兼容兜底（紧急回退）：未知类型默认走 Uncertain 5 分钟遏制",
    ),
]


class PolicyEngine:
    """响应策略引擎"""

    # 惰性清理间隔（秒）：_cooldowns 只增不删会随 src_ip 数无限增长
    CLEANUP_INTERVAL_SEC = 300
    # 策略已下线时其残留 cooldown 条目的兜底过期时间（秒）
    _ORPHAN_TTL_SEC = 3600

    def __init__(self):
        self._policies: list[ResponsePolicy] = []
        # Cooldown tracking: {policy_name: {src_ip: timestamp}}
        self._cooldowns: dict[str, dict[str, float]] = {}
        self._last_cleanup: float = 0.0
        # v5 修复(2026-09-01):per-IP 聚合冷却 — 同一 IP 无论命中哪个策略，
        # 短窗口内只允许一次响应编排（修复同 IP 1.4s 内 5 策略连发 /
        # 累计 15+ 次 policy_match 的资源浪费问题）
        try:
            self.ip_cooldown_sec = int(os.environ.get("RESPONSE_IP_COOLDOWN_SEC", "60"))
        except ValueError:
            self.ip_cooldown_sec = 60
        # {src_ip: 上次任一策略 match 成功的时间}
        self._ip_last_match: dict[str, float] = {}
        # L1: Uncertain 独立冷却（默认 5 分钟，防未知类型刷屏）
        try:
            self.uncertain_cooldown_sec = int(
                os.environ.get("RESPONSE_UNCERTAIN_COOLDOWN_SEC", "300")
            )
        except ValueError:
            self.uncertain_cooldown_sec = 300
        self._uncertain_last: dict[str, float] = {}
        # 紧急开关：false 时回退到旧 ANY 兜底（60min），默认开启 Uncertain
        _flag = os.environ.get("RESPONSE_UNCERTAIN_ENABLED", "true").strip().lower()
        self.uncertain_enabled = _flag not in ("0", "false", "no", "off")
        # L2: YAML 热加载
        self._policies_dir = os.environ.get(
            "RESPONSE_POLICIES_DIR", ""
        ).strip() or None
        self._loaded_mtime: float = 0.0
        self._last_mtime_check: float = 0.0
        try:
            self.yaml_reload_interval_sec = int(
                os.environ.get("RESPONSE_POLICY_RELOAD_SEC", "30")
            )
        except ValueError:
            self.yaml_reload_interval_sec = 30
        self._uncertain_policy: Optional[ResponsePolicy] = None
        self._load_source: str = "code"

    def _policies_dir_resolved(self) -> str:
        if self._policies_dir:
            return self._policies_dir
        from .policy_store import DEFAULT_POLICIES_DIR
        return DEFAULT_POLICIES_DIR

    def load_defaults(self):
        """优先从 YAML 加载；目录为空/失败时回退代码种子。"""
        self.reload()

    def reload(self, policies_dir: Optional[str] = None) -> int:
        """热加载 YAML 策略。返回加载条数（不含 uncertain 模板）。"""
        from . import policy_store

        directory = policies_dir or self._policies_dir_resolved()
        loaded: list[ResponsePolicy] = []
        uncertain: Optional[ResponsePolicy] = None
        source = "code"

        try:
            rows = policy_store.load_all(directory)
        except Exception as e:
            logger.warning(f"Policy YAML load failed ({directory}): {e}; using code defaults")
            rows = []

        if rows:
            source = "yaml"
            for row in rows:
                pol = policy_from_dict(row)
                if pol.role == "uncertain_template":
                    uncertain = pol
                    continue
                loaded.append(pol)
        else:
            loaded = list(DEFAULT_POLICIES)
            uncertain = None

        self._policies = sorted(loaded, key=lambda p: p.priority, reverse=True)
        self._uncertain_policy = uncertain
        self._load_source = source
        try:
            self._loaded_mtime = policy_store.dir_mtime(directory)
        except Exception:
            self._loaded_mtime = time.time()
        self._last_mtime_check = time.time()
        try:
            from .threat_taxonomy import reload_taxonomy
            reload_taxonomy()
        except Exception as e:
            logger.debug(f"Taxonomy reload skipped: {e}")
        logger.info(
            f"Loaded {len(self._policies)} response policies "
            f"(source={source}, uncertain_template="
            f"{'yes' if uncertain else 'code-fallback'})"
        )
        return len(self._policies)

    def _maybe_reload_yaml(self):
        """惰性热加载：mtime 变化且距上次检查超过间隔。

        RESPONSE_POLICY_RELOAD_SEC:
          >0  节流间隔（秒）
           0  每次 match 都检查 mtime
          <0  关闭自动热加载（仍可用 reload() / API）
        """
        if self.yaml_reload_interval_sec < 0:
            return
        now = time.time()
        if (
            self.yaml_reload_interval_sec > 0
            and now - self._last_mtime_check < self.yaml_reload_interval_sec
        ):
            return
        self._last_mtime_check = now
        try:
            from . import policy_store
            mtime = policy_store.dir_mtime(self._policies_dir_resolved())
        except Exception:
            return
        if mtime > self._loaded_mtime:
            logger.info("Response policy YAML changed; hot-reloading")
            self.reload()

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
            if p.name == name or (p.policy_id and p.policy_id == name):
                return p
        if (
            self._uncertain_policy
            and (
                self._uncertain_policy.name == name
                or self._uncertain_policy.policy_id == name
            )
        ):
            return self._uncertain_policy
        return None

    def _has_dedicated_policy(self, threat_type: str) -> bool:
        """是否存在该 threat_type 的专属 leaf 策略定义（不含 ANY / 父类 / 已禁用）。"""
        tt = str(threat_type or "").strip().upper()
        if not tt:
            return False
        for p in self._policies:
            if not p.enabled or p.role == "uncertain_template" or p.is_category_policy():
                continue
            if p.threat_type != "ANY" and p.threat_type.upper() == tt:
                return True
        return False

    def _try_match_policy(
        self,
        policy: "ResponsePolicy",
        now: float,
        src_ip: str,
        threat_type: str,
        confidence: float,
        severity: str,
        status: MatchStatus,
        category: str = "",
    ) -> Optional[ThreatActionMap]:
        """冷却检查 + 构造命中结果；冷却中返回 None（由调用方记 SKIPPED）。"""
        if src_ip:
            last_run = self._cooldowns.get(policy.name, {}).get(src_ip, 0)
            elapsed = time.time() - last_run
            if elapsed < policy.cooldown_minutes * 60:
                logger.info(
                    f"Policy '{policy.name}' in cooldown for {src_ip} "
                    f"({elapsed:.0f}s < {policy.cooldown_minutes*60}s)"
                )
                return None
        if src_ip:
            self._ip_last_match[src_ip] = now
        needs_approval = policy.needs_approval()
        logger.info(
            f"Policy matched: '{policy.name}' → type={threat_type or '-'} "
            f"cat={category or '-'} conf={confidence:.2f} sev={severity} "
            f"status={status.value} auto={policy.auto_execute} approval={needs_approval}"
        )
        return ThreatActionMap(
            policy_name=policy.name,
            threat_type=threat_type,
            confidence=confidence,
            severity=severity,
            actions=list(policy.actions),
            needs_approval=needs_approval,
            auto_execute=policy.auto_execute,
            matched=True,
            match_status=status,
            category=category or policy.category or "",
        )

    def _uncertain_template(self) -> ResponsePolicy:
        if self._uncertain_policy and self._uncertain_policy.enabled:
            return self._uncertain_policy
        return ResponsePolicy(
            name=UNCERTAIN_POLICY_NAME,
            threat_type="__UNCERTAIN__",
            actions=_uncertain_actions(),
            min_confidence=0.0,
            min_severity="info",
            auto_execute=True,
            require_approval=True,
            priority=1,
            cooldown_minutes=5,
            policy_id="POL-UNCERTAIN",
            role="uncertain_template",
            description="code-fallback uncertain template",
        )

    def _make_uncertain(
        self, threat_type: str, confidence: float, severity: str, src_ip: str, now: float,
    ) -> ThreatActionMap:
        """未知类型 → Uncertain：5 分钟短封 + 高优先级告警（编排层建 P1 工单）。"""
        tmpl = self._uncertain_template()
        cooldown_sec = max(
            self.uncertain_cooldown_sec,
            int(tmpl.cooldown_minutes or 0) * 60,
        )
        if src_ip and cooldown_sec > 0:
            last = self._uncertain_last.get(src_ip, 0)
            if now - last < cooldown_sec:
                logger.info(
                    f"Uncertain cooldown for {src_ip} "
                    f"({now - last:.0f}s < {cooldown_sec}s)"
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
                    match_status=MatchStatus.SKIPPED,
                    skip_reason="uncertain_cooldown",
                )
            self._uncertain_last[src_ip] = now
        if src_ip:
            self._ip_last_match[src_ip] = now

        logger.warning(
            f"Policy UNCERTAIN: '{tmpl.name}' → {threat_type} "
            f"conf={confidence:.2f} sev={severity} src={src_ip or '-'} "
            f"(template containment + p1 ticket)"
        )
        return ThreatActionMap(
            policy_name=tmpl.name or UNCERTAIN_POLICY_NAME,
            threat_type=threat_type,
            confidence=confidence,
            severity=severity,
            actions=list(tmpl.actions or _uncertain_actions()),
            needs_approval=bool(tmpl.require_approval or tmpl.needs_approval()),
            auto_execute=bool(tmpl.auto_execute),
            matched=True,
            match_status=MatchStatus.UNCERTAIN,
        )

    def match(
        self,
        threat_type: str,
        confidence: float,
        severity: str,
        src_ip: str = "",
        category: str = "",
    ) -> ThreatActionMap:
        """
        匹配威胁到策略。

        决策序（L1+L3）:
          1. per-IP 聚合冷却 → SKIPPED
          2. 专属 leaf threat_type 策略 → MATCHED
          3. 有专属 leaf 但阈值/冷却未过 → SKIPPED / NO_ACTION
          4. 父类 category 策略 → MATCHED_CATEGORY
          5. 良性类型 → NO_ACTION
          6. 其余未知 → UNCERTAIN（或紧急开关关闭时回退 ANY）
        """
        self._maybe_cleanup()
        self._maybe_reload_yaml()
        try:
            from .threat_taxonomy import _maybe_reload as _tax_reload
            _tax_reload()
        except Exception:
            pass

        now = time.time()
        tt = str(threat_type or "").strip()
        cat = str(category or "").strip()
        if not cat and tt:
            try:
                from .threat_taxonomy import category_for_leaf
                cat = category_for_leaf(tt)
            except Exception:
                cat = ""

        # per-IP 聚合冷却
        if src_ip and self.ip_cooldown_sec > 0:
            last_match = self._ip_last_match.get(src_ip, 0)
            if now - last_match < self.ip_cooldown_sec:
                logger.info(
                    f"IP aggregate cooldown for {src_ip} "
                    f"({now - last_match:.0f}s < {self.ip_cooldown_sec}s), "
                    f"status=skipped"
                )
                return ThreatActionMap(
                    policy_name="",
                    threat_type=tt,
                    confidence=confidence,
                    severity=severity,
                    actions=[],
                    needs_approval=False,
                    auto_execute=False,
                    matched=False,
                    match_status=MatchStatus.SKIPPED,
                    skip_reason="ip_cooldown",
                    category=cat,
                )

        dedicated_threshold_miss = False
        dedicated_in_cooldown = False

        # ── 2) leaf 精确匹配 ──
        for policy in self._policies:
            if not policy.enabled or policy.role == "uncertain_template":
                continue
            if policy.is_category_policy():
                continue
            if policy.threat_type == "ANY":
                if self.uncertain_enabled:
                    continue
                if not policy.matches(tt, confidence, severity):
                    continue
            else:
                if not policy.matches(tt, confidence, severity):
                    if tt and policy.threat_type.upper() == tt.upper():
                        dedicated_threshold_miss = True
                    continue

            status = (
                MatchStatus.MATCHED_BEHAVIOR
                if tt.upper() == "BEHAVIOR_ANOMALY"
                else MatchStatus.MATCHED
            )
            hit = self._try_match_policy(
                policy, now, src_ip, tt, confidence, severity,
                status, category=cat,
            )
            if hit is None:
                if policy.threat_type != "ANY":
                    dedicated_in_cooldown = True
                continue
            return hit

        # 有专属 leaf 策略但未命中 → 不掉进父类 / Uncertain
        if self._has_dedicated_policy(tt):
            if dedicated_in_cooldown:
                return ThreatActionMap(
                    policy_name="",
                    threat_type=tt,
                    confidence=confidence,
                    severity=severity,
                    actions=[],
                    needs_approval=False,
                    auto_execute=False,
                    matched=False,
                    match_status=MatchStatus.SKIPPED,
                    skip_reason="policy_cooldown",
                    category=cat,
                )
            return ThreatActionMap(
                policy_name="",
                threat_type=tt,
                confidence=confidence,
                severity=severity,
                actions=[],
                needs_approval=False,
                auto_execute=False,
                matched=False,
                match_status=MatchStatus.NO_ACTION,
                skip_reason="threshold_not_met" if dedicated_threshold_miss else "no_match",
                category=cat,
            )

        # ── 4) 父类 category 匹配 ──
        if cat:
            cat_threshold_miss = False
            cat_in_cooldown = False
            for policy in self._policies:
                if not policy.enabled or not policy.is_category_policy():
                    continue
                if not policy.matches_category(cat, confidence, severity):
                    if policy.category.upper() == cat.upper():
                        cat_threshold_miss = True
                    continue
                hit = self._try_match_policy(
                    policy, now, src_ip, tt, confidence, severity,
                    MatchStatus.MATCHED_CATEGORY, category=cat,
                )
                if hit is None:
                    cat_in_cooldown = True
                    continue
                return hit
            # 有父类策略但阈值/冷却未过：可观测，不立刻 Uncertain
            if cat_in_cooldown:
                return ThreatActionMap(
                    policy_name="",
                    threat_type=tt,
                    confidence=confidence,
                    severity=severity,
                    actions=[],
                    needs_approval=False,
                    auto_execute=False,
                    matched=False,
                    match_status=MatchStatus.SKIPPED,
                    skip_reason="category_policy_cooldown",
                    category=cat,
                )
            if cat_threshold_miss:
                # 父类存在但 severity/confidence 不够 → 仍可 Uncertain？
                # 保守：继续往下走 Uncertain，避免高危未知被 NO_ACTION 漏掉
                pass

        tt_upper = tt.upper()
        if tt_upper in BENIGN_TYPES or cat.upper() == "BENIGN":
            logger.info(f"Policy NO_ACTION for benign type={tt} cat={cat}")
            return ThreatActionMap(
                policy_name="",
                threat_type=tt,
                confidence=confidence,
                severity=severity,
                actions=[],
                needs_approval=False,
                auto_execute=False,
                matched=False,
                match_status=MatchStatus.NO_ACTION,
                skip_reason="benign_type",
                category=cat,
            )

        if self.uncertain_enabled:
            am = self._make_uncertain(tt, confidence, severity, src_ip, now)
            am.category = cat
            return am

        logger.info(
            f"No policy matched for type={tt} cat={cat} "
            f"(uncertain disabled), status=no_action"
        )
        return ThreatActionMap(
            policy_name="",
            threat_type=tt,
            confidence=confidence,
            severity=severity,
            actions=[],
            needs_approval=False,
            auto_execute=False,
            matched=False,
            match_status=MatchStatus.NO_ACTION,
            skip_reason="no_policy",
            category=cat,
        )

    def mark_executed(self, policy_name: str, src_ip: str = ""):
        """v5 修复(C1):动作实际执行 / 审批工单创建后写入 per-policy 冷却。

        之前在 match() 命中时就写冷却，导致 SecurityGuard 拦截全部动作
        （误判保护）时冷却窗口被白白消耗，后续真实威胁无法再触发响应。
        """
        if src_ip:
            self._cooldowns.setdefault(policy_name, {})[src_ip] = time.time()

    def clear_cooldowns(self):
        """清除所有冷却状态（用于测试/人工重置）"""
        self._cooldowns.clear()
        self._ip_last_match.clear()
        self._uncertain_last.clear()
        logger.info("All policy cooldowns cleared")

    def cleanup_expired(self, now: Optional[float] = None):
        """清理已过期的 cooldown 条目，防止长期运行内存无限增长。

        每个条目按所属策略的 cooldown_minutes 过期；策略已下线的残留条目
        按兜底 TTL 过期。条目过期不代表冷却逻辑曾经失效——冷却判断本就
        只看时间差，提前删除过期条目不改变任何匹配行为。
        """
        now = now if now is not None else time.time()
        for policy_name in list(self._cooldowns.keys()):
            cooldown_map = self._cooldowns[policy_name]
            policy = self.get_policy(policy_name)
            ttl = (
                policy.cooldown_minutes * 60
                if policy else self._ORPHAN_TTL_SEC
            )
            for src_ip, ts in list(cooldown_map.items()):
                if (now - ts) >= max(ttl, self._ORPHAN_TTL_SEC):
                    del cooldown_map[src_ip]
            if not cooldown_map:
                del self._cooldowns[policy_name]
        # per-IP 聚合冷却条目随窗口过期即可，提前删除不改变匹配行为
        ip_ttl = max(self.ip_cooldown_sec, 60)
        for src_ip, ts in list(self._ip_last_match.items()):
            if (now - ts) >= ip_ttl:
                del self._ip_last_match[src_ip]
        uncertain_ttl = max(self.uncertain_cooldown_sec, 60)
        for src_ip, ts in list(self._uncertain_last.items()):
            if (now - ts) >= uncertain_ttl:
                del self._uncertain_last[src_ip]

    def _maybe_cleanup(self):
        """match() 入口的惰性清理：距上次清理超过间隔才执行一次。"""
        now = time.time()
        if now - self._last_cleanup < self.CLEANUP_INTERVAL_SEC:
            return
        self._last_cleanup = now
        try:
            self.cleanup_expired(now)
        except Exception as e:
            logger.warning(f"Policy cooldown cleanup failed: {e}")


policy_engine = PolicyEngine()
policy_engine.load_defaults()
