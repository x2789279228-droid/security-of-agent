"""
DDoS 响应策略 (DDoSResponsePolicy)

在现有 Response Engine 中扩展 DDoS 场景的响应策略，不重新实现独立响应系统。

核心原则:
  1. 禁止 Agent 自动封禁整个 RFC1918 内网网段
     (10.0.0.0/8、172.16.0.0/12、192.168.0.0/16)
  2. 区分 6 种 DDoS 场景，分别匹配响应策略:
     - 外部单 IP
     - 外部 CIDR
     - 分布式外部 DDoS
     - 内部单主机
     - 内部多主机
     - 核心网络级攻击
  3. 内部 DDoS 优先定位具体异常主机 (限速/EDR/NAC/端口控制/账号禁用)
  4. 外部 CIDR 阻断必须满足:
     高置信度证据 + 明确 CIDR 授权 + 非受保护服务商 + 短 TTL
     + Canary + 自动回滚 + 业务健康检查
  5. 大规模 DDoS 切换到清洗设备/运营商/云 Anti-DDoS/核心网络策略
     不允许 Agent 通过单机 iptables 直接执行大网段阻断

接入点:
  - response_orchestrator.on_threat_detected
      → threat_type == "DDoS_TRAFFIC" 时分流到 DDoSResponsePolicy
  - 不替代 PolicyEngine, 只处理 DDoS 专有逻辑
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ── 常量 ──────────────────────────────────────────────────────

# RFC1918 内网网段 — 禁止 Agent 自动封禁
RFC1918_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)

# 环回地址 — 同样禁止自动封禁
PROTECTED_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",  # IPv4 loopback
    "::1/128",       # IPv6 loopback
    "169.254.0.0/16",  # link-local
)

# 受保护的服务商网段 (云厂商骨干网, 不应被自动封禁)
# 实际部署时应从 config 加载完整列表
PROTECTED_PROVIDER_CIDRS: tuple[str, ...] = (
    # 云厂商 DNS / NTP 等公共服务的网段示例
    # 生产环境需从 config 加载
)

# 大规模 DDoS 阈值 — 超过则切换到清洗设备
LARGE_SCALE_DDoS_THRESHOLD_PPS: int = 100_000      # 10万包/秒
LARGE_SCALE_DDoS_THRESHOLD_Gbps: int = 10          # 10 Gbps
LARGE_SCALE_DDoS_THRESHOLD_SOURCES: int = 1_000    # 1000+ 源 IP

# 外部 CIDR 阻断的最大前缀长度 (防止封 /8 /16 等大网段)
MAX_EXTERNAL_CIDR_PREFIX: int = 24  # 只允许 /24 及更具体

# 短 TTL 上限 (秒) — 外部 CIDR 阻断必须使用短 TTL
MAX_EXTERNAL_CIDR_TTL_SECONDS: int = 3600  # 1 小时

# 最低证据置信度
MIN_EVIDENCE_CONFIDENCE: float = 0.8


class DDoSCategory(str, Enum):
    """DDoS 攻击分类"""
    EXTERNAL_SINGLE_IP = "external_single_ip"        # 外部单 IP
    EXTERNAL_CIDR = "external_cidr"                 # 外部 CIDR
    DISTRIBUTED_EXTERNAL = "distributed_external"   # 分布式外部 DDoS
    INTERNAL_SINGLE_HOST = "internal_single_host"   # 内部单主机
    INTERNAL_MULTI_HOST = "internal_multi_host"      # 内部多主机
    CORE_NETWORK = "core_network"                    # 核心网络级攻击
    UNKNOWN = "unknown"


class DDoSResponseDecision(str, Enum):
    """DDoS 响应决策"""
    ALLOW_AUTO_BLOCK = "allow_auto_block"                # 允许自动封禁 (单 IP)
    ALLOW_CIDR_BLOCK = "allow_cidr_block"               # 允许 CIDR 封禁 (严格条件)
    USE_SCRUBBING_DEVICE = "use_scrubbing_device"       # 切换到清洗设备
    USE_RATE_LIMIT_ONLY = "use_rate_limit_only"        # 只允许限速
    ISOLATE_INTERNAL_HOST = "isolate_internal_host"    # 隔离内部主机
    DENY_AUTO_RESPONSE = "deny_auto_response"          # 拒绝自动响应
    REQUIRE_HUMAN_APPROVAL = "require_human_approval"   # 需人工审批


# ── 数据模型 ─────────────────────────────────────────────────

@dataclass
class DDoSAttackContext:
    """DDoS 攻击上下文 — 从威胁事件中提取的 DDoS 相关信息"""
    category: DDoSCategory = DDoSCategory.UNKNOWN
    src_ips: list[str] = field(default_factory=list)
    src_cidrs: list[str] = field(default_factory=list)
    target_ip: str = ""
    target_service: str = ""
    traffic_pps: int = 0           # 包/秒
    traffic_gbps: float = 0.0      # 带宽 Gbps
    duration_seconds: int = 0
    evidence_confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    attack_pattern: str = ""       # SYN_FLOOD / UDP_FLOOD / DNS_AMP / NTP_AMP / ...

    @property
    def is_large_scale(self) -> bool:
        """是否为大规模 DDoS (需切换到清洗设备)"""
        return (
            self.traffic_pps >= LARGE_SCALE_DDoS_THRESHOLD_PPS
            or self.traffic_gbps >= LARGE_SCALE_DDoS_THRESHOLD_Gbps
            or len(self.src_ips) >= LARGE_SCALE_DDoS_THRESHOLD_SOURCES
        )

    @property
    def source_count(self) -> int:
        """攻击源数量"""
        return len(self.src_ips) + len(self.src_cidrs)


@dataclass
class DDoSResponseResult:
    """DDoS 响应策略决策结果"""
    decision: DDoSResponseDecision
    category: DDoSCategory
    allowed_actions: list[str] = field(default_factory=list)
    denied_actions: list[str] = field(default_factory=list)
    reason: str = ""
    recommendations: list[str] = field(default_factory=list)
    require_human_approval: bool = False
    require_canary: bool = False
    require_auto_rollback: bool = False
    require_health_check: bool = False
    max_ttl_seconds: int = MAX_EXTERNAL_CIDR_TTL_SECONDS
    scrubbing_device_required: bool = False
    # 供 TAG/Orchestrator 使用的具体目标 (已通过校验)
    safe_targets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "category": self.category.value,
            "allowed_actions": self.allowed_actions,
            "denied_actions": self.denied_actions,
            "reason": self.reason,
            "recommendations": self.recommendations,
            "require_human_approval": self.require_human_approval,
            "require_canary": self.require_canary,
            "require_auto_rollback": self.require_auto_rollback,
            "require_health_check": self.require_health_check,
            "max_ttl_seconds": self.max_ttl_seconds,
            "scrubbing_device_required": self.scrubbing_device_required,
            "safe_targets": self.safe_targets,
        }


# ── 核心策略 ─────────────────────────────────────────────────

class DDoSResponsePolicy:
    """DDoS 响应策略引擎

    区分 6 种 DDoS 场景并给出对应响应决策。
    不执行任何动作，只输出决策结果供 Orchestrator 执行。
    """

    def classify(self, ctx: DDoSAttackContext) -> DDoSCategory:
        """分类 DDoS 攻击类型"""
        # 1. 核心网络级攻击 — 目标是核心网络设备
        if ctx.target_service in ("core_router", "core_switch", "gateway",
                                   "firewall", "load_balancer"):
            return DDoSCategory.CORE_NETWORK

        # 2. 分布式外部 — 多源 + 大流量
        if (ctx.source_count > 10
                and any(self._is_external(ip) for ip in ctx.src_ips)):
            return DDoSCategory.DISTRIBUTED_EXTERNAL

        # 3. 外部 CIDR — 源是外部 CIDR
        if ctx.src_cidrs and any(self._is_external_cidr(c) for c in ctx.src_cidrs):
            return DDoSCategory.EXTERNAL_CIDR

        # 4. 外部单 IP — 单个外部 IP
        if len(ctx.src_ips) == 1 and self._is_external(ctx.src_ips[0]):
            return DDoSCategory.EXTERNAL_SINGLE_IP

        # 5. 内部多主机 — 多个内部 IP
        if len(ctx.src_ips) > 1 and all(self._is_internal(ip) for ip in ctx.src_ips):
            return DDoSCategory.INTERNAL_MULTI_HOST

        # 6. 内部单主机
        if len(ctx.src_ips) == 1 and self._is_internal(ctx.src_ips[0]):
            return DDoSCategory.INTERNAL_SINGLE_HOST

        return DDoSCategory.UNKNOWN

    def evaluate(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """评估 DDoS 攻击并给出响应决策"""
        if ctx.category == DDoSCategory.UNKNOWN:
            ctx.category = self.classify(ctx)

        # 大规模 DDoS — 一律切换到清洗设备
        if ctx.is_large_scale:
            return self._use_scrubbing_device(ctx)

        # 按分类处理
        if ctx.category == DDoSCategory.EXTERNAL_SINGLE_IP:
            return self._handle_external_single_ip(ctx)
        if ctx.category == DDoSCategory.EXTERNAL_CIDR:
            return self._handle_external_cidr(ctx)
        if ctx.category == DDoSCategory.DISTRIBUTED_EXTERNAL:
            return self._handle_distributed_external(ctx)
        if ctx.category == DDoSCategory.INTERNAL_SINGLE_HOST:
            return self._handle_internal_single_host(ctx)
        if ctx.category == DDoSCategory.INTERNAL_MULTI_HOST:
            return self._handle_internal_multi_host(ctx)
        if ctx.category == DDoSCategory.CORE_NETWORK:
            return self._handle_core_network(ctx)

        return DDoSResponseResult(
            decision=DDoSResponseDecision.REQUIRE_HUMAN_APPROVAL,
            category=ctx.category,
            reason="未知 DDoS 类型, 需人工介入",
            require_human_approval=True,
        )

    # ── 各场景处理逻辑 ──

    def _handle_external_single_ip(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """外部单 IP — 允许自动封禁 (带条件)"""
        # 检查证据置信度
        if ctx.evidence_confidence < MIN_EVIDENCE_CONFIDENCE:
            return DDoSResponseResult(
                decision=DDoSResponseDecision.REQUIRE_HUMAN_APPROVAL,
                category=ctx.category,
                reason=f"证据置信度不足 ({ctx.evidence_confidence:.0%} < {MIN_EVIDENCE_CONFIDENCE:.0%})",
                require_human_approval=True,
                recommendations=["补充证据: 流量样本、包特征、回溯分析"],
            )

        return DDoSResponseResult(
            decision=DDoSResponseDecision.ALLOW_AUTO_BLOCK,
            category=ctx.category,
            allowed_actions=["block_ip", "rate_limit"],
            denied_actions=["block_cidr"],
            safe_targets=list(ctx.src_ips),
            max_ttl_seconds=MAX_EXTERNAL_CIDR_TTL_SECONDS,
            require_auto_rollback=True,
            require_health_check=True,
            reason="外部单 IP DDoS, 证据充分, 允许自动封禁 (短 TTL + 自动回滚)",
        )

    def _handle_external_cidr(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """外部 CIDR — 严格条件下的 CIDR 封禁"""
        # 1. 证据置信度
        if ctx.evidence_confidence < MIN_EVIDENCE_CONFIDENCE:
            return DDoSResponseResult(
                decision=DDoSResponseDecision.REQUIRE_HUMAN_APPROVAL,
                category=ctx.category,
                reason=f"CIDR 阻断证据不足 ({ctx.evidence_confidence:.0%})",
                require_human_approval=True,
            )

        # 2. 校验每个 CIDR
        safe_cidrs: list[str] = []
        denied: list[str] = []
        for cidr in ctx.src_cidrs:
            ok, reason = self._validate_external_cidr(cidr)
            if ok:
                safe_cidrs.append(cidr)
            else:
                denied.append(f"{cidr}: {reason}")

        if not safe_cidrs:
            return DDoSResponseResult(
                decision=DDoSResponseDecision.DENY_AUTO_RESPONSE,
                category=ctx.category,
                denied_actions=["block_cidr"],
                reason="所有 CIDR 都未通过校验: " + "; ".join(denied),
                require_human_approval=True,
            )

        return DDoSResponseResult(
            decision=DDoSResponseDecision.ALLOW_CIDR_BLOCK,
            category=ctx.category,
            allowed_actions=["block_cidr"],
            denied_actions=denied,
            safe_targets=safe_cidrs,
            max_ttl_seconds=MAX_EXTERNAL_CIDR_TTL_SECONDS,
            require_canary=True,           # 必须 Canary
            require_auto_rollback=True,
            require_health_check=True,
            reason="外部 CIDR 阻断: 高置信度 + 明确授权 + 短 TTL + Canary + 自动回滚 + 健康检查",
        )

    def _handle_distributed_external(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """分布式外部 DDoS — 多源攻击"""
        # 分布式攻击通常规模较大 → 清洗设备
        if ctx.is_large_scale:
            return self._use_scrubbing_device(ctx)

        # 中等规模分布式 — 逐个 IP 封禁 (不封 CIDR)
        safe_ips: list[str] = []
        for ip in ctx.src_ips:
            if self._is_external(ip):
                ok, _ = self._validate_external_ip(ip)
                if ok:
                    safe_ips.append(ip)

        if not safe_ips:
            return DDoSResponseResult(
                decision=DDoSResponseDecision.REQUIRE_HUMAN_APPROVAL,
                category=ctx.category,
                reason="无有效外部 IP 可封禁",
                require_human_approval=True,
            )

        # 限制单次封禁数量 (避免批量封禁引起连锁故障)
        safe_ips = safe_ips[:50]

        return DDoSResponseResult(
            decision=DDoSResponseDecision.ALLOW_AUTO_BLOCK,
            category=ctx.category,
            allowed_actions=["block_ip"],
            denied_actions=["block_cidr"],
            safe_targets=safe_ips,
            max_ttl_seconds=MAX_EXTERNAL_CIDR_TTL_SECONDS,
            require_canary=True,
            require_auto_rollback=True,
            require_health_check=True,
            reason=f"分布式外部 DDoS: 逐个封禁 {len(safe_ips)} 个 IP (Canary + 自动回滚)",
        )

    def _handle_internal_single_host(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """内部单主机 — 优先定位异常主机, 不封网段"""
        host_ip = ctx.src_ips[0] if ctx.src_ips else ""

        return DDoSResponseResult(
            decision=DDoSResponseDecision.ISOLATE_INTERNAL_HOST,
            category=ctx.category,
            allowed_actions=[
                "rate_limit",           # 限速
                "isolate_host",         # EDR 隔离
                "nac_isolate",          # NAC 隔离
                "switch_port_disable",  # 交换机端口控制
                "disable_account",      # 临时禁用异常账号
                "send_alert",
            ],
            denied_actions=["block_cidr", "block_ip"],  # 不允许封 IP/网段
            safe_targets=[host_ip] if host_ip else [],
            require_human_approval=True,    # 内部隔离需人工确认
            require_auto_rollback=True,
            reason=(
                "内部单主机 DDoS: 优先限速/EDR 隔离/NAC 隔离/端口控制/账号禁用, "
                "禁止封禁内网网段"
            ),
            recommendations=[
                f"定位主机 {host_ip} 的异常进程",
                "检查是否被植入挖矿/C2/僵尸网络",
                "联系资产负责人确认",
            ],
        )

    def _handle_internal_multi_host(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """内部多主机 — 可能是内网僵尸网络"""
        return DDoSResponseResult(
            decision=DDoSResponseDecision.ISOLATE_INTERNAL_HOST,
            category=ctx.category,
            allowed_actions=[
                "rate_limit",
                "isolate_host",
                "nac_isolate",
                "switch_port_disable",
                "disable_account",
                "send_alert",
            ],
            denied_actions=["block_cidr", "block_ip"],
            safe_targets=list(ctx.src_ips),
            require_human_approval=True,
            require_canary=True,
            require_auto_rollback=True,
            reason=(
                f"内部多主机 DDoS ({len(ctx.src_ips)} 台): 可能是僵尸网络, "
                "逐台隔离 + 人工确认, 禁止封禁内网网段"
            ),
            recommendations=[
                "启动僵尸网络排查流程",
                "关联 C2 通信证据",
                "逐台 EDR 隔离 + 取证",
            ],
        )

    def _handle_core_network(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """核心网络级攻击 — 必须走清洗设备"""
        return DDoSResponseResult(
            decision=DDoSResponseDecision.USE_SCRUBBING_DEVICE,
            category=ctx.category,
            allowed_actions=[],  # 不允许 Agent 直接处置
            denied_actions=["block_ip", "block_cidr", "isolate_host"],
            require_human_approval=True,
            scrubbing_device_required=True,
            reason=(
                "核心网络级攻击: 必须走清洗设备/运营商/云 Anti-DDoS, "
                "禁止 Agent 通过单机 iptables 直接处置"
            ),
            recommendations=[
                "立即联系网络运维团队",
                "启用上游清洗设备",
                "联系运营商启用 Anti-DDoS",
                "准备核心网络容灾切换",
            ],
        )

    def _use_scrubbing_device(self, ctx: DDoSAttackContext) -> DDoSResponseResult:
        """大规模 DDoS — 切换到清洗设备"""
        return DDoSResponseResult(
            decision=DDoSResponseDecision.USE_SCRUBBING_DEVICE,
            category=ctx.category,
            allowed_actions=["trigger_scrubbing"],   # 只允许触发清洗设备
            denied_actions=["block_ip", "block_cidr", "isolate_host"],
            require_human_approval=True,
            scrubbing_device_required=True,
            reason=(
                f"大规模 DDoS (pps={ctx.traffic_pps}, gbps={ctx.traffic_gbps}, "
                f"sources={ctx.source_count}): 超过单机处理能力, "
                "切换到清洗设备/运营商/云 Anti-DDoS, 禁止单机 iptables 处置"
            ),
            recommendations=[
                "启用清洗设备 (Arbor/Fortinet/华为 CloudDDoS)",
                "联系运营商启用近源清洗",
                "云环境启用云 Anti-DDoS",
                "核心网络策略调整",
                "通知 SOC 值班人员",
            ],
        )

    # ── 校验工具 ──

    def _validate_external_ip(self, ip: str) -> tuple[bool, str]:
        """校验外部 IP 是否可以封禁"""
        if not ip:
            return False, "IP 为空"

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"无效 IP: {ip}"

        # 禁止内网 IP
        if self._is_internal(ip):
            return False, f"内网 IP 禁止自动封禁: {ip}"

        # 禁止环回
        if addr.is_loopback:
            return False, f"环回地址禁止封禁: {ip}"

        # 禁止受保护服务商
        for cidr in PROTECTED_PROVIDER_CIDRS:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return False, f"受保护服务商网段: {ip} in {cidr}"

        return True, "OK"

    def _validate_external_cidr(self, cidr: str) -> tuple[bool, str]:
        """校验外部 CIDR 是否可以封禁

        要求 (检查顺序很重要, 内网检测必须优先):
          1. 非 RFC1918 内网网段 (内网网段永远禁止自动封禁)
          2. 前缀长度 <= MAX_EXTERNAL_CIDR_PREFIX (只允许 /24 及更具体)
          3. 非环回地址
          4. 非受保护服务商
        """
        if not cidr:
            return False, "CIDR 为空"

        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False, f"无效 CIDR: {cidr}"

        # 1. 优先禁止 RFC1918 内网网段 (即使前缀过宽也要明确标注为内网)
        for rfc in RFC1918_CIDRS:
            rfc_net = ipaddress.ip_network(rfc, strict=False)
            if net == rfc_net or rfc_net.supernet_of(net) or net.overlaps(rfc_net):
                return False, (
                    f"内网网段禁止自动封禁: {cidr} 与 RFC1918 {rfc} 重叠 "
                    "(禁止 Agent 自动封禁整个内网)"
                )

        # 2. 禁止 /0、/8 等大网段 (在确认非内网后再检查前缀宽度)
        if net.prefixlen < MAX_EXTERNAL_CIDR_PREFIX:
            return False, (
                f"CIDR 前缀过宽: {cidr} (prefix={net.prefixlen}, "
                f"最小允许 /{MAX_EXTERNAL_CIDR_PREFIX})"
            )

        # 3. 禁止环回
        for prot in ("127.0.0.0/8", "::1/128"):
            if net.overlaps(ipaddress.ip_network(prot, strict=False)):
                return False, f"环回网段禁止封禁: {cidr}"

        # 4. 禁止受保护服务商
        for prot_cidr in PROTECTED_PROVIDER_CIDRS:
            if net.overlaps(ipaddress.ip_network(prot_cidr, strict=False)):
                return False, f"受保护服务商网段: {cidr} 与 {prot_cidr} 重叠"

        return True, "OK"

    def _is_internal(self, ip: str) -> bool:
        """判断是否为内网 IP"""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        if addr.is_loopback:
            return True

        for cidr in RFC1918_CIDRS:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        return False

    def _is_external(self, ip: str) -> bool:
        return not self._is_internal(ip)

    def _is_external_cidr(self, cidr: str) -> bool:
        """判断 CIDR 是否为外部网段"""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

        for rfc in RFC1918_CIDRS:
            rfc_net = ipaddress.ip_network(rfc, strict=False)
            if net.overlaps(rfc_net):
                return False
        return True

    # ── 全局禁止规则 ──

    def is_rfc1918_block_attempt(self, target: str) -> bool:
        """判断目标是否为 RFC1918 内网网段 (禁止自动封禁)"""
        if not target:
            return False
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False

        for rfc in RFC1918_CIDRS:
            rfc_net = ipaddress.ip_network(rfc, strict=False)
            # 完全匹配或被 RFC1918 包含
            if net == rfc_net or rfc_net.supernet_of(net):
                return True
        return False


# ── 全局单例 ──

ddos_policy = DDoSResponsePolicy()
