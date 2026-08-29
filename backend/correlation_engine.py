"""
攻击链关联引擎 — 跨事件模式识别

核心功能：
  1. 时间窗口关联 — 同 IP 在 T 分钟内的事件序列
  2. 攻击链模式 — 已知攻击路径的模式匹配
  3. 低频组合检测 — 多个低严重度事件的组合分析
  4. 图关联 — 通过共同目标 IP 关联不同源

设计理念：
  安全审计的核心不是"记住重要的事"，而是"发现事件之间的关系"。
  单个 info 事件不危险，但 DNS 查询 + 文件访问 + C2 回连 = 攻击链。

用法:
    engine = CorrelationEngine()
    chains = await engine.analyze(session, session_id)
    # chains 包含所有识别出的攻击链
"""
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import SecurityEvent, MemoryTreeNode

logger = logging.getLogger(__name__)

# ── 攻击链模式定义 ──

# 中文事件名 → 标准英文类型名映射
ZH_EVENT_MAP = {
    # 数据外泄相关
    "未授权获取密码信息": "DATA_EXFIL",
    "未授权获取明文密码信息": "DATA_EXFIL",
    "请求数据存在明文密码信息": "DATA_EXFIL",
    # 未授权访问
    "非敏感接口未鉴权": "UNAUTHORIZED_ACCESS",
    "日志接口未授权访问": "UNAUTHORIZED_ACCESS",
    # 暴力破解
    "登录弱密码": "BRUTE_FORCE",
    "暴力破解": "BRUTE_FORCE",
    # 端口扫描
    "端口扫描": "PORT_SCAN",
    # C2
    "C2通信": "C2_BEACON",
    # 恶意软件
    "恶意软件": "MALWARE_DETECT",
    # Web攻击
    "SQL注入": "SQL_INJECTION",
    "跨站脚本": "XSS_ATTACK",
    # 横向移动
    "横向移动": "LATERAL_MOVE",
    # 登录相关
    "登录成功": "USER_LOGIN",
    "登录失败": "SUSPICIOUS_LOGIN",
    # 文件相关
    "文件访问": "FILE_ACCESS",
    # 网络相关
    "DNS查询": "DNS_QUERY",
    "DDoS": "DDoS_TRAFFIC",
}

# 英文别名归一（Kill Chain 常见写法）
EVENT_TYPE_ALIASES = {
    "LATERAL_MOVEMENT": "LATERAL_MOVE",
    "DATA_EXFILTRATION": "DATA_EXFIL",
    "DATA_EXFILTRATE": "DATA_EXFIL",
    "C2_COMM": "C2_BEACON",
    "SSH_BRUTE": "BRUTE_FORCE",
}


def normalize_event_type(raw_type: str) -> str:
    """将事件名归一化为标准英文类型名"""
    if not raw_type:
        return "UNKNOWN"
    # 中文映射
    mapped = ZH_EVENT_MAP.get(raw_type)
    if mapped:
        return mapped
    upper = raw_type.strip().upper().replace("-", "_").replace(" ", "_")
    return EVENT_TYPE_ALIASES.get(upper, upper if raw_type.isascii() else raw_type)

# 已知的攻击路径模式：有序的事件类型序列
ATTACK_CHAIN_PATTERNS = {
    "port_scan_to_c2": {
        "name": "端口扫描→漏洞利用→C2回连",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"],
        "max_gap_minutes": 30,
        "severity_required": False,
        "min_match": 3,
    },
    "classic_killchain": {
        "name": "经典杀伤链",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL"],
        "max_gap_minutes": 60,
        "severity_required": False,
        "min_match": 3,  # 允许部分有序子序列（可跳过未出现的中间步）
        "skippable": ["LATERAL_MOVE"],
    },
    # 无横向移动的外部入侵→失陷外联（演示与常见跳板场景）
    "external_compromise_exfil": {
        "name": "外部入侵→失陷外联",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "DATA_EXFIL"],
        "max_gap_minutes": 60,
        "severity_required": False,
        "min_match": 3,
    },
    "lateral_movement": {
        "name": "横向移动",
        "steps": ["SUSPICIOUS_LOGIN", "FILE_ACCESS", "LATERAL_MOVE", "C2_BEACON"],
        "max_gap_minutes": 60,
        "severity_required": False,
        "min_match": 2,
    },
    "post_compromise": {
        "name": "失陷后扩散",
        "steps": ["LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL"],
        "max_gap_minutes": 30,
        "severity_required": False,
        "min_match": 2,
    },
    "data_exfil": {
        "name": "数据外泄",
        "steps": ["FILE_ACCESS", "DATA_EXFIL"],
        "max_gap_minutes": 15,
        "severity_required": False,
    },
    "web_attack": {
        "name": "Web攻击链",
        "steps": ["PORT_SCAN", "SQL_INJECTION", "PRIV_ESC", "C2_BEACON"],
        "max_gap_minutes": 45,
        "severity_required": False,
    },
    "ransomware": {
        "name": "勒索软件",
        "steps": ["PHISHING", "SUSPICIOUS_LOGIN", "FILE_ACCESS", "RANSOMWARE"],
        "max_gap_minutes": 120,
        "severity_required": False,
    },
    "dns_anomaly": {
        "name": "DNS异常→C2",
        "steps": ["DNS_QUERY", "DNS_QUERY", "C2_BEACON"],
        "max_gap_minutes": 10,
        "severity_required": False,
    },
    # 新增：未授权访问类攻击
    "unauthorized_access": {
        "name": "未授权访问",
        "steps": ["UNAUTHORIZED_ACCESS", "DATA_EXFIL"],
        "max_gap_minutes": 30,
        "severity_required": False,
    },
    "data_leak_chain": {
        "name": "数据泄露",
        "steps": ["UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS", "DATA_EXFIL"],
        "max_gap_minutes": 60,
        "severity_required": False,
    },
}


@dataclass
class AttackChain:
    """攻击链 — 一组关联的安全事件序列"""
    chain_id: str
    pattern_name: str
    confidence: float          # 0-1
    events: list[dict]         # 原始事件列表
    src_ips: set               # 涉及的源IP
    dst_ips: set               # 涉及的目标IP
    time_span_minutes: float   # 时间跨度
    alert: str                 # 简要告警描述


@dataclass
class CorrelationResult:
    """关联分析结果"""
    chains: list[AttackChain] = field(default_factory=list)
    temporal_groups: list[dict] = field(default_factory=list)   # 时间窗口分组
    entity_links: list[dict] = field(default_factory=list)      # 实体关联
    total_events_analyzed: int = 0


class CorrelationEngine:
    """
    攻击链关联引擎

    分析流程:
    1. 获取 session 的所有事件（从 SecurityEvent 表）
    2. 按源 IP 分组，时间排序
    3. 对每个 IP 的事件序列进行攻击链模式匹配
    4. 输出所有匹配的攻击链
    """

    def __init__(self):
        self.patterns = ATTACK_CHAIN_PATTERNS

    async def analyze(
        self,
        session: AsyncSession,
        session_id: str,
        time_window_minutes: int = 1440,  # 默认回溯24小时
    ) -> CorrelationResult:
        """
        对 session 的安全事件进行关联分析

        Args:
            session: DB session
            session_id: 会话ID
            time_window_minutes: 分析时间窗口

        Returns:
            CorrelationResult
        """
        # 1. 获取事件
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
        stmt = (
            select(SecurityEvent)
            .where(
                SecurityEvent.session_id == session_id,
                SecurityEvent.created_at >= cutoff,
            )
            .order_by(SecurityEvent.created_at)
        )
        result = await session.execute(stmt)
        events = result.scalars().all()

        if not events:
            logger.info(f"No events found for {session_id}")
            return CorrelationResult()

        logger.info(f"Analyzing {len(events)} events for {session_id}")

        # 2. 按源IP分组
        events_by_ip: dict[str, list[dict]] = defaultdict(list)
        for evt in events:
            src_ip = evt.src_ip or "unknown"
            events_by_ip[src_ip].append({
                "id": evt.id,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "src_ip": evt.src_ip,
                "dst_ip": evt.dst_ip,
                "message": evt.message or "",
                "created_at": evt.created_at,
            })

        # 3. 对每个 IP 进行攻击链模式匹配
        chains = []
        temporal_groups = []
        entity_links = []

        for src_ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda e: e["created_at"])

            # 3a. 攻击链模式匹配
            for pattern_key, pattern in self.patterns.items():
                try:
                    chain = self._match_pattern(
                        pattern_key, pattern, src_ip, ip_events
                    )
                    if chain:
                        chains.append(chain)
                except Exception as e:
                    logger.warning(f"Pattern match failed for {pattern_key}: {e}")

            # 3b. 时间窗口分组（同一IP在短时内的事件）
            groups = self._temporal_grouping(src_ip, ip_events, window_minutes=10)
            temporal_groups.extend(groups)

        # 3c. 枢纽主机模式：先作受害者(dst)后作攻击源(src)的 IP 串联跨源 Kill Chain
        try:
            hub_chains = self._match_hub_hosts(events)
            chains.extend(hub_chains)
        except Exception as e:
            logger.warning(f"Hub-host correlation failed: {e}")

        # 4. 图关联：通过共同目标IP发现不同源IP的关联
        entity_links = self._entity_linking(events_by_ip)

        # 5. 去重
        chains = self._dedup_chains(chains)

        result = CorrelationResult(
            chains=chains,
            temporal_groups=temporal_groups,
            entity_links=entity_links,
            total_events_analyzed=len(events),
        )

        if chains:
            logger.info(f"Found {len(chains)} attack chains for {session_id}")
            for c in chains:
                logger.info(f"  Chain: {c.pattern_name} "
                            f"confidence={c.confidence:.2f} "
                            f"events={len(c.events)} "
                            f"alert={c.alert[:80]}")

        return result

    def _match_hub_hosts(self, events: list) -> list[AttackChain]:
        """以「先作 dst、后作 src」的枢纽主机串联跨源攻击链。"""
        # 统一为 dict 视图
        rows = []
        for evt in events:
            rows.append({
                "id": evt.id,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "src_ip": evt.src_ip,
                "dst_ip": evt.dst_ip,
                "message": evt.message or "",
                "created_at": evt.created_at,
            })

        dst_set = {r["dst_ip"] for r in rows if r.get("dst_ip")}
        src_set = {r["src_ip"] for r in rows if r.get("src_ip")}
        hubs = dst_set & src_set
        chains: list[AttackChain] = []

        # 优先匹配无强制横向移动的外联模式，再尝试完整经典杀伤链
        hub_patterns = []
        if "external_compromise_exfil" in self.patterns:
            hub_patterns.append(
                ("hub_external_exfil", self.patterns["external_compromise_exfil"])
            )
        hub_patterns.append((
            "hub_killchain",
            self.patterns.get("classic_killchain") or {
                "name": "枢纽主机杀伤链",
                "steps": ["PORT_SCAN", "BRUTE_FORCE", "LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL"],
                "max_gap_minutes": 60,
                "min_match": 3,
                "skippable": ["LATERAL_MOVE"],
            },
        ))

        for hub in hubs:
            inbound = [r for r in rows if r.get("dst_ip") == hub]
            outbound = [r for r in rows if r.get("src_ip") == hub]
            # 时间轴：先入站侦察/突破，再出站横向/外联
            timeline = sorted(inbound + outbound, key=lambda e: e["created_at"])
            # 去重同 id
            seen = set()
            deduped = []
            for e in timeline:
                if e["id"] in seen:
                    continue
                seen.add(e["id"])
                deduped.append(e)
            for pattern_key, pattern in hub_patterns:
                chain = self._match_pattern(
                    pattern_key,
                    {**pattern, "name": f"{pattern.get('name', '枢纽杀伤链')}({hub})"},
                    hub,
                    deduped,
                )
                if chain:
                    chain.chain_id = f"chain_hub_{hub}_{deduped[0]['id']}"
                    chain.src_ips = {e.get("src_ip") for e in chain.events if e.get("src_ip")}
                    chain.dst_ips = {e.get("dst_ip") for e in chain.events if e.get("dst_ip")}
                    chains.append(chain)
                    break  # 同一 hub 只保留最高优先级命中
        return chains

    def _match_pattern(
        self,
        pattern_key: str,
        pattern: dict,
        src_ip: str,
        events: list[dict],
    ) -> Optional[AttackChain]:
        """
        在事件序列中匹配攻击链模式

        使用滑动窗口 + 有序子序列匹配算法。
        不要求严格连续，只要求按顺序出现且时间间隔在阈值内。
        """
        steps = pattern["steps"]
        max_gap = pattern["max_gap_minutes"]
        n = len(steps)
        min_match = int(pattern.get("min_match") or n)
        skippable = {
            normalize_event_type(s) for s in (pattern.get("skippable") or [])
        }

        if len(events) < min_match:
            return None

        # 将事件类型转换为序列（支持中文事件名映射）
        event_types = [normalize_event_type(e["event_type"]) for e in events]

        # 有序子序列匹配：可跳过 skippable / 未出现的中间步，满足 min_match 即可
        matched_indices = []
        step_idx = 0

        for i, et in enumerate(event_types):
            if step_idx >= n:
                break
            # 当前事件匹配当前期望步骤
            if et == steps[step_idx]:
                matched_indices.append(i)
                step_idx += 1
                continue
            # 向前查找：跳过可跳过步骤，看是否能匹配更后面的步骤
            advanced = False
            for look_ahead in range(step_idx + 1, n):
                # 仅当中间步骤均可跳过（或模式允许任意跳过）时前进
                middle = steps[step_idx:look_ahead]
                if all(normalize_event_type(m) in skippable for m in middle) or pattern.get(
                    "allow_skip_missing", True
                ):
                    if et == steps[look_ahead]:
                        matched_indices.append(i)
                        step_idx = look_ahead + 1
                        advanced = True
                        break
                else:
                    break
            if advanced:
                continue

        if len(matched_indices) < min_match:
            return None

        # 验证时间间隔
        matched_events = [events[i] for i in matched_indices]
        for j in range(1, len(matched_events)):
            gap = (matched_events[j]["created_at"]
                   - matched_events[j-1]["created_at"]).total_seconds() / 60
            if gap > max_gap:
                return None

        # 计算置信度
        severity_scores = {
            "critical": 1.0, "high": 0.8, "medium": 0.5,
            "low": 0.2, "info": 0.1,
        }
        max_sev = max(
            severity_scores.get(e["severity"], 0.1) for e in matched_events
        )
        match_ratio = len(matched_indices) / max(len(steps), 1)
        confidence = min(1.0, max_sev * 0.4 + match_ratio * 0.6)

        time_span = (
            matched_events[-1]["created_at"]
            - matched_events[0]["created_at"]
        ).total_seconds() / 60

        dst_ips = {e.get("dst_ip", "") for e in matched_events if e.get("dst_ip")}

        sev_tags = [e["severity"].upper() for e in matched_events]
        alert = (
            f"[{pattern['name']}] {src_ip} → "
            f"{', '.join(sev_tags)} "
            f"({len(matched_events)}步, {time_span:.0f}分钟)"
        )

        return AttackChain(
            chain_id=f"chain_{pattern_key}_{src_ip}_{matched_events[0]['id']}",
            pattern_name=pattern["name"],
            confidence=round(confidence, 3),
            events=matched_events,
            src_ips={src_ip},
            dst_ips=dst_ips,
            time_span_minutes=round(time_span, 1),
            alert=alert,
        )

    def _temporal_grouping(
        self,
        src_ip: str,
        events: list[dict],
        window_minutes: int = 10,
    ) -> list[dict]:
        """
        时间窗口分组：同一源IP在短时内的事件聚为一组
        
        用于记忆树关联和 Agent 上下文提示
        """
        if not events:
            return []

        groups = []
        current_group = [events[0]]

        for evt in events[1:]:
            gap = (evt["created_at"] - current_group[-1]["created_at"]).total_seconds() / 60
            if gap <= window_minutes:
                current_group.append(evt)
            else:
                if len(current_group) >= 2:
                    types = [e["event_type"] for e in current_group]
                    groups.append({
                        "src_ip": src_ip,
                        "events": current_group,
                        "types": types,
                        "start": current_group[0]["created_at"].isoformat(),
                        "end": current_group[-1]["created_at"].isoformat(),
                        "count": len(current_group),
                    })
                current_group = [evt]

        if len(current_group) >= 2:
            types = [e["event_type"] for e in current_group]
            groups.append({
                "src_ip": src_ip,
                "events": current_group,
                "types": types,
                "start": current_group[0]["created_at"].isoformat(),
                "end": current_group[-1]["created_at"].isoformat(),
                "count": len(current_group),
            })

        return groups

    def _entity_linking(
        self,
        events_by_ip: dict[str, list[dict]],
    ) -> list[dict]:
        """
        实体关联：通过共同目标IP发现不同源IP的关联
        
        如果两个不同源IP都访问了同一个目标IP，它们可能协同攻击。
        """
        dst_to_srcs: dict[str, set] = defaultdict(set)
        for src_ip, events in events_by_ip.items():
            for evt in events:
                dst = evt.get("dst_ip", "")
                if dst:
                    dst_to_srcs[dst].add(src_ip)

        links = []
        for dst, srcs in dst_to_srcs.items():
            if len(srcs) >= 2:
                links.append({
                    "dst_ip": dst,
                    "src_ips": list(srcs),
                    "type": "共同目标关联",
                })

        return links

    def _dedup_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """去重：如果两个链共享相同事件，保留更完整的那个"""
        if not chains:
            return []

        chains.sort(key=lambda c: len(c.events), reverse=True)

        kept = []
        used_event_ids = set()

        for chain in chains:
            event_ids = {e["id"] for e in chain.events}
            if event_ids - used_event_ids:
                kept.append(chain)
                used_event_ids.update(event_ids)

        return kept


correlation_engine = CorrelationEngine()
