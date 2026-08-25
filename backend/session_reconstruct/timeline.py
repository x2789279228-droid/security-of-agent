"""
timeline.py — 攻击时间线构建与故事化叙述

将多源事件（网络流、EDR、告警、审计结论）按时间排序，
构建统一攻击时间线，并生成结构化叙述。

输出:
  - 时间线: [{timestamp, source, event_type, description, severity}]
  - 攻击阶段: MITRE ATT&CK Kill Chain 映射
  - 故事化摘要: LLM 可读的结构化叙述

用法:
    from session_reconstruct.timeline import timeline_builder
    tl = await timeline_builder.build(session, src_ip="10.0.0.5", hours=24)
    narrative = timeline_builder.narrate(tl)
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# MITRE ATT&CK Kill Chain 阶段
_KILL_CHAIN_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# 事件类型 → Kill Chain 阶段映射
_EVENT_TACTIC_MAP = {
    "PORT_SCAN": "reconnaissance",
    "BRUTE_FORCE": "initial-access",
    "SQL_INJECTION": "initial-access",
    "XSS_ATTACK": "initial-access",
    "UNAUTHORIZED_ACCESS": "initial-access",
    "MALWARE_DETECT": "execution",
    "PRIVILEGE_ESCALATION": "privilege-escalation",
    "LATERAL_MOVE": "lateral-movement",
    "C2_BEACON": "command-and-control",
    "DATA_EXFIL": "exfiltration",
    "DDoS_TRAFFIC": "impact",
    "DNS_QUERY": "command-and-control",
    "USER_LOGIN": "initial-access",
    "SUSPICIOUS_LOGIN": "initial-access",
    "FILE_ACCESS": "collection",
}


@dataclass
class TimelineEvent:
    """时间线条目"""
    timestamp: str = ""
    source: str = ""          # network | edr | alert | audit
    event_type: str = ""
    description: str = ""
    severity: str = "info"
    tactic: str = ""          # MITRE Kill Chain 阶段
    src_ip: str = ""
    dst_ip: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "tactic": self.tactic,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
        }


@dataclass
class AttackTimeline:
    """攻击时间线"""
    target_ip: str = ""
    time_range: str = ""
    events: list = field(default_factory=list)
    tactics_observed: list = field(default_factory=list)
    kill_chain_progress: int = 0   # 推进到第几个阶段 (0-13)
    total_events: int = 0
    critical_count: int = 0
    narrative: str = ""

    def to_dict(self) -> dict:
        return {
            "target_ip": self.target_ip,
            "time_range": self.time_range,
            "events": [e.to_dict() for e in self.events],
            "tactics_observed": self.tactics_observed,
            "kill_chain_progress": self.kill_chain_progress,
            "total_events": self.total_events,
            "critical_count": self.critical_count,
            "narrative": self.narrative,
        }


class TimelineBuilder:
    """攻击时间线构建器"""

    async def build(
        self,
        session: AsyncSession,
        src_ip: str = "",
        dst_ip: str = "",
        hours: int = 24,
    ) -> AttackTimeline:
        """
        构建攻击时间线

        从多个数据源收集事件，按时间排序。
        """
        timeline = AttackTimeline(target_ip=src_ip or dst_ip)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        timeline.time_range = f"last_{hours}h"

        all_events = []

        # 1. 安全事件
        try:
            from models import SecurityEvent
            q = select(SecurityEvent).where(SecurityEvent.created_at >= cutoff)
            if src_ip:
                q = q.where(SecurityEvent.src_ip == src_ip)
            if dst_ip:
                q = q.where(SecurityEvent.dst_ip == dst_ip)
            q = q.order_by(SecurityEvent.created_at).limit(200)
            result = await session.execute(q)
            for evt in result.scalars().all():
                tactic = _EVENT_TACTIC_MAP.get(evt.event_type, "")
                all_events.append(TimelineEvent(
                    timestamp=evt.created_at.isoformat() if evt.created_at else "",
                    source="alert",
                    event_type=evt.event_type,
                    description=evt.message or evt.event_type,
                    severity=evt.severity,
                    tactic=tactic,
                    src_ip=evt.src_ip or "",
                    dst_ip=evt.dst_ip or "",
                ))
        except Exception as e:
            logger.debug("时间线-安全事件查询失败: %s", e)

        # 2. 网络流
        try:
            from models import NetworkFlow
            q = select(NetworkFlow).where(NetworkFlow.created_at >= cutoff)
            if src_ip:
                q = q.where(NetworkFlow.src_ip == src_ip)
            q = q.order_by(NetworkFlow.created_at).limit(200)
            result = await session.execute(q)
            for flow in result.scalars().all():
                all_events.append(TimelineEvent(
                    timestamp=flow.created_at.isoformat() if flow.created_at else "",
                    source="network",
                    event_type=f"flow:{flow.app_protocol or flow.protocol}",
                    description=(
                        f"{flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port} "
                        f"({flow.app_protocol or flow.protocol}, {flow.bytes_out}B out)"
                    ),
                    severity="info",
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                ))
        except Exception as e:
            logger.debug("时间线-网络流查询失败: %s", e)

        # 3. EDR 事件
        try:
            from models import EdrEvent
            q = select(EdrEvent).where(EdrEvent.created_at >= cutoff)
            if src_ip:
                q = q.where(EdrEvent.src_ip == src_ip)
            q = q.order_by(EdrEvent.created_at).limit(200)
            result = await session.execute(q)
            for evt in result.scalars().all():
                all_events.append(TimelineEvent(
                    timestamp=evt.created_at.isoformat() if evt.created_at else "",
                    source="edr",
                    event_type=f"sysmon:{evt.event_name}" if evt.source_type == "sysmon" else f"winevent:{evt.event_id}",
                    description=(
                        f"{evt.process_name} on {evt.computer_name}"
                        + (f": {evt.command_line[:100]}" if evt.command_line else "")
                    ),
                    severity=evt.severity,
                    tactic=evt.mitre_technique,
                    src_ip=evt.src_ip,
                ))
        except Exception as e:
            logger.debug("时间线-EDR查询失败: %s", e)

        # 按时间排序
        all_events.sort(key=lambda e: e.timestamp)
        timeline.events = all_events
        timeline.total_events = len(all_events)
        timeline.critical_count = sum(1 for e in all_events if e.severity == "critical")

        # Kill Chain 进度
        tactics = set()
        max_progress = 0
        for e in all_events:
            if e.tactic and e.tactic in _KILL_CHAIN_ORDER:
                tactics.add(e.tactic)
                idx = _KILL_CHAIN_ORDER.index(e.tactic)
                max_progress = max(max_progress, idx)
        timeline.tactics_observed = sorted(tactics, key=lambda t: _KILL_CHAIN_ORDER.index(t) if t in _KILL_CHAIN_ORDER else 99)
        timeline.kill_chain_progress = max_progress

        # 生成叙述
        timeline.narrative = self.narrate(timeline)

        return timeline

    def narrate(self, timeline: AttackTimeline) -> str:
        """生成结构化攻击叙述（模板版，同步，无 LLM 依赖）"""
        if not timeline.events:
            return "在指定时间范围内未观察到相关安全事件。"

        parts = []
        parts.append(
            f"目标 {timeline.target_ip} 在最近 {timeline.time_range} 内"
            f"共记录 {timeline.total_events} 条事件"
            f"（{timeline.critical_count} 条严重）。"
        )

        if timeline.tactics_observed:
            tactics_str = " → ".join(timeline.tactics_observed)
            parts.append(f"攻击链推进: {tactics_str}")
            parts.append(
                f"Kill Chain 进度: {timeline.kill_chain_progress + 1}/{len(_KILL_CHAIN_ORDER)} "
                f"({timeline.tactics_observed[-1] if timeline.tactics_observed else 'N/A'})"
            )

        # 按来源统计
        source_counts = {}
        for e in timeline.events:
            source_counts[e.source] = source_counts.get(e.source, 0) + 1
        source_str = ", ".join(f"{k}:{v}" for k, v in source_counts.items())
        parts.append(f"事件来源分布: {source_str}")

        # 关键事件
        critical_events = [e for e in timeline.events if e.severity in ("critical", "high")]
        if critical_events:
            parts.append("关键事件:")
            for e in critical_events[:5]:
                parts.append(f"  [{e.timestamp[:19]}] {e.event_type}: {e.description[:100]}")

        return "\n".join(parts)

    async def narrate_llm(self, timeline: AttackTimeline) -> str:
        """
        LLM 增强攻击叙事（异步，降级到模板版）

        触发条件: settings.llm_edr_enabled == True 且事件数 >= 3
        降级: LLM 不可用/超预算/超时 → 返回模板版 narrate()
        """
        from config import settings as _s

        if not _s.llm_edr_enabled or timeline.total_events < 3:
            return self.narrate(timeline)

        try:
            from llm_enhancer import enhance_edr

            # 构建事件摘要（限制 token）
            events_summary = "\n".join(
                f"[{e.timestamp[:19]}] ({e.source}/{e.severity}) {e.event_type}: {e.description[:80]}"
                for e in timeline.events[:15]
            )

            from prompts import render
            _tactics = ', '.join(timeline.tactics_observed) if timeline.tactics_observed else '无'
            prompt = render("analysis/timeline_narrative",
                            target_ip=timeline.target_ip,
                            time_range=timeline.time_range,
                            total_events=timeline.total_events,
                            critical_count=timeline.critical_count,
                            kill_chain_pos=timeline.kill_chain_progress + 1,
                            kill_chain_total=len(_KILL_CHAIN_ORDER),
                            tactics=_tactics,
                            events_summary=events_summary)

            result = await enhance_edr(
                cache_key=f"timeline:{timeline.target_ip}:{timeline.time_range}",
                prompt_messages=[
                    {"role": "system", "content": render("analysis/timeline_narrative_system")},
                    {"role": "user", "content": prompt},
                ],
                budget_cost_jpy=0.05,
            )

            if result and isinstance(result, dict):
                # enhance_edr 返回 JSON，但我们要求的是文本
                # 如果 LLM 返回了 JSON 格式，提取 narrative 字段
                narrative = result.get("narrative", "")
                if narrative:
                    return narrative

            # 如果 LLM 返回了纯文本（被 _safe_parse_json 解析为 None）
            # 则降级到模板版
            return self.narrate(timeline)

        except Exception as e:
            logger.debug("时间线 LLM 叙事降级: %s", e)
            return self.narrate(timeline)


# ── 全局单例 ──
timeline_builder = TimelineBuilder()
