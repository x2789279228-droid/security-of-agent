"""
分块器 (Chunker) — 将工具返回的大量事件拆分为可管理的审核块

分块策略（按优先级）:
  1. 攻击链优先 — 关联引擎识别的事件单独成块
  2. 按 IP 分块 — 同 src_ip 的事件聚为一组
  3. 按时间窗分块 — 30 分钟窗口
  4. 散兵块 — 剩余独立事件

块大小控制：
  每块 ≤ MAX_CHUNK_EVENTS 条事件 或 ≤ MAX_CHUNK_TOKENS tokens
  超过则递归拆分（按时间窗二次切分）
"""
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

MAX_CHUNK_EVENTS = 20       # 每块最多事件数
MAX_CHUNK_TOKENS = 2000     # 每块预估最大 tokens


@dataclass
class AuditChunk:
    """一个待审核的块"""
    chunk_id: str
    strategy: str               # "attack_chain" | "by_ip" | "time_window" | "standalone"
    label: str                  # 块描述（如 "IP 10.0.0.5 的15条事件"）
    events: list[dict] = field(default_factory=list)
    source_type: str = ""       # 事件类型分布
    severity_range: str = ""    # 严重度范围
    estimated_tokens: int = 0

    def to_prompt_block(self) -> str:
        """转成 LLM prompt 中的一块"""
        lines = [f"### 审核块: {self.label} (策略={self.strategy})"]
        for e in self.events:
            sev = e.get("severity", "?").upper()
            et = e.get("event_type", e.get("type", "?"))
            msg = (e.get("message", "") or "")[:150]
            aid = e.get("id", e.get("event_id", "?"))
            lines.append(f"  [{sev}] [{et}] #{aid} {msg}")
        return "\n".join(lines)


class Chunker:
    """
    分块器

    chunk(tool_results, correlation_chain_ids) → list[AuditChunk]
    """

    def __init__(self):
        self.max_events = MAX_CHUNK_EVENTS
        self.max_tokens = MAX_CHUNK_TOKENS

    def chunk(
        self,
        events: list[dict],
        chain_event_ids: set = None,
    ) -> list[AuditChunk]:
        """
        将事件列表拆分为审核块

        Args:
            events: 待审核事件列表（每条含 id, event_type, severity, src_ip 等）
            chain_event_ids: 已关联到攻击链的事件 ID 集合

        Returns:
            list[AuditChunk]
        """
        chain_event_ids = chain_event_ids or set()
        total = len(events)
        if total == 0:
            return []

        logger.info(f"Chunker: splitting {total} events, {len(chain_event_ids)} in chains")

        chunks: list[AuditChunk] = []
        remaining: list[dict] = []
        chain_events: list[dict] = []

        # 1. 攻击链事件单独出块
        for evt in events:
            eid = evt.get("id", evt.get("event_id"))
            if eid in chain_event_ids:
                chain_events.append(evt)
            else:
                remaining.append(evt)

        if chain_events:
            sub_chunks = self._split_to_size(
                chain_events, "attack_chain", "攻击链关联事件"
            )
            chunks.extend(sub_chunks)

        # 2. 按 IP 分组
        ip_groups: dict[str, list[dict]] = defaultdict(list)
        for evt in remaining:
            ip = evt.get("src_ip", "unknown")
            ip_groups[ip].append(evt)

        # 3. 每个 IP 的事件再分块
        for ip, ip_events in sorted(ip_groups.items()):
            if len(ip_events) <= self.max_events:
                chunks.append(AuditChunk(
                    chunk_id=f"ip_{ip}",
                    strategy="by_ip",
                    label=f"源IP {ip} 的 {len(ip_events)} 条事件",
                    events=ip_events,
                    source_type=self._summarize_types(ip_events),
                    severity_range=self._severity_range(ip_events),
                    estimated_tokens=self._estimate_tokens(ip_events),
                ))
            else:
                # IP 内事件太多 → 按时间窗二次拆分
                sorted_evts = sorted(
                    ip_events,
                    key=lambda e: (e.get("created_at") or "")
                )
                sub = self._split_by_time(sorted_evts, f"ip_{ip}", ip)
                chunks.extend(sub)

        # 按块大小排序（大的先审，因为通常更重要）
        chunks.sort(key=lambda c: len(c.events), reverse=True)

        logger.info(
            f"Chunker: produced {len(chunks)} chunks "
            f"({len(chain_events)} chain, {len(remaining)} remaining)"
        )
        return chunks

    def _split_to_size(
        self, events: list[dict], strategy: str, label_prefix: str
    ) -> list[AuditChunk]:
        """按 MAX_CHUNK_EVENTS 切分"""
        chunks = []
        for i in range(0, len(events), self.max_events):
            batch = events[i:i + self.max_events]
            chunk_id = f"{strategy}_{i // self.max_events}"
            chunks.append(AuditChunk(
                chunk_id=chunk_id,
                strategy=strategy,
                label=f"{label_prefix} (第{i//self.max_events+1}组, {len(batch)}条)",
                events=batch,
                source_type=self._summarize_types(batch),
                severity_range=self._severity_range(batch),
                estimated_tokens=self._estimate_tokens(batch),
            ))
        return chunks

    def _split_by_time(
        self, events: list[dict], prefix: str, ip: str
    ) -> list[AuditChunk]:
        """按时间窗口切分（30分钟一个窗口）"""
        from datetime import datetime, timedelta

        chunks = []
        current_batch = []
        window_start = None

        for evt in events:
            ts_str = evt.get("created_at", "")
            if not ts_str:
                current_batch.append(evt)
                continue

            try:
                ts = datetime.fromisoformat(ts_str)
            except Exception:
                current_batch.append(evt)
                continue

            if window_start is None:
                window_start = ts
                current_batch = [evt]
            elif (ts - window_start).total_seconds() < 1800:
                current_batch.append(evt)
            else:
                if current_batch:
                    chunks.append(AuditChunk(
                        chunk_id=f"{prefix}_tw{len(chunks)}",
                        strategy="time_window",
                        label=f"IP {ip} {window_start.strftime('%H:%M')}时段 "
                              f"({len(current_batch)}条)",
                        events=current_batch,
                        source_type=self._summarize_types(current_batch),
                        severity_range=self._severity_range(current_batch),
                        estimated_tokens=self._estimate_tokens(current_batch),
                    ))
                window_start = ts
                current_batch = [evt]

        if current_batch:
            chunks.append(AuditChunk(
                chunk_id=f"{prefix}_tw{len(chunks)}",
                strategy="time_window",
                label=f"IP {ip} 最后时段 ({len(current_batch)}条)",
                events=current_batch,
                source_type=self._summarize_types(current_batch),
                severity_range=self._severity_range(current_batch),
                estimated_tokens=self._estimate_tokens(current_batch),
            ))

        return chunks

    def _summarize_types(self, events: list[dict]) -> str:
        types = set(
            e.get("event_type", e.get("type", "?"))
            for e in events
        )
        return ", ".join(sorted(types)[:5])

    def _severity_range(self, events: list[dict]) -> str:
        sevs = [e.get("severity", "info") for e in events]
        levels = ["critical", "high", "medium", "low", "info"]
        min_idx = min((levels.index(s) for s in sevs if s in levels), default=4)
        max_idx = max((levels.index(s) for s in sevs if s in levels), default=4)
        return f"{levels[min_idx]}~{levels[max_idx]}"

    def _estimate_tokens(self, events: list[dict]) -> int:
        text = json.dumps(events, ensure_ascii=False)
        return len(text) // 2


chunker = Chunker()
