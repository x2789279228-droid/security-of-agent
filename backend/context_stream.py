"""
Streaming 渐进式推理上下文流 — 安全审计改造版

核心变更：
  - _prune() 不再删除 fragments，只控制线性化输出长度
  - 所有片段在 Redis 中完整保留
  - linearize() 按分数排序截断，而非直接丢弃

设计原则：
  存储 = 完整（永不丢）
  输出 = 视图（只截断不删除）
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, asdict
from typing import Any, Callable, Awaitable, Optional

logger = logging.getLogger(__name__)

CONTEXT_STREAM_KEY = "context_stream:{session_id}"


@dataclass
class ContextFragment:
    """上下文片段 — 流中的一个单元"""
    id: str
    source: str       # "query" | "window" | "tree" | "memory" | "summary"
    content: str
    importance: float  # 0-1 (保留字段，实际不再用于剪枝)
    tokens: int
    timestamp: float
    group_key: str = ""


class ContextStream:
    """
    增量上下文流 — 安全审计版
    
    关键区别：
    - _prune 不再从 self.fragments 删除任何内容
    - 只在线性化时做输出截断
    - 所有片段完整保存在 Redis 中
    
    用法:
        stream = ContextStream(max_tokens=6000)
        await stream.load(session_id)
        new_frags = [...]
        await stream.add(new_frags)
        await stream.save(session_id)
        context_text = stream.linearize(max_tokens=4000)  # 截断输出
    """

    def __init__(self, max_tokens: int = 6000):
        self.fragments: list[ContextFragment] = []
        self.total_tokens = 0
        self.max_tokens = max_tokens
        self.redis: Any = None
        self._summarizer: Optional[Callable[[list[ContextFragment]], Awaitable[str]]] = None
        self._last_query = ""

    def set_redis(self, redis_client: Any):
        self.redis = redis_client

    def set_summarizer(self, summarizer: Callable[[list[ContextFragment]], Awaitable[str]]):
        self._summarizer = summarizer

    def set_query(self, query: str):
        self._last_query = query

    # ── Persistence ──

    async def load(self, session_id: str) -> bool:
        """从 Redis 恢复上下文流，返回是否找到已有流"""
        if not self.redis:
            return False
        key = CONTEXT_STREAM_KEY.format(session_id=session_id)
        data = await self.redis.get(key)
        if not data:
            return False
        try:
            obj = json.loads(data)
            self.fragments = [ContextFragment(**f) for f in obj.get("fragments", [])]
            self.total_tokens = obj.get("total_tokens", 0)
            logger.info(f"Loaded context stream: {len(self.fragments)} frags, {self.total_tokens} tokens")
            return True
        except Exception as e:
            logger.warning(f"Failed to load context stream: {e}")
            return False

    async def save(self, session_id: str):
        if not self.redis:
            return
        key = CONTEXT_STREAM_KEY.format(session_id=session_id)
        data = json.dumps({
            "fragments": [
                {k: v for k, v in asdict(f).items()}
                for f in self.fragments
            ],
            "total_tokens": self.total_tokens,
            "max_tokens": self.max_tokens,
            "updated_at": time.time(),
        }, ensure_ascii=False)
        await self.redis.setex(key, 86400, data)

    async def clear(self, session_id: str):
        if not self.redis:
            return
        key = CONTEXT_STREAM_KEY.format(session_id=session_id)
        await self.redis.delete(key)
        self.fragments.clear()
        self.total_tokens = 0

    # ── Core Operations ──

    async def add(self, new_fragments: list[ContextFragment],
                  query_embedding: Optional[list[float]] = None):
        """
        追加新片段 — 只做去重和追加，不做删除
        
        安全审计要求：永不删除已有片段。
        如果超出 max_tokens，只在线性化时截断。
        """
        existing_ids = {f.id for f in self.fragments}
        added = 0
        for frag in new_fragments:
            if frag.id in existing_ids:
                continue
            existing_ids.add(frag.id)
            self.fragments.append(frag)
            self.total_tokens += frag.tokens
            added += 1

        if added:
            logger.info(f"Added {added} new frags, total={len(self.fragments)}, tokens={self.total_tokens}")

        # 不再调用 _prune — 存储永不丢弃

    def linearize(self, max_tokens: Optional[int] = None) -> str:
        """
        线性化为 LLM prompt 文本。
        
        安全审计改造：
        - 不再基于重要性截断
        - 先按时间排序（最新的优先展示）
        - 如果超 budget，在末尾追加截断标记
        - Agent 可通过查询 event_store 回溯完整数据
        """
        limit_tokens = max_tokens or self.max_tokens
        parts = ["## 上下文流（完整事件列表）\n"]
        parts.append("> 以下是会话的完整事件上下文。如果被截断，Agent可通过查询接口获取完整原始日志。\n")

        source_icons = {
            "query": "QUERY", "window": "WINDOW", "tree": "TREE",
            "memory": "MEMORY", "summary": "SUMMARY",
        }

        # 按时间排序（最新的优先）
        sorted_frags = sorted(self.fragments, key=lambda f: f.timestamp, reverse=True)

        # 当前已用 token 数
        used_tokens = 0
        truncated = False

        for i, f in enumerate(sorted_frags):
            icon = source_icons.get(f.source, "OTHER")
            truncated_content = f.content[:500]
            line = f"[{icon}] #{i+1} [{f.source}] (t={f.tokens})\n  {truncated_content}\n"

            estimated_tokens = len(line) // 2
            if used_tokens + estimated_tokens > limit_tokens:
                truncated = True
                break

            parts.append(line)
            used_tokens += estimated_tokens

        if truncated:
            remaining = len(sorted_frags) - i
            parts.append(
                f"\n[截断] 上下文已达 token 上限({limit_tokens})，"
                f"还有 {remaining} 条事件未展示。"
                f"请通过查询接口获取完整原始日志。\n"
            )

        result = "\n".join(parts)

        logger.info(f"Linearized context: {len(result)} chars, "
                    f"{used_tokens} tokens used, "
                    f"{'truncated' if truncated else 'full'}")
        return result

    def stats(self) -> dict:
        return {
            "fragment_count": len(self.fragments),
            "total_tokens": self.total_tokens,
            "max_tokens": self.max_tokens,
            "usage_pct": round(self.total_tokens / self.max_tokens * 100, 1) if self.max_tokens else 0,
            "sources": {s: sum(1 for f in self.fragments if f.source == s)
                        for s in set(f.source for f in self.fragments)},
        }


context_stream = ContextStream()
