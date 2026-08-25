import json
import logging
import hashlib
import time
import re
from collections import defaultdict
from datetime import date
from typing import Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def estimate_tokens(text: str) -> int:
    """估算 token 数（中文按字计，其余按 2 字符/1 token）"""
    if not text:
        return 0
    chinese = len(_CJK_RE.findall(text))
    other = len(text) - chinese
    return chinese + int(other / 2) + 1


class CostTracker:
    """LLM 成本追踪器 — 每日预算 + 每事件费用

    预算与单价来自 settings (SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS /
    SHARED_MEMORY_LLM_PRICE_INPUT_PER_1K_TOKENS /
    SHARED_MEMORY_LLM_PRICE_OUTPUT_PER_1K_TOKENS)。
    输入/输出分别计价, 与主流 API 计费模型一致。
    用量同时落库于 llm_traces (由 trace_hook 持久化), 内存仅作运行期门禁;
    重启后用 restore_today_usage() 从 DB 重建当日用量, 保证预算门禁不因重启失效。
    """

    def __init__(
        self,
        daily_budget_tokens: int = 5_000_000,
        price_input_per_1k: float = 0.0,
        price_output_per_1k: float = 0.0,
    ):
        self.daily_budget = daily_budget_tokens
        self.price_input_per_1k = price_input_per_1k
        self.price_output_per_1k = price_output_per_1k
        self._daily_usage: dict[str, int] = defaultdict(int)  # date → total_tokens
        self._daily_prompt: dict[str, int] = defaultdict(int)  # date → prompt_tokens
        self._daily_completion: dict[str, int] = defaultdict(int)  # date → completion_tokens
        self._event_costs: dict[int, int] = {}  # event_id → total_tokens
        self._call_count: dict[str, int] = defaultdict(int)  # date → call_count

    def record(self, tokens: int, event_id: int = 0,
               prompt_tokens: int = 0, completion_tokens: int = 0):
        today = date.today().isoformat()
        self._daily_usage[today] += tokens
        self._daily_prompt[today] += prompt_tokens or 0
        self._daily_completion[today] += completion_tokens or 0
        self._call_count[today] += 1
        if event_id:
            self._event_costs[event_id] = self._event_costs.get(event_id, 0) + tokens
        # Prometheus 暴露 token 消耗(供对齐 token reduction 目标)
        try:
            from metrics import inc_llm_tokens
            inc_llm_tokens("llm", int(tokens or 0))
        except Exception:
            pass

    def restore_today_usage(self, tokens: int, calls: int = 0,
                            prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """从持久化数据恢复今日用量 (启动时调用, 覆盖而非累加)"""
        today = date.today().isoformat()
        self._daily_usage[today] = max(0, int(tokens or 0))
        self._daily_prompt[today] = max(0, int(prompt_tokens or 0))
        self._daily_completion[today] = max(0, int(completion_tokens or 0))
        if calls:
            self._call_count[today] = max(0, int(calls or 0))

    def is_over_budget(self) -> bool:
        today = date.today().isoformat()
        return self._daily_usage[today] >= self.daily_budget

    def remaining_budget(self) -> int:
        today = date.today().isoformat()
        return max(0, self.daily_budget - self._daily_usage[today])

    def estimate_cost_jpy(self, prompt_tokens: int, completion_tokens: int) -> float:
        """按输入/输出每千 token 单价估算费用。

        注意: 返回值的单位与 price_*_per_1k 一致——本项目按 mimo-v2.5 官方单价配置为
        ¥/1K tokens(0.001 输入 / 0.002 输出), 故返回人民币元(¥), 非日元。
        该函数名保留历史命名, 语义请用 estimate_cost_yuan。
        """
        cost = 0.0
        if self.price_input_per_1k > 0:
            cost += (max(0, int(prompt_tokens or 0)) / 1000) * self.price_input_per_1k
        if self.price_output_per_1k > 0:
            cost += (max(0, int(completion_tokens or 0)) / 1000) * self.price_output_per_1k
        return round(cost, 4)

    # 语义别名: 本项目按 ¥(元) 计价, 避免维护者误读为日元换算
    estimate_cost_yuan = estimate_cost_jpy

    def stats(self) -> dict:
        today = date.today().isoformat()
        used = self._daily_usage.get(today, 0)
        prompt = self._daily_prompt.get(today, 0)
        completion = self._daily_completion.get(today, 0)
        return {
            "daily_budget": self.daily_budget,
            "today_usage": used,
            "today_prompt": prompt,
            "today_completion": completion,
            "today_calls": self._call_count.get(today, 0),
            "remaining": self.remaining_budget(),
            "over_budget": self.is_over_budget(),
            "usage_pct": round(used / self.daily_budget * 100, 1) if self.daily_budget else 0.0,
            "price_input_per_1k": self.price_input_per_1k,
            "price_output_per_1k": self.price_output_per_1k,
            "estimated_cost_jpy": self.estimate_cost_jpy(prompt, completion),
            "tracked_events": len(self._event_costs),
        }


cost_tracker = CostTracker(
    daily_budget_tokens=settings.llm_daily_budget_tokens,
    price_input_per_1k=settings.llm_price_input_per_1k_tokens,
    price_output_per_1k=settings.llm_price_output_per_1k_tokens,
)


class LLMClient:
    """LLM 客户端 — 支持重试、降级、成本控制、响应缓存"""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url.rstrip("/")
        self.model = settings.llm_model
        self.client: httpx.AsyncClient | None = None
        self._response_cache: dict[str, tuple[str, float]] = {}  # key → (response, timestamp)
        self._cache_ttl = 600  # 10 分钟缓存

    async def ensure_client(self):
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=10.0),
            )

    async def chat(self, messages: list[dict], temperature: float = 0.3) -> str:
        from trace_hook import emit_trace, get_trace_context

        t_start = time.time()
        prompt_text = "\n".join(m.get("content", "") for m in messages)
        prompt_tokens = estimate_tokens(prompt_text)
        ctx = get_trace_context()
        event_id = int(ctx.get("event_id", 0) or 0)

        # 成本检查：超预算时降级
        if cost_tracker.is_over_budget():
            logger.warning(f"[CostControl] Daily budget exhausted, returning fallback")
            emit_trace(
                status="error", error_type="budget_exhausted",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({
                "error": "每日 LLM 预算已用尽", "fallback": True,
                "budget_stats": cost_tracker.stats(),
            }, ensure_ascii=False)

        # 响应缓存（相同 prompt + temperature → 缓存响应）
        cache_key = hashlib.md5(
            f"{prompt_text}:{temperature}".encode("utf-8")
        ).hexdigest()
        cached = self._response_cache.get(cache_key)
        if cached and (time.time() - cached[1]) < self._cache_ttl:
            emit_trace(
                status="success", cache_hit=True,
                prompt_tokens=prompt_tokens, completion_tokens=0, total_tokens=0,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return cached[0]

        if not self.api_key:
            logger.warning("LLM API key not configured, returning fallback")
            emit_trace(
                status="error", error_type="no_api_key",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({"error": "LLM未配置", "fallback": True}, ensure_ascii=False)
        await self.ensure_client()
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        effort = (getattr(settings, "llm_reasoning_effort", "") or "").strip()
        if effort:
            payload["reasoning_effort"] = effort
        last_error = None
        retries = 0
        for attempt in range(2):
            try:
                resp = await self.client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                if resp.status_code == 400 and "reasoning_effort" in payload:
                    payload.pop("reasoning_effort", None)
                    continue
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage") or {}
                total_tokens = int(usage.get("total_tokens", 0)) or (
                    prompt_tokens + estimate_tokens(content)
                )

                # 成本记录
                cost_tracker.record(
                    total_tokens, event_id=event_id,
                    prompt_tokens=int(usage.get("prompt_tokens", prompt_tokens)),
                    completion_tokens=int(usage.get("completion_tokens", estimate_tokens(content))),
                )

                # 缓存响应
                self._response_cache[cache_key] = (content, time.time())
                # 清理过期缓存
                if len(self._response_cache) > 200:
                    now = time.time()
                    self._response_cache = {
                        k: v for k, v in self._response_cache.items()
                        if now - v[1] < self._cache_ttl
                    }

                emit_trace(
                    status="success",
                    model=self.model,
                    prompt_tokens=int(usage.get("prompt_tokens", prompt_tokens)),
                    completion_tokens=int(usage.get("completion_tokens", estimate_tokens(content))),
                    total_tokens=total_tokens,
                    latency_ms=(time.time() - t_start) * 1000,
                    retry_count=retries,
                )
                return content
            except Exception as e:
                retries += 1
                last_error = e
                logger.warning(f"LLM call attempt {attempt+1} failed: {e}")
        logger.error(f"LLM call failed after retries: {last_error}")
        emit_trace(
            status="error", error_type=type(last_error).__name__ if last_error else "unknown",
            model=self.model,
            prompt_tokens=prompt_tokens,
            latency_ms=(time.time() - t_start) * 1000,
            retry_count=retries,
        )
        return json.dumps({"error": f"LLM调用失败", "fallback": True}, ensure_ascii=False)

    async def close(self):
        if self.client:
            await self.client.aclose()


class EmbeddingClient:
    """Embedding 客户端 — 支持Redis缓存与降级"""

    def __init__(self):
        self.api_key = settings.embedding_api_key
        self.base_url = settings.embedding_base_url.rstrip("/")
        self.model = settings.embedding_model
        self.client: httpx.AsyncClient | None = None
        self.redis = None

    def set_redis(self, redis_client):
        self.redis = redis_client

    async def ensure_client(self):
        if self.client is None:
            self.client = httpx.AsyncClient(timeout=60.0)

    async def embed(self, text: str) -> list[float]:
        if not self.api_key:
            logger.warning("Embedding API key not configured, returning zero vector")
            return [0.0] * settings.embedding_dim

        cache_key = f"embed_cache:{hashlib.md5(text.encode('utf-8')).hexdigest()}"
        if self.redis:
            cached = await self.redis.get(cache_key)
            if cached:
                return json.loads(cached)

        await self.ensure_client()
        payload = {
            "model": self.model,
            "input": text,
        }
        last_error = None
        for attempt in range(2):
            try:
                resp = await self.client.post(
                    f"{self.base_url}/embeddings",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                result = data["data"][0]["embedding"]
                if self.redis:
                    await self.redis.setex(cache_key, settings.embedding_cache_ttl, json.dumps(result))
                return result
            except Exception as e:
                last_error = e
                logger.warning(f"Embedding attempt {attempt+1} failed: {e}")
        logger.error(f"Embedding call failed after retries: {last_error}")
        return [0.0] * settings.embedding_dim

    async def close(self):
        if self.client:
            await self.client.aclose()


class SummaryCompression:
    def __init__(self):
        self.llm = LLMClient()

    async def ensure_client(self):
        await self.llm.ensure_client()

    async def compress(self, text: str, max_tokens: int = 500) -> str:
        from prompts import render
        prompt = render("analysis/summary_compress", max_tokens=max_tokens, text=text)
        return await self.llm.chat([
            {"role": "system", "content": render("analysis/summary_compress_system")},
            {"role": "user", "content": prompt},
        ])

    async def summarize_conversation(self, messages: list[dict]) -> str:
        text = "\n".join(
            f"[{m.get('agent_id','unknown')}][{m.get('role','user')}]: {m.get('content','')}"
            for m in messages
        )
        return await self.compress(text)

    async def close(self):
        await self.llm.close()


summary = SummaryCompression()
embedder = EmbeddingClient()
