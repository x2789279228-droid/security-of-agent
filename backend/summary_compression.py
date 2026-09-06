import asyncio
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
        unlimited: bool = None,
    ):
        self.daily_budget = daily_budget_tokens
        self.price_input_per_1k = price_input_per_1k
        self.price_output_per_1k = price_output_per_1k
        if unlimited is None:
            unlimited = daily_budget_tokens <= 0
        self._unlimited = bool(unlimited)
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
        if self._unlimited:
            return False
        today = date.today().isoformat()
        return self._daily_usage[today] >= self.daily_budget

    def remaining_budget(self):
        if self._unlimited:
            return None
        today = date.today().isoformat()
        return max(0, self.daily_budget - self._daily_usage[today])

    def estimate_cost_yuan(self, prompt_tokens: int, completion_tokens: int) -> float:
        """按输入/输出每千 token 单价估算费用。

        返回人民币元(¥): price_*_per_1k 的单位为 ¥/1K tokens
        (本项目按 mimo-v2.5 官方单价配置, 0.001 输入 / 0.002 输出)。
        """
        cost = 0.0
        if self.price_input_per_1k > 0:
            cost += (max(0, int(prompt_tokens or 0)) / 1000) * self.price_input_per_1k
        if self.price_output_per_1k > 0:
            cost += (max(0, int(completion_tokens or 0)) / 1000) * self.price_output_per_1k
        return round(cost, 4)

    # 弃用别名: 历史命名误标 JPY(实为人民币元), 保留一个版本供旧调用方过渡
    estimate_cost_jpy = estimate_cost_yuan

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
            "unlimited": bool(self._unlimited),
            "usage_pct": (0.0 if self._unlimited else
                          round(used / self.daily_budget * 100, 1) if self.daily_budget else 0.0),
            "price_input_per_1k": self.price_input_per_1k,
            "price_output_per_1k": self.price_output_per_1k,
            "estimated_cost_yuan": self.estimate_cost_yuan(prompt, completion),
            # 弃用键: 与 estimated_cost_yuan 同值, 保留一个版本供前端/脚本迁移
            "estimated_cost_jpy": self.estimate_cost_yuan(prompt, completion),
            "tracked_events": len(self._event_costs),
        }


cost_tracker = CostTracker(
    daily_budget_tokens=settings.llm_daily_budget_tokens,
    unlimited=getattr(settings, "llm_budget_unlimited", None),
    price_input_per_1k=settings.llm_price_input_per_1k_tokens,
    price_output_per_1k=settings.llm_price_output_per_1k_tokens,
)


def _extract_text_content(data: dict) -> str:
    """从 LLM 响应中稳健提取文本内容（兼容 OpenAI 标准与讯飞 MaaS/ASTRON 等非标准 schema）。

    OpenAI 兼容: {choices:[{message:{content}}]} 或 delta.content (流式)
    ASTRON/讯飞 MaaS: 可能为 {content:...} / {output_text:...} / {text:...} / {response:...}
    """
    if not isinstance(data, dict):
        raise ValueError("LLM 响应不是 JSON 对象")
    # 标准 OpenAI chat/completions
    try:
        choices = data.get("choices") or []
        if choices:
            msg = choices[0].get("message") or choices[0].get("delta") or {}
            c = msg.get("content")
            if isinstance(c, list):  # 多模态 content 数组 → 取首个 text
                for part in c:
                    if isinstance(part, dict) and part.get("type") == "text":
                        c = part.get("text")
                        break
            if c is not None:
                return str(c)
    except Exception:
        pass
    # 常见非标准/扁平字段
    for key in ("output_text", "text", "content", "response", "answer", "result"):
        v = data.get(key)
        if isinstance(v, str) and v:
            return v
    # 嵌套 choices[0].text (AISTUDIO/部分 vLLM)
    try:
        c = data["choices"][0].get("text")
        if isinstance(c, str) and c:
            return c
    except Exception:
        pass
    raise ValueError(f"无法从 LLM 响应提取文本: {list(data.keys())[:6]}")


class LLMClient:
    """LLM 客户端 — 支持重试、降级、成本控制、响应缓存"""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url.rstrip("/")
        self.model = settings.llm_model
        self.client: httpx.AsyncClient | None = None
        # LLM 响应缓存: 进程内 dict 作为快速路径, Redis 作为跨重启/跨容器共享源
        self._response_cache: dict[str, str] = {}  # key → response(JSON {v,t}), 快速路径
        self.redis = None
        self._cache_ttl = settings.llm_cache_ttl

    def set_redis(self, redis_client):
        self.redis = redis_client

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

        # 响应缓存（相同 prompt + temperature → 缓存响应）: Redis 主源 + 本地 dict 快速路径
        # 缓存命中是零 token 成本路径（不扣预算），必须置于预算门禁之前——
        # 否则预算耗尽期间连免费命中也不可达，缓存"只出不进"随 TTL 枯竭（被门禁饿死）。
        digest = hashlib.md5(
            f"{prompt_text}:{temperature}".encode("utf-8")
        ).hexdigest()
        cache_key = f"llmcache:{digest}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            emit_trace(
                status="success", cache_hit=True,
                prompt_tokens=prompt_tokens, completion_tokens=0, total_tokens=0,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return cached

        # 成本检查：超预算时降级（仅拦真实 API 调用，上面的缓存命中不受门禁影响）
        if cost_tracker.is_over_budget():
            logger.warning(f"[CostControl] Daily budget exhausted, returning fallback")
            emit_trace(
                status="degraded", error_type="budget_exhausted",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({
                "error": "每日 LLM 预算已用尽", "fallback": True,
                "budget_stats": cost_tracker.stats(),
            }, ensure_ascii=False)

        if not self.api_key:
            logger.warning("LLM API key not configured, returning fallback")
            emit_trace(
                status="degraded", error_type="no_api_key",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({"error": "LLM未配置", "fallback": True}, ensure_ascii=False)
        await self.ensure_client()
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "reasoning_split": True,  # MiniMax-M3: thinking 拆到独立字段，不污染 JSON 输出
        }
        effort = (getattr(settings, "llm_reasoning_effort", "") or "").strip()
        if effort:
            payload["reasoning_effort"] = effort
        from llm_limiter import LlmSlotTimeout, get_llm_limiter
        _triage = (ctx.get("log_data") or {}).get("_audit_triage") or {}
        _tier = str(_triage.get("tier") or ctx.get("tier") or "P2")
        try:
            async with get_llm_limiter().acquire(tier=_tier):
                return await self._chat_http(
                    payload, prompt_tokens, t_start, event_id, cache_key,
                )
        except LlmSlotTimeout as e:
            logger.warning("LLM slot timeout: %s", e)
            emit_trace(
                status="degraded", error_type="llm_slot_timeout",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({
                "error": "LLM slot timeout", "fallback": True,
                "error_type": "llm_slot_timeout", "retryable": True,
            }, ensure_ascii=False)

    async def _chat_http(self, payload, prompt_tokens, t_start, event_id, cache_key) -> str:
        from trace_hook import emit_trace
        last_error = None
        retries = 0
        _no_reasoning_split = False
        for attempt in range(3):
            try:
                req_payload = dict(payload)
                if _no_reasoning_split:
                    req_payload.pop("reasoning_split", None)
                resp = await self.client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=req_payload,
                )
                if resp.status_code == 400 and "reasoning_effort" in req_payload:
                    payload.pop("reasoning_effort", None)
                    continue
                if resp.status_code == 429:
                    try:
                        from metrics import inc_llm_429
                        inc_llm_429()
                    except Exception:
                        pass
                    retry_after = (resp.headers.get("retry-after") or "").strip()
                    wait_cap = float(getattr(settings, "llm_429_retry_s", 1.0) or 1.0)
                    wait_s = wait_cap
                    if retry_after:
                        try:
                            wait_s = min(wait_cap, max(0.05, float(retry_after)))
                        except ValueError:
                            pass
                    retries += 1
                    last_error = f"HTTP 429 Too Many Requests (attempt {attempt+1})"
                    emit_trace(
                        status="degraded", error_type="rate_limited_429",
                        prompt_tokens=prompt_tokens,
                        latency_ms=(time.time() - t_start) * 1000,
                        retry_count=retries,
                    )
                    if retries <= 1:
                        logger.warning(
                            "LLM rate-limited (429), short retry %.2fs (attempt %s)",
                            wait_s, attempt + 1,
                        )
                        await asyncio.sleep(wait_s)
                        continue
                    logger.warning("LLM 429 after short retry — releasing slot")
                    return json.dumps({
                        "error": "LLM rate-limited",
                        "fallback": True,
                        "error_type": "rate_limited_429",
                        "retryable": True,
                    }, ensure_ascii=False)
                resp.raise_for_status()
                data = resp.json()
                try:
                    content = _extract_text_content(data)
                except (ValueError, KeyError, IndexError, TypeError):
                    if req_payload.get("reasoning_split") and not _no_reasoning_split:
                        # reasoning_split=True 时 content 可能为空(reasoning 在
                        # 独立字段), 关闭该参数让模型把正文写回 content
                        logger.warning(
                            "LLM content extraction failed with reasoning_split, "
                            "retrying with reasoning_split disabled"
                        )
                        _no_reasoning_split = True
                        retries += 1
                        continue
                    raise
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

                # 缓存响应(Redis 主源 + 本地快速路径); TTL 交由 Redis EXPIRE 管理, 不做全量清空
                await self._cache_set(cache_key, content)

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
            status="degraded", error_type=type(last_error).__name__ if last_error else "unknown",
            model=self.model,
            prompt_tokens=prompt_tokens,
            latency_ms=(time.time() - t_start) * 1000,
            retry_count=retries,
        )
        return json.dumps({"error": f"LLM调用失败", "fallback": True}, ensure_ascii=False)

    async def close(self):
        if self.client:
            await self.client.aclose()

    # ── LLM 响应缓存基底 (Redis 主源 + 本地 dict 快速路径) ──

    async def _cache_get(self, key: str):
        """取缓存; 命中返回内容, 未命中/异常返回 None(降级实时调用)。"""
        # 1) 本地快速路径
        local = self._response_cache.get(key)
        if local is not None:
            return local
        # 2) Redis 共享源(raw 即响应内容; 命中后回填本地)
        if self.redis is not None and key.startswith("llmcache:"):
            try:
                raw = await self.redis.get(key)
                if raw is not None:
                    text_val = raw.decode() if isinstance(raw, (bytes, bytearray)) else raw
                    self._response_cache[key] = text_val
                    if len(self._response_cache) > 5000:  # 极简上限防本地畸形膨胀
                        self._response_cache.pop(next(iter(self._response_cache)), None)
                    return text_val
            except Exception:
                pass
        return None

    async def _cache_set(self, key: str, content: str):
        """写入 Redis(带 TTL)与本地快速路径; Redis 不可用时静默降级为仅本地。"""
        self._response_cache[key] = content
        if self.redis is not None and key.startswith("llmcache:"):
            try:
                await self.redis.setex(key, self._cache_ttl, content)
            except Exception:
                pass


class EmbeddingClient:
    """Embedding 客户端 — 支持Redis缓存与降级"""

    def __init__(self):
        self.api_key = settings.embedding_api_key
        self.base_url = settings.embedding_base_url.rstrip("/")
        self.model = settings.embedding_model
        self.client: httpx.AsyncClient | None = None
        self.redis = None
        # 缓存命中计数: hits/misses/errors — 嵌入命中率指标的数据源
        # (Redis 未注入/故障计入 misses, 该"全 miss"状态因此可见)
        self._stats = {"hits": 0, "misses": 0, "errors": 0}

    def stats(self) -> dict:
        total = self._stats["hits"] + self._stats["misses"]
        return {
            **self._stats,
            "total": total,
            "hit_rate": round(self._stats["hits"] / total, 4) if total else 0.0,
        }

    def set_redis(self, redis_client):
        self.redis = redis_client

    async def ensure_client(self):
        if self.client is None:
            self.client = httpx.AsyncClient(timeout=60.0)

    async def embed(self, text: str, type_: str = "db") -> list[float]:
        """向量化。

        type_ 默认为 "db"（用于构建向量库）；查询检索时调用方应传 "query" 以启用 MiniMax
        的不对称检索方案。本方法兼容两种响应格式：
          - MiniMax embo-01:  {vectors: [[...]], base_resp: {...}}
          - OpenAI 兼容:     {data: [{embedding: [...]}], ...}

        可观测性: 每条调用经 emit_trace(caller="embedding") 落 AgentTrace,
        cache_hit 区分缓存命中/未命中,供 agent-traces/stats 聚合命中率。
        """
        from trace_hook import emit_trace

        t_start = time.time()

        def _trace(**kw):
            emit_trace(caller="embedding", operation="embed", model=self.model,
                       total_tokens=0, latency_ms=(time.time() - t_start) * 1000, **kw)

        if not self.api_key:
            self._stats["errors"] += 1
            logger.warning("Embedding API key not configured, returning zero vector")
            _trace(status="degraded", error_type="no_api_key")
            return [0.0] * settings.embedding_dim

        # 缓存键包含 type，避免 db/query 互相串扰
        cache_key = f"embed_cache:{type_}:{hashlib.md5(text.encode('utf-8')).hexdigest()}"
        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
            except Exception as e:
                # Redis 故障降级为 miss 继续真实调用（此前会直接冒泡中断检索）
                logger.warning(f"Embedding cache read failed, falling back to API: {e}")
                cached = None
            if cached:
                self._stats["hits"] += 1
                _trace(status="success", cache_hit=True)
                return json.loads(cached)
        self._stats["misses"] += 1

        await self.ensure_client()
        # MiniMax embo-01 协议：texts 数组 + type 字段
        payload = {
            "model": self.model,
            "texts": [text],
            "type": type_,
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
                # 双协议响应兼容：MiniMax (vectors) / OpenAI (data[].embedding)
                if isinstance(data, dict) and "vectors" in data and data["vectors"]:
                    result = data["vectors"][0]
                elif isinstance(data, dict) and "data" in data and data["data"]:
                    result = data["data"][0]["embedding"]
                else:
                    raise ValueError(f"Unknown embedding response keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
                if self.redis:
                    await self.redis.setex(cache_key, settings.embedding_cache_ttl, json.dumps(result))
                _trace(status="success", cache_hit=False)
                return result
            except Exception as e:
                last_error = e
                logger.warning(f"Embedding attempt {attempt+1} failed: {e}")
        self._stats["errors"] += 1
        logger.error(f"Embedding call failed after retries: {last_error}")
        _trace(status="error", error_type="embedding_failed")
        return [0.0] * settings.embedding_dim


    async def _post_embedding(self, texts, type_):
        import os as _o
        batch_key = _o.environ.get("SHARED_MEMORY_EMBEDDING_BATCH_KEY", "").strip() or "texts"
        low = (str(self.model or "") + "|" + str(self.base_url or "")).lower()
        if batch_key not in ("texts", "input"):
            batch_key = "texts" if ("embo" in low or "minimax" in low) else "input"
        payload = {"model": self.model, batch_key: texts}
        if batch_key == "texts":
            payload["type"] = type_
        resp = await self.client.post(
            f"{self.base_url}/embeddings",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and data.get("vectors"):
            return list(data["vectors"])
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return [d["embedding"] for d in data["data"] if isinstance(d, dict) and "embedding" in d]
        raise ValueError("Unknown embedding response keys")

    async def embed_batch(self, texts, type_: str = "db"):
        import json as _json, hashlib as _hash, logging as _log
        from trace_hook import emit_trace
        t0 = __import__("time").time()
        items = list(texts)
        out = [None] * len(items)
        miss_idx = []
        for i, tx in enumerate(items):
            if not isinstance(tx, str) or not tx.strip():
                out[i] = [0.0] * settings.embedding_dim
                continue
            key = f"embed_cache:{type_}:{_hash.md5(tx.encode('utf-8')).hexdigest()}"
            val = None
            if self.redis:
                try:
                    val = await self.redis.get(key)
                except Exception:
                    val = None
            if val:
                self._stats["hits"] += 1
                try:
                    out[i] = _json.loads(val)
                except Exception:
                    out[i] = None
            else:
                self._stats["misses"] += 1
                miss_idx.append(i)
        failures = 0
        if miss_idx:
            await self.ensure_client()
            need = [items[i] for i in miss_idx]
            got = []
            for attempt in range(2):
                try:
                    got = await self._post_embedding(need, type_)
                    break
                except Exception as e:
                    failures += 1
                    if attempt == 0:
                        _log.getLogger(__name__).warning(f"Embedding batch attempt1 failed: {e}")
            if not got:
                for i in miss_idx:
                    out[i] = [0.0] * settings.embedding_dim
                emit_trace(caller="embedding", operation="embed_batch", model=self.model,
                           total_tokens=0, latency_ms=(__import__("time").time()-t0)*1000,
                           status="error", error_type="embedding_failed")
            else:
                for k, i in enumerate(miss_idx):
                    emb = got[k] if k < len(got) else [0.0]*settings.embedding_dim
                    out[i] = emb
                    key = f"embed_cache:{type_}:{_hash.md5(str(items[i]).encode('utf-8')).hexdigest()}"
                    if self.redis:
                        try:
                            await self.redis.setex(key, settings.embedding_cache_ttl, _json.dumps(emb))
                        except Exception:
                            pass
        emit_trace(caller="embedding", operation="embed_batch", model=self.model,
                   total_tokens=0, latency_ms=(__import__("time").time()-t0)*1000,
                   status=("degraded" if failures else ("success" if miss_idx else "cache")),
                   cache_hit=not bool(miss_idx))
        return out

    async def embed_many(self, texts, type_: str = "db"):
        import os as _o
        size = max(1, int(_o.environ.get("EMBED_BATCH_SIZE", "100") or "100"))
        texts = list(texts)
        acc = []
        for i in range(0, len(texts), size):
            acc.extend(await self.embed_batch(texts[i:i+size], type_=type_))
        return acc

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
