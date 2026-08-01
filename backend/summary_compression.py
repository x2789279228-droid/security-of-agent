import json
import logging
import hashlib
import time
import re
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


class LLMClient:
    """LLM 客户端 — 支持重试与降级"""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url.rstrip("/")
        self.model = settings.llm_model
        self.client: httpx.AsyncClient | None = None

    async def ensure_client(self):
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=10.0),
            )

    async def chat(self, messages: list[dict], temperature: float = 0.3) -> str:
        from trace_hook import emit_trace

        t_start = time.time()
        prompt_text = "\n".join(m.get("content", "") for m in messages)
        prompt_tokens = estimate_tokens(prompt_text)

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
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage") or {}
                emit_trace(
                    status="success",
                    model=self.model,
                    prompt_tokens=int(usage.get("prompt_tokens", prompt_tokens)),
                    completion_tokens=int(usage.get("completion_tokens", estimate_tokens(content))),
                    total_tokens=int(usage.get("total_tokens", 0)) or (
                        prompt_tokens + estimate_tokens(content)
                    ),
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
        prompt = f"""请将以下内容压缩为简洁的摘要（{max_tokens} tokens以内），保留关键信息和时间顺序：

{text}"""
        return await self.llm.chat([
            {"role": "system", "content": "你是一个专业的信息压缩助手。请保留核心信息。回复简洁。只用中文。"},
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
