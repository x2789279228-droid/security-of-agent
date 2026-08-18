"""
LLM 增强器 (LLM Enhancer) — P0.S 共享基础设施

三大 LLM 增强模块 (流量/钓鱼/数据安全) 共用的:
  1. 并发限制 (保护 LLM API,默认 5 并发)
  2. 模块日预算分桶 (任一超限降级,不挤占其它模块)
  3. 缓存命中 (除 summary.llm 自身 10min 缓存外的业务级去重)
  4. 超时降级 (默认 15s,拒绝 LLM 卡死)
  5. 异常吃掉 (绝不抛回调用方)
  6. trace 留痕 (复用 trace_hook)

性能红线:
  - 主路径 0 等待 (调用方走 asyncio.create_task)
  - LLM API 并发 ≤ settings.llm_enhancer_concurrency
  - 重复输入命中缓存 < 1ms
  - 失败返回 None,调用方视为无 LLM 增强

调用方式:
    from llm_enhancer import llm_enhancer
    result = await llm_enhancer.enhance(
        module="phishing",
        cache_key=f"phish:{sender}:{subject}",
        prompt_messages=[...],
        budget_cost_jpy=0.1,    # 单次成本估算(¥)
    )
"""
import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Callable, Awaitable

from config import settings

logger = logging.getLogger(__name__)


# ── 业务级去重缓存 (key → (result, expire_ts)) ──
# 与 summary.llm 10min 响应缓存互补:对应"业务语义"级去重,
# 例如同一 sender+subject 反复判定,只跑一次
_BIZ_CACHE: dict[str, tuple[Optional[dict], float]] = {}
_BIZ_CACHE_TTL = 600  # 10 分钟
_BIZ_CACHE_MAX = 2000


# ── 模块日预算跟踪 ──
# {module: {"date_str": "YYYY-MM-DD", "used_jpy": float}}
_MODULE_BUDGET: dict[str, dict] = {}


# ── 共享并发信号量 (延迟初始化,避免在无 event loop 的导入期报错) ──
_SEMAPHORE: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    global _SEMAPHORE
    if _SEMAPHORE is None:
        _SEMAPHORE = asyncio.Semaphore(settings.llm_enhancer_concurrency)
    return _SEMAPHORE


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _check_and_consume_budget(module: str, cost_jpy: float) -> bool:
    """
    检查并扣减模块日预算.超限返回 False (不调用 LLM).
    """
    budget_map = {
        "traffic": settings.llm_traffic_budget_jpy_per_day,
        "phishing": settings.llm_phishing_budget_jpy_per_day,
        "data_security": settings.llm_data_security_budget_jpy_per_day,
        "encrypted_traffic": settings.llm_encrypted_traffic_budget_jpy_per_day,
        "edr": settings.llm_edr_budget_jpy_per_day,
        "intel": settings.llm_intel_budget_jpy_per_day,
        "sandbox": settings.llm_sandbox_budget_jpy_per_day,
    }
    limit = budget_map.get(module, 0)
    if limit <= 0:
        return False

    today = _today_str()
    bucket = _MODULE_BUDGET.setdefault(module, {"date": today, "used": 0.0})
    # 跨日重置
    if bucket["date"] != today:
        bucket["date"] = today
        bucket["used"] = 0.0

    if bucket["used"] + cost_jpy > limit:
        logger.warning(
            f"[LlmEnhancer] module '{module}' daily budget exhausted: "
            f"used={bucket['used']:.2f}/{limit}¥, skip this call"
        )
        return False

    bucket["used"] += cost_jpy
    return True


def _release_budget_on_failure(module: str, cost_jpy: float) -> None:
    """LLM 调用失败时退还预算,避免预算黑洞."""
    bucket = _MODULE_BUDGET.get(module)
    if bucket:
        bucket["used"] = max(0.0, bucket["used"] - cost_jpy)


def get_module_budget_status() -> dict:
    """供运营 KPI / dashboard 调用."""
    budget_map = {
        "traffic": settings.llm_traffic_budget_jpy_per_day,
        "phishing": settings.llm_phishing_budget_jpy_per_day,
        "data_security": settings.llm_data_security_budget_jpy_per_day,
        "encrypted_traffic": settings.llm_encrypted_traffic_budget_jpy_per_day,
        "edr": settings.llm_edr_budget_jpy_per_day,
        "intel": settings.llm_intel_budget_jpy_per_day,
        "sandbox": settings.llm_sandbox_budget_jpy_per_day,
    }
    out = {}
    for module, limit in budget_map.items():
        bucket = _MODULE_BUDGET.get(module, {"date": _today_str(), "used": 0.0})
        if bucket["date"] != _today_str():
            bucket = {"date": _today_str(), "used": 0.0}
        out[module] = {
            "limit_jpy": limit,
            "used_jpy": round(bucket["used"], 3),
            "remaining_jpy": round(max(0.0, limit - bucket["used"]), 3),
            "usage_pct": round((bucket["used"] / limit * 100) if limit > 0 else 0, 1),
        }
    return out


def _biz_cache_key(module: str, raw_key: str) -> str:
    """业务缓存键:拼接 module 防止跨模块撞车."""
    return f"{module}:{hashlib.md5(raw_key.encode('utf-8')).hexdigest()}"


def _biz_cache_get(key: str) -> Optional[dict]:
    entry = _BIZ_CACHE.get(key)
    if entry is None:
        return None
    result, expire_ts = entry
    if time.time() > expire_ts:
        _BIZ_CACHE.pop(key, None)
        return None
    return result


def _biz_cache_set(key: str, value: Optional[dict]) -> None:
    if len(_BIZ_CACHE) >= _BIZ_CACHE_MAX:
        # 简单淘汰失效项
        now = time.time()
        for k in list(_BIZ_CACHE.keys()):
            if now > _BIZ_CACHE[k][1]:
                _BIZ_CACHE.pop(k, None)
                if len(_BIZ_CACHE) < _BIZ_CACHE_MAX:
                    break
    _BIZ_CACHE[key] = (value, time.time() + _BIZ_CACHE_TTL)


def reset_daily_budgets() -> None:
    """由 scheduler 每日凌晨调用,显式重置所有模块预算."""
    today = _today_str()
    for module in ("traffic", "phishing", "data_security",
                   "encrypted_traffic", "edr", "intel", "sandbox"):
        _MODULE_BUDGET[module] = {"date": today, "used": 0.0}
    logger.info("[LlmEnhancer] daily budgets reset")


# ── 通用异步 LLM 增强 (主接口) ──

async def enhance(
    *,
    module: str,
    cache_key: str,
    prompt_messages: list[dict],
    budget_cost_jpy: float = 0.1,
    timeout_sec: Optional[int] = None,
    temperature: float = 0.1,
) -> Optional[dict]:
    """
    通用 LLM 增强调度.调用方必须以 asyncio.create_task 包裹,本函数不做主路径等待.

    Args:
        module: "traffic" | "phishing" | "data_security"
        cache_key: 业务去重键 (如 "phish:no-reply@amaz0n.com:URGENT account")
        prompt_messages: OpenAI 兼容 messages 列表
        budget_cost_jpy: 单次成本估算 (¥),超预算则不调用
        timeout_sec: 单次超时,None=用 settings.llm_enhancer_timeout_sec

    Returns:
        解析后的 dict (LLM 返回 JSON) 或 None (降级/失败/超时/超预算)

    性能保障:
        - 缓存命中 → 0 LLM 调用
        - 信号量限流 → 保护 LLM API
        - 超时 → 0 卡死
        - 异常 → 0 抛出
        - 预算超限 → 0 调用
    """
    if timeout_sec is None:
        timeout_sec = settings.llm_enhancer_timeout_sec

    # 1. 业务缓存命中 → 立即返回
    biz_key = _biz_cache_key(module, cache_key)
    cached = _biz_cache_get(biz_key)
    if cached is not None:
        logger.debug(f"[LlmEnhancer:{module}] cache hit: {cache_key[:50]}")
        return cached

    # 2. 模块开关检查
    enabled_map = {
        "traffic": settings.llm_traffic_enabled,
        "phishing": settings.llm_phishing_enabled,
        "data_security": settings.llm_data_security_enabled,
        "encrypted_traffic": settings.llm_encrypted_traffic_enabled,
        "edr": settings.llm_edr_enabled,
        "intel": settings.llm_intel_enabled,
        "sandbox": settings.llm_sandbox_enabled,
    }
    if not enabled_map.get(module, False):
        return None

    # 3. 预算检查
    if not _check_and_consume_budget(module, budget_cost_jpy):
        return None

    # 4. 信号量限流 + 超时 + 异常吃掉
    sem = _get_semaphore()
    try:
        async with sem:
            async with asyncio.timeout(timeout_sec):
                from summary_compression import summary
                raw = await summary.llm.chat(prompt_messages, temperature=temperature)
                parsed = _safe_parse_json(raw)
                if parsed is not None:
                    _biz_cache_set(biz_key, parsed)
                return parsed
    except asyncio.TimeoutError:
        logger.warning(f"[LlmEnhancer:{module}] timeout {timeout_sec}s")
        _release_budget_on_failure(module, budget_cost_jpy)
        return None
    except Exception as e:
        logger.warning(f"[LlmEnhancer:{module}] LLM call failed: {e}")
        _release_budget_on_failure(module, budget_cost_jpy)
        return None


def _safe_parse_json(raw: str) -> Optional[dict]:
    """LLM 输出严格 JSON 解析.失败返回 None (调用方视为降级)."""
    if not raw:
        return None
    raw = raw.strip()
    # 兼容 LLM 包裹 ```json ... ``` 的情况
    if raw.startswith("```"):
        # 去掉首尾 ``` 行
        lines = raw.split("\n")
        if len(lines) >= 3 and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()
    try:
        result = json.loads(raw)
        return result if isinstance(result, dict) else None
    except json.JSONDecodeError:
        # 尝试提取第一段 JSON
        try:
            start = raw.find("{")
            end = raw.rfind("}")
            if start >= 0 and end > start:
                return json.loads(raw[start:end + 1])
        except Exception:
            pass
        logger.warning(f"[LlmEnhancer] JSON parse failed: {raw[:120]}")
        return None


def is_module_enabled(module: str) -> bool:
    """供 hook 点快速判断是否需要发起 enhance task."""
    enabled_map = {
        "traffic": settings.llm_traffic_enabled,
        "phishing": settings.llm_phishing_enabled,
        "data_security": settings.llm_data_security_enabled,
        "encrypted_traffic": settings.llm_encrypted_traffic_enabled,
        "edr": settings.llm_edr_enabled,
        "intel": settings.llm_intel_enabled,
        "sandbox": settings.llm_sandbox_enabled,
    }
    return enabled_map.get(module, False)


def safe_dispatch(coro: Awaitable, *, log_label: str = "") -> None:
    """
    安全派发后台 LLM 增强任务.调用方用它替代裸 asyncio.create_task:
      - 自动捕获并吃掉所有异常 (主路径不感知)
      - 失败时记录 warning
        - log_label 用于追溯是哪个模块的派发

    必须在已有 event loop 的上下文调用 (FastAPI 请求/消费者循环内)
    """
    try:
        task = asyncio.create_task(coro)
        label = log_label or "llm_enhance"

        def _on_done(t: asyncio.Task) -> None:
            if t.cancelled():
                return
            exc = t.exception()
            if exc:
                logger.warning(f"[LlmEnhancer:{label}] background task failed: {exc}")

        task.add_done_callback(_on_done)
    except RuntimeError:
        # 无 event loop (单元测试等场景) → 同步跳过
        logger.debug(f"[LlmEnhancer:{log_label}] no event loop, skipping dispatch")


# ── 模块级便捷实例 (供各模块直接 import 使用) ──

async def enhance_traffic(
    cache_key: str, prompt_messages: list[dict],
    budget_cost_jpy: float = 0.05,
) -> Optional[dict]:
    """流量大模型专用入口."""
    return await enhance(
        module="traffic", cache_key=cache_key,
        prompt_messages=prompt_messages, budget_cost_jpy=budget_cost_jpy,
    )


async def enhance_phishing(
    cache_key: str, prompt_messages: list[dict],
    budget_cost_jpy: float = 0.1,
) -> Optional[dict]:
    """钓鱼大模型专用入口."""
    return await enhance(
        module="phishing", cache_key=cache_key,
        prompt_messages=prompt_messages, budget_cost_jpy=budget_cost_jpy,
    )


async def enhance_data_security(
    cache_key: str, prompt_messages: list[dict],
    budget_cost_jpy: float = 0.1,
) -> Optional[dict]:
    """数据安全大模型专用入口."""
    return await enhance(
        module="data_security", cache_key=cache_key,
        prompt_messages=prompt_messages, budget_cost_jpy=budget_cost_jpy,
    )


# ── NDR 扩展模块入口 ──

async def enhance_encrypted_traffic(
    cache_key: str, prompt_messages: list[dict],
    budget_cost_jpy: float = 0.05,
) -> Optional[dict]:
    """加密流量 LLM 语义判定入口."""
    return await enhance(
        module="encrypted_traffic", cache_key=cache_key,
        prompt_messages=prompt_messages, budget_cost_jpy=budget_cost_jpy,
    )


async def enhance_edr(
    cache_key: str, prompt_messages: list[dict],
    budget_cost_jpy: float = 0.05,
) -> Optional[dict]:
    """EDR 跨源关联 LLM 叙事入口."""
    return await enhance(
        module="edr", cache_key=cache_key,
        prompt_messages=prompt_messages, budget_cost_jpy=budget_cost_jpy,
    )


async def enhance_intel(
    cache_key: str, prompt_messages: list[dict],
    budget_cost_jpy: float = 0.03,
) -> Optional[dict]:
    """威胁情报 LLM 上下文摘要入口."""
    return await enhance(
        module="intel", cache_key=cache_key,
        prompt_messages=prompt_messages, budget_cost_jpy=budget_cost_jpy,
    )


async def enhance_sandbox(
    cache_key: str, prompt_messages: list[dict],
    budget_cost_jpy: float = 0.05,
) -> Optional[dict]:
    """沙箱行为 LLM 解读入口."""
    return await enhance(
        module="sandbox", cache_key=cache_key,
        prompt_messages=prompt_messages, budget_cost_jpy=budget_cost_jpy,
    )