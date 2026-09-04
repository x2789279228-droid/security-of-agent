"""
质量评估与轨迹存储层 — 异步 SQLAlchemy 实现
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, func, case as sa_case, desc

from models import AgentTrace, EvalRun, EvalScore, async_session

logger = logging.getLogger(__name__)


# ── 质量评估 ──────────────────────────────────────────────

async def save_evaluation_run(
    *,
    run_type: str,
    scores: list[dict],
    subject_id: str = "",
    evaluator: str = "heuristic",
    query: str = "",
    answer: str = "",
    ground_truth: str = "",
    contexts: Optional[list] = None,
    input_payload: Optional[dict] = None,
    output_payload: Optional[dict] = None,
    prompt_version: str = "",
    retrieval_strategy: str = "",
    status: str = "completed",
    error: str = "",
) -> dict:
    """保存一次评估运行及其指标得分"""
    run_id = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)
    try:
        async with async_session() as session:
            session.add(EvalRun(
                id=run_id,
                run_type=run_type,
                subject_id=subject_id,
                evaluator=evaluator,
                status=status,
                prompt_version=prompt_version,
                retrieval_strategy=retrieval_strategy,
                query=query,
                answer=answer,
                ground_truth=ground_truth,
                contexts=contexts or [],
                input_payload=input_payload or {},
                output_payload=output_payload or {},
                error=error,
                created_at=now,
            ))
            for score in scores:
                session.add(EvalScore(
                    run_id=run_id,
                    metric=score["metric"],
                    score=float(score.get("score", 0.0)),
                    threshold=float(score.get("threshold", 0.5)),
                    passed=bool(score.get("passed", False)),
                    reason=str(score.get("reason", "")),
                ))
            await session.commit()
    except Exception as e:
        logger.error(f"save_evaluation_run failed: {e}")
        return {"id": run_id, "run_type": run_type, "scores": scores, "saved": False}
    return {"id": run_id, "run_type": run_type, "scores": scores, "saved": True}


async def list_evaluation_runs(run_type: str = "", limit: int = 50) -> list[dict]:
    """列出最近评估运行（含指标得分）"""
    try:
        async with async_session() as session:
            stmt = select(EvalRun).order_by(desc(EvalRun.created_at)).limit(max(1, min(limit, 200)))
            rows = (await session.execute(stmt)).scalars().all()
            runs = []
            for r in rows:
                score_stmt = select(EvalScore).where(EvalScore.run_id == r.id)
                score_rows = (await session.execute(score_stmt)).scalars().all()
                runs.append(_run_to_dict(r, score_rows))
            return runs
    except Exception as e:
        logger.error(f"list_evaluation_runs failed: {e}")
        return []


async def get_evaluation_run(run_id: str) -> Optional[dict]:
    try:
        async with async_session() as session:
            run = await session.get(EvalRun, run_id)
            if run is None:
                return None
            score_rows = (await session.execute(
                select(EvalScore).where(EvalScore.run_id == run_id)
            )).scalars().all()
            return _run_to_dict(run, score_rows)
    except Exception as e:
        logger.error(f"get_evaluation_run failed: {e}")
        return None


async def evaluation_report(run_type: str = "", limit: int = 200) -> dict:
    """聚合报告：各指标均值 / 通过率 / 最近运行"""
    try:
        async with async_session() as session:
            run_ids_stmt = select(EvalRun.id)
            if run_type:
                run_ids_stmt = run_ids_stmt.where(EvalRun.run_type == run_type)
            run_ids_stmt = run_ids_stmt.order_by(desc(EvalRun.created_at)).limit(limit)
            run_ids = [r for r in (await session.execute(run_ids_stmt)).scalars().all()]
            if not run_ids:
                return {
                    "run_count": 0, "metric_averages": {}, "pass_rates": {},
                    "recent_runs": [],
                }
            agg_stmt = (
                select(
                    EvalScore.metric,
                    func.avg(EvalScore.score),
                    func.avg(sa_case((EvalScore.passed.is_(True), 1.0), else_=0.0)),
                )
                .where(EvalScore.run_id.in_(run_ids))
                .group_by(EvalScore.metric)
            )
            rows = (await session.execute(agg_stmt)).all()
            recent = await list_evaluation_runs(run_type=run_type, limit=10)
            return {
                "run_count": len(run_ids),
                "metric_averages": {m: round(float(avg or 0), 4) for m, avg, _ in rows},
                "pass_rates": {m: round(float(rate or 0), 4) for m, _, rate in rows},
                "recent_runs": recent,
            }
    except Exception as e:
        logger.error(f"evaluation_report failed: {e}")
        return {"run_count": 0, "metric_averages": {}, "pass_rates": {}, "recent_runs": []}


def _run_to_dict(run: EvalRun, score_rows: list[EvalScore]) -> dict:
    return {
        "id": run.id,
        "run_type": run.run_type,
        "subject_id": run.subject_id,
        "evaluator": run.evaluator,
        "status": run.status,
        "prompt_version": run.prompt_version,
        "retrieval_strategy": run.retrieval_strategy,
        "query": run.query,
        "answer": run.answer,
        "ground_truth": run.ground_truth,
        "contexts": run.contexts or [],
        "input_payload": run.input_payload or {},
        "output_payload": run.output_payload or {},
        "error": run.error,
        "created_at": run.created_at.isoformat() if run.created_at else "",
        "scores": [
            {
                "metric": s.metric,
                "score": round(s.score, 4),
                "threshold": s.threshold,
                "passed": s.passed,
                "reason": s.reason,
            }
            for s in score_rows
        ],
    }


# ── Agent 轨迹 ────────────────────────────────────────────

async def get_traces(
    caller: str = "",
    operation: str = "",
    status: str = "",
    event_id: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """查询 LLM 轨迹（分页 + 过滤）"""
    try:
        async with async_session() as session:
            conditions = []
            if caller:
                conditions.append(AgentTrace.caller == caller)
            if operation:
                conditions.append(AgentTrace.operation == operation)
            if status:
                conditions.append(AgentTrace.status == status)
            if event_id:
                conditions.append(AgentTrace.event_id == event_id)

            total_stmt = select(func.count(AgentTrace.id))
            if conditions:
                total_stmt = total_stmt.where(*conditions)
            total = (await session.execute(total_stmt)).scalar() or 0

            stmt = select(AgentTrace).order_by(desc(AgentTrace.created_at)).limit(
                max(1, min(limit, 500))
            ).offset(max(0, offset))
            if conditions:
                stmt = stmt.where(*conditions)
            rows = (await session.execute(stmt)).scalars().all()
            return {
                "traces": [
                    {
                        "id": t.id,
                        "caller": t.caller,
                        "operation": t.operation,
                        "model": t.model,
                        "event_id": t.event_id,
                        "session_id": t.session_id,
                        "prompt_tokens": t.prompt_tokens,
                        "completion_tokens": t.completion_tokens,
                        "total_tokens": t.total_tokens,
                        "latency_ms": t.latency_ms,
                        "cache_hit": t.cache_hit,
                        "status": t.status,
                        "error_type": t.error_type,
                        "retry_count": t.retry_count,
                        "created_at": t.created_at.isoformat() if t.created_at else "",
                    }
                    for t in rows
                ],
                "total": total,
                "limit": limit,
                "offset": offset,
            }
    except Exception as e:
        logger.error(f"get_traces failed: {e}")
        return {"traces": [], "total": 0, "limit": limit, "offset": offset}


async def get_cache_channel_stats() -> dict:
    """缓存命中率按通道聚合（全局视图，不受 caller 过滤影响）。

    通道划分：embedding = caller=="embedding"；llm = 其余全部真实 LLM 调用。
    embedding 行由 EmbeddingClient.embed() 的 emit_trace 写入。
    """
    try:
        async with async_session() as session:
            async def _count(*conds) -> int:
                return (await session.execute(
                    select(func.count(AgentTrace.id)).where(*conds)
                )).scalar() or 0

            llm_total = await _count(AgentTrace.caller != "embedding")
            llm_hits = await _count(
                AgentTrace.caller != "embedding", AgentTrace.cache_hit == True,
            )
            emb_total = await _count(AgentTrace.caller == "embedding")
            emb_hits = await _count(
                AgentTrace.caller == "embedding", AgentTrace.cache_hit == True,
            )

        def _rate(h: int, t: int) -> float:
            return round(float(h) / t, 4) if t else 0.0

        return {
            "llm": {
                "calls": int(llm_total), "hits": int(llm_hits),
                "rate": _rate(llm_hits, llm_total),
            },
            "embedding": {
                "calls": int(emb_total), "hits": int(emb_hits),
                "rate": _rate(emb_hits, emb_total),
            },
        }
    except Exception as e:
        logger.error(f"get_cache_channel_stats failed: {e}")
        return {
            "llm": {"calls": 0, "hits": 0, "rate": 0.0},
            "embedding": {"calls": 0, "hits": 0, "rate": 0.0},
        }


async def get_trace_stats(caller: str = "") -> dict:
    """轨迹聚合统计"""
    try:
        async with async_session() as session:
            conditions = []
            if caller:
                conditions.append(AgentTrace.caller == caller)

            base = select(AgentTrace)
            if conditions:
                base = base.where(*conditions)

            total = (await session.execute(
                select(func.count(AgentTrace.id)).where(*conditions) if conditions
                else select(func.count(AgentTrace.id))
            )).scalar() or 0
            total_tokens = (await session.execute(
                select(func.coalesce(func.sum(AgentTrace.total_tokens), 0)).where(*conditions) if conditions
                else select(func.coalesce(func.sum(AgentTrace.total_tokens), 0))
            )).scalar() or 0
            total_prompt = (await session.execute(
                select(func.coalesce(func.sum(AgentTrace.prompt_tokens), 0)).where(*conditions) if conditions
                else select(func.coalesce(func.sum(AgentTrace.prompt_tokens), 0))
            )).scalar() or 0
            total_completion = (await session.execute(
                select(func.coalesce(func.sum(AgentTrace.completion_tokens), 0)).where(*conditions) if conditions
                else select(func.coalesce(func.sum(AgentTrace.completion_tokens), 0))
            )).scalar() or 0
            avg_latency = (await session.execute(
                select(func.coalesce(func.avg(AgentTrace.latency_ms), 0)).where(*conditions) if conditions
                else select(func.coalesce(func.avg(AgentTrace.latency_ms), 0))
            )).scalar() or 0.0
            errors = (await session.execute(
                select(func.count(AgentTrace.id)).where(
                    *(conditions + [AgentTrace.status == "error"])
                ) if conditions else select(func.count(AgentTrace.id)).where(AgentTrace.status == "error")
            )).scalar() or 0

            degraded = (await session.execute(
                select(func.count(AgentTrace.id)).where(
                    *(conditions + [AgentTrace.status == "degraded"])
                ) if conditions else select(func.count(AgentTrace.id)).where(AgentTrace.status == "degraded")
            )).scalar() or 0

            cache_hits = (await session.execute(
                select(func.count(AgentTrace.id)).where(
                    *(conditions + [AgentTrace.cache_hit == True])
                ) if conditions else select(func.count(AgentTrace.id)).where(AgentTrace.cache_hit == True)
            )).scalar() or 0

            by_operation = {}
            op_rows = (await session.execute(
                select(AgentTrace.operation, func.count(AgentTrace.id)).where(*conditions)
                .group_by(AgentTrace.operation) if conditions else
                select(AgentTrace.operation, func.count(AgentTrace.id))
                .group_by(AgentTrace.operation)
            )).all()
            for op, cnt in op_rows:
                by_operation[op] = int(cnt or 0)

            by_error_type = {}
            et_rows = (await session.execute(
                select(AgentTrace.error_type, func.count(AgentTrace.id))
                .where(*(conditions + [AgentTrace.status == "error"]))
                .group_by(AgentTrace.error_type)
            )).all()
            for et, cnt in et_rows:
                key = et or "unknown"
                by_error_type[key] = int(cnt or 0)

            by_degraded_type = {}
            dt_rows = (await session.execute(
                select(AgentTrace.error_type, func.count(AgentTrace.id))
                .where(*(conditions + [AgentTrace.status == "degraded"]))
                .group_by(AgentTrace.error_type)
            )).all()
            for et, cnt in dt_rows:
                key = et or "unknown"
                by_degraded_type[key] = int(cnt or 0)

            return {
                "total_calls": int(total),
                "total_tokens": int(total_tokens),
                "total_prompt_tokens": int(total_prompt),
                "total_completion_tokens": int(total_completion),
                "avg_latency_ms": round(float(avg_latency), 2),
                "error_rate": round(float(errors) / total, 4) if total else 0.0,
                "error_count": int(errors),
                "degraded_count": int(degraded),
                "degraded_rate": round(float(degraded) / total, 4) if total else 0.0,
                "cache_hit_count": int(cache_hits),
                "cache_hit_rate": round(float(cache_hits) / total, 4) if total else 0.0,
                "cache_by_channel": await get_cache_channel_stats(),
                "by_operation": by_operation,
                "by_error_type": by_error_type,
                "by_degraded_type": by_degraded_type,
            }
    except Exception as e:
        logger.error(f"get_trace_stats failed: {e}")
        return {
            "total_calls": 0, "total_tokens": 0, "total_prompt_tokens": 0,
            "total_completion_tokens": 0, "avg_latency_ms": 0.0,
            "error_rate": 0.0, "error_count": 0, "by_operation": {},
        }


# ── Token 成本聚合 (运营中心成本面板) ─────────────────────────

async def get_event_token_aggregation(
    days: int = 30,
    min_tokens: int = 0,
    limit: int = 50,
    offset: int = 0,
    event_type: str = "",
    severity: str = "",
) -> dict:
    """按事件聚合 token 消耗 (llm_traces 分组 + security_events 关联)

    返回分页列表 + 汇总: 每事件调用次数 / 输入输出 / 总 tokens /
    平均延迟 / 错误数 / 事件元信息。按总 tokens 降序。
    """
    try:
        from datetime import datetime, timezone, timedelta

        from models import SecurityEvent

        async with async_session() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
            conditions = [
                AgentTrace.event_id > 0,
                AgentTrace.created_at >= cutoff,
            ]
            if event_type:
                conditions.append(SecurityEvent.event_type == event_type)
            if severity:
                conditions.append(SecurityEvent.severity == severity)

            sum_prompt = func.coalesce(func.sum(AgentTrace.prompt_tokens), 0)
            sum_completion = func.coalesce(func.sum(AgentTrace.completion_tokens), 0)
            sum_errors = func.coalesce(
                func.sum(sa_case((AgentTrace.status == "error", 1), else_=0)), 0
            )
            # total_tokens 列部分行缺失(为0), 用 prompt+completion 兜底保证总量/占比/费用一致
            sum_total = sa_case(
                (func.sum(AgentTrace.total_tokens) > 0, func.sum(AgentTrace.total_tokens)),
                else_=sum_prompt + sum_completion,
            )

            # 事件总数 (分组行数)
            grouped = (
                select(AgentTrace.event_id)
                .select_from(AgentTrace)
                .join(SecurityEvent, SecurityEvent.id == AgentTrace.event_id, isouter=True)
                .where(*conditions)
                .group_by(AgentTrace.event_id)
            )
            if min_tokens > 0:
                grouped = grouped.having(sum_total >= min_tokens)
            total_events = (await session.execute(
                select(func.count()).select_from(grouped.subquery())
            )).scalar() or 0

            # 全量汇总 (所有命中调用的 token 总和)
            grand_stmt = select(
                func.count(AgentTrace.id),
                sum_prompt,
                sum_completion,
                sum_total,
                sum_errors,
            ).select_from(
                AgentTrace.__table__.join(
                    SecurityEvent.__table__,
                    SecurityEvent.id == AgentTrace.event_id,
                    isouter=True,
                )
            ).where(*conditions)
            grand_calls, grand_prompt, grand_completion, grand_total, grand_errors = (
                (await session.execute(grand_stmt)).one()
            )

            stmt = (
                select(
                    AgentTrace.event_id,
                    func.count(AgentTrace.id).label("calls"),
                    sum_prompt.label("prompt_tokens"),
                    sum_completion.label("completion_tokens"),
                    sum_total.label("total_tokens"),
                    func.coalesce(func.avg(AgentTrace.latency_ms), 0.0).label("avg_latency_ms"),
                    sum_errors.label("errors"),
                    func.max(AgentTrace.created_at).label("last_used_at"),
                    SecurityEvent.event_type,
                    SecurityEvent.severity,
                    SecurityEvent.src_ip,
                    SecurityEvent.message,
                    SecurityEvent.analyzed,
                    SecurityEvent.created_at.label("event_created_at"),
                )
                .select_from(AgentTrace)
                .join(SecurityEvent, SecurityEvent.id == AgentTrace.event_id, isouter=True)
                .where(*conditions)
                .group_by(AgentTrace.event_id, SecurityEvent.id)
                .order_by(desc(sum_total))
                .limit(max(1, min(limit, 500)))
                .offset(max(0, offset))
            )
            if min_tokens > 0:
                stmt = stmt.having(sum_total >= min_tokens)
            rows = (await session.execute(stmt)).all()

            return {
                "events": [
                    {
                        "event_id": r.event_id,
                        "calls": int(r.calls),
                        "prompt_tokens": int(r.prompt_tokens),
                        "completion_tokens": int(r.completion_tokens),
                        "total_tokens": int(r.total_tokens),
                        "avg_latency_ms": round(float(r.avg_latency_ms or 0.0), 2),
                        "errors": int(r.errors),
                        "last_used_at": r.last_used_at.isoformat() if r.last_used_at else "",
                        "event_type": r.event_type or "",
                        "severity": r.severity or "",
                        "src_ip": r.src_ip or "",
                        "message": (r.message or "")[:200],
                        "analyzed": bool(r.analyzed),
                        "event_created_at": r.event_created_at.isoformat() if r.event_created_at else "",
                    }
                    for r in rows
                ],
                "total_events": int(total_events),
                "grand": {
                    "calls": int(grand_calls),
                    "prompt_tokens": int(grand_prompt),
                    "completion_tokens": int(grand_completion),
                    "total_tokens": int(grand_total),
                    "errors": int(grand_errors),
                },
                "limit": limit,
                "offset": offset,
            }
    except Exception as e:
        logger.error(f"get_event_token_aggregation failed: {e}")
        return {
            "events": [], "total_events": 0, "grand": {
                "calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                "total_tokens": 0, "errors": 0,
            }, "limit": limit, "offset": offset,
        }


async def get_daily_token_usage(days: int = 14) -> list[dict]:
    """近 N 天每日 token 用量 / 调用数趋势 (缺失日期补 0), 含输入输出拆分"""
    try:
        from datetime import datetime, timezone, timedelta

        async with async_session() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
            day_col = func.date(AgentTrace.created_at)
            sum_prompt = func.coalesce(func.sum(AgentTrace.prompt_tokens), 0)
            sum_completion = func.coalesce(func.sum(AgentTrace.completion_tokens), 0)
            total_expr = sa_case(
                (func.sum(AgentTrace.total_tokens) > 0, func.sum(AgentTrace.total_tokens)),
                else_=sum_prompt + sum_completion,
            )
            rows = (await session.execute(
                select(
                    day_col.label("day"),
                    total_expr.label("total_tokens"),
                    sum_prompt.label("prompt_tokens"),
                    sum_completion.label("completion_tokens"),
                    func.count(AgentTrace.id).label("calls"),
                )
                .where(AgentTrace.created_at >= cutoff)
                .group_by(day_col)
                .order_by(day_col)
            )).all()
            by_day = {
                str(r.day): {
                    "day": str(r.day), "total_tokens": int(r.total_tokens),
                    "prompt_tokens": int(r.prompt_tokens),
                    "completion_tokens": int(r.completion_tokens),
                    "calls": int(r.calls),
                }
                for r in rows
            }
            out = []
            today = datetime.now(timezone.utc).date()
            for i in range(max(1, days) - 1, -1, -1):
                d = (today - timedelta(days=i)).isoformat()
                out.append(by_day.get(d, {
                    "day": d, "total_tokens": 0,
                    "prompt_tokens": 0, "completion_tokens": 0, "calls": 0,
                }))
            return out
    except Exception as e:
        logger.error(f"get_daily_token_usage failed: {e}")
        return []


async def get_cost_by_caller(days: int = 14) -> list[dict]:
    """按调用来源(caller)聚合 tokens 与调用数, 供“钱花在哪个模块”分账展示。

    返回按 total_tokens 降序的 [{caller, calls, prompt_tokens, completion_tokens,
    total_tokens, cost_yuan}], cost_yuan 用 cost_tracker 单价估算(¥, 见 estimate_cost_yuan)。
    """
    try:
        from datetime import datetime, timezone, timedelta
        from summary_compression import cost_tracker

        async with async_session() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
            sum_prompt = func.coalesce(func.sum(AgentTrace.prompt_tokens), 0)
            sum_completion = func.coalesce(func.sum(AgentTrace.completion_tokens), 0)
            # total_tokens 列部分行缺失(为0), 用 prompt+completion 兜底保证总量/占比准确
            total_expr = sa_case(
                (func.sum(AgentTrace.total_tokens) > 0, func.sum(AgentTrace.total_tokens)),
                else_=sum_prompt + sum_completion,
            )
            rows = (await session.execute(
                select(
                    AgentTrace.caller,
                    func.count(AgentTrace.id).label("calls"),
                    sum_prompt.label("prompt_tokens"),
                    sum_completion.label("completion_tokens"),
                    total_expr.label("total_tokens"),
                )
                .where(AgentTrace.created_at >= cutoff)
                .group_by(AgentTrace.caller)
                .order_by(total_expr.desc())
            )).all()
            out = []
            for r in rows:
                prompt = int(r.prompt_tokens)
                completion = int(r.completion_tokens)
                out.append({
                    "caller": r.caller or "unknown",
                    "calls": int(r.calls),
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                    "total_tokens": int(r.total_tokens),
                    "cost_yuan": round(cost_tracker.estimate_cost_yuan(prompt, completion), 4),
                })
            return out
    except Exception as e:
        logger.error(f"get_cost_by_caller failed: {e}")
        return []
