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

            by_operation = {}
            op_rows = (await session.execute(
                select(AgentTrace.operation, func.count(AgentTrace.id)).where(*conditions)
                .group_by(AgentTrace.operation) if conditions else
                select(AgentTrace.operation, func.count(AgentTrace.id))
                .group_by(AgentTrace.operation)
            )).all()
            for op, cnt in op_rows:
                by_operation[op] = int(cnt or 0)

            return {
                "total_calls": int(total),
                "total_tokens": int(total_tokens),
                "total_prompt_tokens": int(total_prompt),
                "total_completion_tokens": int(total_completion),
                "avg_latency_ms": round(float(avg_latency), 2),
                "error_rate": round(float(errors) / total, 4) if total else 0.0,
                "error_count": int(errors),
                "by_operation": by_operation,
            }
    except Exception as e:
        logger.error(f"get_trace_stats failed: {e}")
        return {
            "total_calls": 0, "total_tokens": 0, "total_prompt_tokens": 0,
            "total_completion_tokens": 0, "avg_latency_ms": 0.0,
            "error_rate": 0.0, "error_count": 0, "by_operation": {},
        }
