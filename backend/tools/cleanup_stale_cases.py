"""
清理早期历史案例残留(安全案例/关联工单) — 幂等运维工具

背景: 开发/演示阶段 security_cases 混有跨多天的测试残留(CASE-* 覆盖数周),
     导致运营中心"案例超时"一片红。本脚本按创建时间清理早期 case 及其关联 work_order。

用法:
    python -m tools.cleanup_stale_cases --keep-days 7
    python -m tools.cleanup_stale_cases --before 2026-08-23
    python -m tools.cleanup_stale_cases --dry-run            # 只打印不清除

说明:
  - 幂等: 可任意重复执行; 只删除 created_at < cutoff 的 case 及其 work_order。
  - 保留近期(默认 7 天)以不误删有效演示数据。
  - 需先注 SHARED_MEMORY_DATABASE_URL(默认 postgres://localhost:5432/shared_memory)。
"""
import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

# 保证能 import backend 模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 测试/本地用 sqlite 时可去掉 PG 专属 pool 参数
import sqlalchemy.ext.asyncio as _sa_async
_orig_create_async_engine = _sa_async.create_async_engine


def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)


_sa_async.create_async_engine = _patched_create_async_engine

import models  # noqa: F401  (确保 engine 使用 patched 版本)


async def run(before: datetime, dry_run: bool, close_only: bool = False) -> dict:
    from sqlalchemy import select
    from models import async_session, SecurityCase, WorkOrder

    deleted_cases = 0
    deleted_orders = 0
    closed_cases = 0
    cancelled_orders = 0
    matched_cases = 0
    now = datetime.now(timezone.utc)
    async with async_session() as session:
        cases = (await session.execute(
            select(SecurityCase).where(SecurityCase.created_at.is_not(None),
                                       SecurityCase.created_at < before)
        )).scalars().all()
        matched_cases = len(cases)
        if dry_run:
            return {"dry_run": True, "matched_cases": matched_cases,
                    "earliest": min((c.created_at for c in cases), default=None),
                    "latest": max((c.created_at for c in cases), default=None),
                    "deleted_cases": 0, "deleted_orders": 0,
                    "closed_cases": 0, "cancelled_orders": 0}
        for case in cases:
            orders = (await session.execute(
                select(WorkOrder).where(WorkOrder.case_id == case.id)
            )).scalars().all()
            if close_only:
                if case.status not in ("closed", "false_positive"):
                    case.status = "closed"
                    case.closed_at = now
                    case.updated_at = now
                    closed_cases += 1
                for o in orders:
                    if o.status not in ("completed", "cancelled"):
                        o.status = "cancelled"
                        o.updated_at = now
                        cancelled_orders += 1
            else:
                deleted_orders += len(orders)
                for o in orders:
                    await session.delete(o)
                await session.delete(case)
                deleted_cases += 1
        await session.commit()
    return {"dry_run": False, "matched_cases": matched_cases,
            "deleted_cases": deleted_cases, "deleted_orders": deleted_orders,
            "closed_cases": closed_cases, "cancelled_orders": cancelled_orders}


def main():
    parser = argparse.ArgumentParser(description="清理早期 security_cases 残留")
    parser.add_argument("--before", type=str, default="",
                        help="删除 created_at 早于该日期(YYYY-MM-DD)的案例")
    parser.add_argument("--keep-days", type=int, default=7,
                        help="保留最近 N 天的案例(默认 7)")
    parser.add_argument("--dry-run", action="store_true", help="只统计不删除")
    parser.add_argument(
        "--close", action="store_true",
        help="不删除，将匹配案例置为 closed 并取消未结工单",
    )
    args = parser.parse_args()

    if args.before:
        cutoff = datetime.fromisoformat(args.before).replace(tzinfo=timezone.utc)
    else:
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.keep_days)

    result = asyncio.run(run(cutoff, args.dry_run, close_only=args.close))
    mode = "dry-run" if result["dry_run"] else ("已关闭" if args.close else "已删除")
    print(f"[cleanup] 截止 {cutoff.isoformat()} | 匹配案例 {result['matched_cases']} | "
          f"删除案例 {result['deleted_cases']} | 删除工单 {result['deleted_orders']} | "
          f"关闭案例 {result.get('closed_cases', 0)} | 取消工单 {result.get('cancelled_orders', 0)} | {mode}")


if __name__ == "__main__":
    main()
