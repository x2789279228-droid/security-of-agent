"""
动作幂等守卫 — 防止重复执行

idempotency_key = SHA256(incident_id + tool_name + target + canonical_json(parameters) + plan_version)
数据库唯一约束防止并发竞争。

行为:
  - 首次请求: 创建记录并执行
  - 相同键 SUCCEEDED: 直接返回原结果
  - 相同键 EXECUTING: 返回处理中
  - FAILED_RETRYABLE: 按限定重试策略执行
  - FAILED_FINAL: 禁止自动重试
  - ROLLED_BACK: 必须生成新 plan_version 才能重新执行
"""
import uuid
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, and_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ActionLedger
from .state_machine import ActionState

logger = logging.getLogger(__name__)

MAX_RETRY = 3


class IdempotencyError(Exception):
    pass


class IdempotencyGuard:
    """动作幂等守卫"""

    def make_key(
        self,
        incident_id: str,
        tool_name: str,
        target: str,
        parameters: dict,
        plan_version: str = "v1",
    ) -> str:
        """生成 idempotency_key"""
        canonical = json.dumps(parameters, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        raw = f"{incident_id}|{tool_name}|{target}|{canonical}|{plan_version}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def make_rollback_key(self, action_id: str, plan_version: str = "v1") -> str:
        """生成回滚的独立 idempotency_key"""
        raw = f"rollback|{action_id}|{plan_version}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def make_action_id(self) -> str:
        return f"ACT-{uuid.uuid4().hex[:12].upper()}"

    def make_parameter_hash(self, parameters: dict) -> str:
        canonical = json.dumps(parameters, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    async def acquire_or_get(
        self,
        session: AsyncSession,
        incident_id: str,
        tool_name: str,
        target: str,
        parameters: dict,
        plan_version: str = "v1",
        grant_id: str = "",
        trace_id: str = "",
    ) -> dict:
        """获取或创建幂等记录

        返回:
          - {"action": "execute", "action_id": ..., "idempotency_key": ...} — 首次，应执行
          - {"action": "return", "record": ...} — 已有记录，返回原结果
          - {"action": "retry", "record": ...} — 可重试
          - {"action": "blocked", "reason": ...} — 禁止执行
        """
        idem_key = self.make_key(incident_id, tool_name, target, parameters, plan_version)
        action_id = self.make_action_id()
        param_hash = self.make_parameter_hash(parameters)

        # 查询已有记录
        existing = await session.execute(
            select(ActionLedger).where(ActionLedger.idempotency_key == idem_key)
        )
        record = existing.scalar_one_or_none()

        if record:
            return self._handle_existing(record)

        # 首次请求 — 创建记录（利用唯一约束防并发）
        new_record = ActionLedger(
            action_id=action_id,
            idempotency_key=idem_key,
            incident_id=incident_id,
            plan_version=plan_version,
            tool_name=tool_name,
            target=target,
            normalized_parameters=parameters,
            parameter_hash=param_hash,
            status=ActionState.PROPOSED.value,
            request_count=1,
            grant_id=grant_id or None,
            trace_id=trace_id,
        )
        session.add(new_record)
        try:
            await session.flush()
        except IntegrityError:
            # 并发竞争 — 另一个 worker 已创建
            await session.rollback()
            existing = await session.execute(
                select(ActionLedger).where(ActionLedger.idempotency_key == idem_key)
            )
            record = existing.scalar_one_or_none()
            if record:
                return self._handle_existing(record)
            raise IdempotencyError("并发竞争但无法获取记录")

        return {
            "action": "execute",
            "action_id": action_id,
            "idempotency_key": idem_key,
            "record": new_record,
        }

    def _handle_existing(self, record: ActionLedger) -> dict:
        """处理已有记录"""
        status = record.status

        if status == ActionState.SUCCEEDED.value:
            return {"action": "return", "record": record, "reason": "已成功执行"}

        if status == ActionState.EXECUTING.value:
            return {"action": "blocked", "reason": "正在执行中", "record": record}

        if status == ActionState.ROLLING_BACK.value:
            return {"action": "blocked", "reason": "正在回滚中", "record": record}

        if status == ActionState.ROLLED_BACK.value:
            return {"action": "blocked", "reason": "已回滚，需新 plan_version 才能重新执行", "record": record}

        if status == ActionState.FAILED_FINAL.value:
            return {"action": "blocked", "reason": "最终失败，禁止自动重试", "record": record}

        if status == ActionState.BLOCKED.value:
            return {"action": "blocked", "reason": f"已阻止: {record.error}", "record": record}

        if status == ActionState.FAILED_RETRYABLE.value:
            if record.request_count >= MAX_RETRY:
                record.status = ActionState.FAILED_FINAL.value
                return {"action": "blocked", "reason": "重试次数已耗尽", "record": record}
            record.request_count += 1
            return {"action": "retry", "record": record, "reason": f"重试 #{record.request_count}"}

        if status == ActionState.PROPOSED.value:
            # 已有处理中的请求 — 不重复执行（防止并发竞争）
            record.request_count += 1
            return {"action": "blocked", "reason": "已有处理中的请求", "record": record}

        return {"action": "blocked", "reason": f"未知状态: {status}", "record": record}

    async def mark_executing(self, session: AsyncSession, action_id: str):
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(
                status=ActionState.EXECUTING.value,
                execution_started_at=datetime.now(timezone.utc),
            )
        )

    async def mark_succeeded(self, session: AsyncSession, action_id: str, result: dict, verification: dict = None):
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(
                status=ActionState.SUCCEEDED.value,
                execution_finished_at=datetime.now(timezone.utc),
                result=result,
                verification_result=verification or {},
                verification_passed=verification.get("verified", False) if verification else None,
            )
        )

    async def mark_failed(self, session: AsyncSession, action_id: str, error: str, retryable: bool = True):
        status = ActionState.FAILED_RETRYABLE.value if retryable else ActionState.FAILED_FINAL.value
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(
                status=status,
                execution_finished_at=datetime.now(timezone.utc),
                error=error,
            )
        )

    async def mark_blocked(self, session: AsyncSession, action_id: str, reason: str):
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(status=ActionState.BLOCKED.value, error=reason)
        )

    async def mark_rollback_required(self, session: AsyncSession, action_id: str, reason: str):
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(status=ActionState.ROLLBACK_REQUIRED.value, error=reason)
        )

    async def acquire_rollback(
        self,
        session: AsyncSession,
        original_action_id: str,
        plan_version: str = "v1",
    ) -> dict:
        """获取回滚的幂等锁

        回滚幂等逻辑:
          1. 查询原始动作的 ActionLedger 记录 (按 action_id)
          2. 若已有 rollback_result — 幂等返回
          3. 若状态为 ROLLING_BACK — 阻塞 (正在回滚)
          4. 否则 — 原子性占位 rollback_idempotency_key 并返回 execute

        并发安全: 使用条件 UPDATE (WHERE rollback_idempotency_key IS NULL)
        确保只有一个 worker 成功占位。
        """
        rollback_key = self.make_rollback_key(original_action_id, plan_version)

        # 查询原始动作记录
        result = await session.execute(
            select(ActionLedger).where(ActionLedger.action_id == original_action_id)
        )
        record = result.scalar_one_or_none()

        if record is None:
            return {
                "action": "blocked",
                "reason": "原始动作不存在",
                "rollback_idempotency_key": rollback_key,
            }

        # 已有回滚结果 — 幂等返回
        if record.rollback_result:
            return {
                "action": "return",
                "result": record.rollback_result,
                "record": record,
            }

        # 正在回滚中 — 阻塞
        if record.status == ActionState.ROLLING_BACK.value:
            return {
                "action": "blocked",
                "reason": "正在回滚中",
                "record": record,
            }

        # 原子性占位 — 条件 UPDATE 防并发竞争
        # 只在 rollback_idempotency_key 为 NULL 时设置
        update_result = await session.execute(
            update(ActionLedger)
            .where(
                and_(
                    ActionLedger.action_id == original_action_id,
                    ActionLedger.rollback_idempotency_key.is_(None),
                )
            )
            .values(rollback_idempotency_key=rollback_key)
        )

        # 若 rowcount == 0, 说明另一个 worker 已占位 — 重新查询返回已有结果
        if update_result.rowcount == 0:
            await session.refresh(record)
            if record.rollback_result:
                return {
                    "action": "return",
                    "result": record.rollback_result,
                    "record": record,
                }
            return {
                "action": "blocked",
                "reason": "回滚已被其他 worker 占位",
                "record": record,
            }

        await session.flush()
        return {
            "action": "execute",
            "rollback_idempotency_key": rollback_key,
            "original_action_id": original_action_id,
            "record": record,
        }

    async def mark_rolling_back(self, session: AsyncSession, action_id: str):
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(status=ActionState.ROLLING_BACK.value)
        )

    async def mark_rolled_back(self, session: AsyncSession, action_id: str, rollback_result: dict):
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(
                status=ActionState.ROLLED_BACK.value,
                rollback_result=rollback_result,
            )
        )

    async def mark_rollback_failed(self, session: AsyncSession, action_id: str, error: str):
        await session.execute(
            update(ActionLedger)
            .where(ActionLedger.action_id == action_id)
            .values(
                status=ActionState.ROLLBACK_FAILED.value,
                error=error,
            )
        )

    async def get_by_action_id(self, session: AsyncSession, action_id: str) -> Optional[ActionLedger]:
        result = await session.execute(
            select(ActionLedger).where(ActionLedger.action_id == action_id)
        )
        return result.scalar_one_or_none()

    async def get_by_key(self, session: AsyncSession, idempotency_key: str) -> Optional[ActionLedger]:
        result = await session.execute(
            select(ActionLedger).where(ActionLedger.idempotency_key == idempotency_key)
        )
        return result.scalar_one_or_none()


# 全局单例
idempotency_guard = IdempotencyGuard()
