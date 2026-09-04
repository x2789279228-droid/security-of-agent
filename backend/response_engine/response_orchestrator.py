"""
响应编排器 (Response Orchestrator)

核心职责:
  1. 监听威胁事件（来自 Audit-LLM 流水线 / AnomalyDetector）
  2. 调用 PolicyEngine 匹配策略
  3. 根据策略结果: 自动执行 / 提交审批 / 跳过
  4. 将执行结果写回事件原始数据
  5. 与熔断器联动

触发时机:
  - Audit-LLM 流水线完成后 (log_ingestion.py 中调用)
  - AnomalyDetector 检测到高异常分事件 (可选)
  - 手动通过 API 触发

流程图:
  on_threat_detected(threat_info)
      → policy_engine.match(...)
      → if matched:
          → if needs_approval:
              → approval_queue.submit(...)
              → 等待审批（异步轮询/Webhook）
              → if approved:
                  → response_executor.execute_actions(...)
              → if rejected:
                  → 记录拒绝
          → else:
              → response_executor.execute_actions(...)
      → 写入 DB (SecurityEvent.raw_data._response)
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .response_policies import (
    policy_engine, MatchStatus, UNCERTAIN_POLICY_NAME,
)
from .response_registry import has_critical_action, response_registry
from .response_executor import response_executor, ActionResult, BatchActionResult
from .human_approval import approval_queue, ApprovalStatus
from .response_log import response_logger

logger = logging.getLogger(__name__)

# 安全护栏（动作执行前多维度审查）
from security_guard.security_guard import security_guard
from security_guard.intent_checker import IntentChecker

# v5 修复(A):双轨封禁门槛 — allow_blocking=False 时仅允许的"无副作用"动作。
# rate_limit 虽不封禁但会改变流量形态，告警-only 模式下一并排除。
ALERT_ONLY_ACTIONS = frozenset({"send_alert"})


def normalize_threat_info_for_guard(threat_info: dict) -> dict:
    """把策略/FastPath 字段归一为 SecurityGuard 期望的 threat_level/reason。"""
    info = dict(threat_info or {})
    info["threat_level"] = IntentChecker.resolve_threat_level(info)
    info["reason"] = IntentChecker.resolve_reason(info)
    if not info.get("severity") and info["threat_level"] != "unknown":
        info["severity"] = info["threat_level"]
    return info


def _infer_from_name(name: str) -> str:
    """从自然语言事件名推断标准威胁类型枚举(如 "C2 通信" → C2_BEACON)。"""
    try:
        from correlation_engine import infer_threat_type
        return infer_threat_type(name)
    except Exception:
        return ""


def _classify_from_name(name: str) -> tuple[str, str]:
    """自然语言 → (leaf, category)。"""
    try:
        from correlation_engine import infer_threat_classification
        return infer_threat_classification(name)
    except Exception:
        leaf = _infer_from_name(name)
        return leaf, ""


def _inner_result(action_result: ActionResult) -> dict:
    raw = action_result.result if isinstance(action_result.result, dict) else {}
    return raw


def action_rows_from_batch(
    batch_result: Optional[BatchActionResult],
    threat_info: dict,
    policy_name: str,
    auto_execute: bool,
    approval_id: str = "",
    approval_status: str = "",
) -> list[dict]:
    """把批量执行结果展开成逐条响应日志字段（便于测试/落库）。"""
    rows: list[dict] = []
    if not batch_result:
        return rows
    for item in batch_result.results or []:
        inner = _inner_result(item)
        mode = inner.get("mode") or inner.get("execution_mode") or ""
        rows.append({
            "session_id": threat_info.get("session_id", ""),
            "event_id": threat_info.get("event_id", 0) or 0,
            "threat_info": {**threat_info, "policy_name": policy_name},
            "action_name": item.action_name,
            "action_params": {
                "execution_mode": mode,
                "verified": inner.get("verified"),
                "error": item.error or inner.get("error") or "",
            },
            "success": bool(item.success),
            "result": inner or {"error": item.error},
            "rollback_token": (
                item.rollback_token or getattr(batch_result, "batch_rollback_token", "") or ""
            ),
            "auto_execute": auto_execute,
            "approval_id": approval_id,
            "approval_status": approval_status,
        })
    return rows


class ResponseOrchestrator:
    """响应编排器"""

    def __init__(self):
        self._running_approvals: dict[str, asyncio.Task] = {}  # ticket_id → poll_task
        self._approval_poll_interval = 5  # 每5秒轮询一次审批状态

    async def _guarded_execute(
        self, actions: list, threat_info: dict
    ) -> BatchActionResult:
        """
        安全护栏包装的执行入口

        对每个动作先经过 SecurityGuard.inspect() 审查:
          - 被拦截 → 跳过该动作，记录日志
          - 通过 → 执行
        执行完毕后调用 SecurityGuard.record() 更新追踪器
        """
        threat_info = normalize_threat_info_for_guard(threat_info)
        allowed_actions = []
        for action in actions:
            action_name = action.get("action", action.get("name", ""))
            guard_result = security_guard.inspect(action_name, threat_info)

            if not guard_result["allowed"]:
                logger.warning(
                    f"[SecurityGuard] 动作被拦截: {action_name} "
                    f"原因: {guard_result['reason']}"
                )
                continue

            if guard_result.get("requires_approval"):
                logger.info(
                    f"[SecurityGuard] 动作需审批: {action_name}"
                )
                # 仍然加入执行列表：CRITICAL 动作已在编排层被强制走人工审批，
                # 能走到这里的需审批动作均为 HIGH 且策略显式 auto_execute 豁免

            allowed_actions.append(action)

        if not allowed_actions:
            logger.warning("[SecurityGuard] 所有动作被拦截，无动作可执行")
            return BatchActionResult(succeeded=0, failed=0, results=[])

        # 执行
        batch_result = await response_executor.execute_actions(
            allowed_actions, threat_info
        )

        # 记录（更新序列/频率/上下文追踪器）
        # 频率名额已在 inspect→rate_limiter.check() 通过时同步预留，
        # 这里按逐动作的执行结果做确认：失败的动作释放预留额度
        success_by_action: dict = {}
        for item in batch_result.results:
            success_by_action.setdefault(item.action_name, []).append(item.success)

        for action in allowed_actions:
            action_name = action.get("action", action.get("name", ""))
            successes = success_by_action.get(action_name, [True])
            security_guard.record(action_name, threat_info, {
                "success": all(successes),
                "succeeded": batch_result.succeeded,
                "failed": batch_result.failed,
            })

        return batch_result

    async def on_threat_detected(
        self,
        session: AsyncSession,
        threat_info: dict,
        event_id: Optional[int] = None,
        session_id: str = "",
        allow_blocking: bool = True,
    ) -> dict:
        """
        当威胁被检测到时调用

        Args:
            session: DB session
            threat_info: {
                "threat_type": "C2_BEACON",
                "confidence": 0.85,
                "severity": "critical",
                "src_ip": "10.0.0.5",
                "dst_ip": "..."，
                "message": "...",
                "event_id": 123,
            }
            event_id: SecurityEvent ID (用于写回)
            session_id: 会话ID
            allow_blocking: v5 修复(A) 双轨封禁门槛。False 时过滤掉
                block_ip/isolate_host/rate_limit 等有副作用动作，仅执行
                send_alert；封禁等 Audit-LLM confirmed 后再触发。
                FastPath 仅 severity 触发（无强非 LLM 信号）时传 False。

        Returns:
            {
                "matched": bool,
                "policy_name": str,
                "actions_executed": int,
                "approval_ticket_id": str (if any),
                "result": BatchActionResult,
            }
        """
        threat_info = normalize_threat_info_for_guard(threat_info)
        if session_id and not threat_info.get("session_id"):
            threat_info["session_id"] = session_id
        if event_id and not threat_info.get("event_id"):
            threat_info["event_id"] = event_id
        # 兜底链: 显式 threat_type 枚举 → 事件名(可能是自然语言) → 按名称推断枚举
        raw_threat_name = (
            threat_info.get("threat_type")
            or threat_info.get("event")
            or ""
        )
        leaf, inferred_cat = _classify_from_name(str(raw_threat_name))
        # leaf 优先；仅识别到父类时 leaf 留空，交给 category 匹配
        if leaf:
            threat_type = leaf
        elif inferred_cat:
            threat_type = ""
        else:
            fallback = _infer_from_name(raw_threat_name)
            raw_s = str(raw_threat_name or "").strip()
            # 未知中文名不透传为 threat_type，避免污染策略键；ASCII 枚举可透传
            threat_type = fallback or (raw_s if raw_s.isascii() else "") or ""
        category = (
            str(threat_info.get("category") or "").strip()
            or inferred_cat
            or ""
        )
        confidence = threat_info.get("confidence", 0.0)
        severity = threat_info.get("severity", "info")
        src_ip = threat_info.get("src_ip", "")

        # v5/L3: 回写归一化 leaf + category，供日志与策略匹配
        threat_info["threat_type"] = threat_type or threat_info.get("threat_type") or ""
        if category:
            threat_info["category"] = category

        logger.info(
            f"Orchestrator: threat detected type={threat_type or '-'} "
            f"cat={category or '-'} conf={confidence:.2f} sev={severity} "
            f"threat_level={threat_info.get('threat_level')} src={src_ip} "
            f"allow_blocking={allow_blocking}"
        )

        # 1. 策略匹配
        action_map = policy_engine.match(
            threat_type=threat_type,
            confidence=confidence,
            severity=severity,
            src_ip=src_ip,
            category=category,
        )
        # 兼容测试/外部 mock：缺省字段按 matched 布尔回退
        match_status = getattr(action_map, "match_status", None)
        if match_status is None:
            match_status = (
                MatchStatus.MATCHED if action_map.matched else MatchStatus.NO_ACTION
            )
        skip_reason = getattr(action_map, "skip_reason", "") or ""
        category = getattr(action_map, "category", "") or ""
        threat_info["match_status"] = (
            match_status.value if hasattr(match_status, "value") else str(match_status)
        )
        threat_info["skip_reason"] = skip_reason
        if category:
            threat_info["category"] = category

        # 非处置状态：可观测返回，禁止 debug 静默放过
        if match_status in (
            MatchStatus.SKIPPED, MatchStatus.NO_ACTION, MatchStatus.FILTERED,
        ):
            logger.info(
                f"Orchestrator: status={match_status.value} type={threat_type} "
                f"reason={action_map.skip_reason or '-'} src={src_ip}"
            )
            return {
                "matched": False,
                "match_status": threat_info["match_status"],
                "skip_reason": skip_reason,
                "policy_name": action_map.policy_name,
                "actions_executed": 0,
            }

        is_uncertain = match_status == MatchStatus.UNCERTAIN

        # 1b. v5 修复(A):双轨门槛 — 仅告警模式过滤掉封禁/限速/隔离类动作
        if not allow_blocking and action_map.actions:
            _removed = [
                (a.get("action") or a.get("name") or "?")
                for a in action_map.actions
                if (a.get("action") or a.get("name") or "") not in ALERT_ONLY_ACTIONS
            ]
            action_map.actions = [
                a for a in action_map.actions
                if (a.get("action") or a.get("name") or "") in ALERT_ONLY_ACTIONS
            ]
            if is_uncertain:
                # Uncertain 即使只剩告警也必须建 P1 工单，等人审决定是否升级封禁
                action_map.needs_approval = True
            else:
                action_map.needs_approval = (
                    any(
                        response_registry.needs_approval(
                            a.get("action") or a.get("name") or ""
                        )
                        for a in action_map.actions
                    )
                )
            if _removed:
                logger.warning(
                    f"[AlertOnly] 双轨门槛拦截封禁类动作 {_removed} "
                    f"(src={src_ip} type={threat_type}); 封禁等 Audit-LLM confirmed"
                )
            action_map.auto_execute = True

        # 2. 记录威胁到日志
        await response_logger.log_threat(
            session=session,
            threat_info=threat_info,
            policy_name=action_map.policy_name,
            actions=action_map.actions,
            auto_execute=action_map.auto_execute,
            needs_approval=action_map.needs_approval,
            match_status=threat_info["match_status"],
            skip_reason=skip_reason,
            category=category,
        )

        result = {
            "matched": True,
            "match_status": threat_info["match_status"],
            "skip_reason": skip_reason,
            "policy_name": action_map.policy_name,
            "actions_executed": 0,
            "approval_required": action_map.needs_approval,
            "auto_execute": action_map.auto_execute,
        }

        ticket_kwargs = {}
        if is_uncertain:
            ticket_kwargs = {
                "priority": "p1",
                "match_status": MatchStatus.UNCERTAIN.value,
                "timeout_minutes": 15,
            }
            logger.warning(
                f"Orchestrator: match_status=uncertain type={threat_type} "
                f"src={src_ip} policy={UNCERTAIN_POLICY_NAME} "
                f"duration=5m allow_blocking={allow_blocking}"
            )

        # 3. 需要审批
        if action_map.needs_approval:
            # 分级强制：CRITICAL 动作（如 isolate_host）无论策略如何一律人工审批；
            # 仅含 HIGH 动作（如 block_ip）时，策略显式 auto_execute=True 才允许
            # 先执行，工单记为 AUTO_EXECUTED（供事后审查/回滚），不伪造审批通过。
            if action_map.auto_execute and not has_critical_action(action_map.actions):
                batch_result = await self._guarded_execute(
                    action_map.actions, threat_info
                )
                result["actions_executed"] = batch_result.succeeded
                result["batch_result"] = {
                    "succeeded": batch_result.succeeded,
                    "failed": batch_result.failed,
                    "rollback_token": batch_result.batch_rollback_token,
                    "actions": [
                        {"name": r.action_name, "success": r.success,
                         "mode": _inner_result(r).get("mode", "")}
                        for r in batch_result.results
                    ],
                }

                blocked = any(
                    r.success and r.action_name == "block_ip"
                    for r in batch_result.results
                )
                if any(r.success for r in batch_result.results) or is_uncertain:
                    # Uncertain 无论是否封成功都建工单；专属策略仍要求至少一动作成功才烧冷却
                    if any(r.success for r in batch_result.results):
                        policy_engine.mark_executed(action_map.policy_name, src_ip)
                    ticket = approval_queue.submit(
                        threat_info=threat_info,
                        policy_name=action_map.policy_name,
                        actions=action_map.actions,
                        **ticket_kwargs,
                    )
                    # Uncertain: 已短封 → AUTO_EXECUTED；未封（medium/双轨）→ PENDING 等人审升级
                    if is_uncertain and not blocked:
                        ticket.status = ApprovalStatus.PENDING
                    else:
                        ticket.status = ApprovalStatus.AUTO_EXECUTED
                    result["approval_ticket_id"] = ticket.id
                    result["approval_priority"] = ticket.priority
                    await self._log_executed_actions(
                        session, batch_result, threat_info, action_map.policy_name,
                        auto_execute=True, approval_id=ticket.id,
                        approval_status=ticket.status.value,
                    )
                    if is_uncertain and not blocked:
                        task = asyncio.create_task(
                            self._poll_approval(ticket.id, threat_info)
                        )
                        self._running_approvals[ticket.id] = task
            else:
                ticket = approval_queue.submit(
                    threat_info=threat_info,
                    policy_name=action_map.policy_name,
                    actions=action_map.actions,
                    **ticket_kwargs,
                )
                result["approval_ticket_id"] = ticket.id
                result["approval_priority"] = ticket.priority
                result["actions_executed"] = 0
                policy_engine.mark_executed(action_map.policy_name, src_ip)

                task = asyncio.create_task(
                    self._poll_approval(ticket.id, threat_info)
                )
                self._running_approvals[ticket.id] = task

                logger.warning(
                    f"Approval required: ticket #{ticket.id[:8]} for "
                    f"{action_map.policy_name} priority={ticket.priority}"
                )

        # 4. 自动执行
        elif action_map.auto_execute:
            batch_result = await self._guarded_execute(
                action_map.actions, threat_info
            )
            result["actions_executed"] = batch_result.succeeded
            if any(r.success for r in batch_result.results):
                policy_engine.mark_executed(action_map.policy_name, src_ip)
            result["batch_result"] = {
                "succeeded": batch_result.succeeded,
                "failed": batch_result.failed,
                "rollback_token": batch_result.batch_rollback_token,
                "actions": [
                    {"name": r.action_name, "success": r.success,
                     "mode": _inner_result(r).get("mode", "")}
                    for r in batch_result.results
                ],
            }
            await self._log_executed_actions(
                session, batch_result, threat_info, action_map.policy_name,
                auto_execute=True, approval_status="approved",
            )

        # 5. 写回事件数据
        await self._update_event_response(
            session, event_id, result, threat_info
        )

        return result

    async def _poll_approval(self, ticket_id: str, threat_info: dict):
        """轮询审批状态 — 当审批通过时执行动作"""
        try:
            while True:
                await asyncio.sleep(self._approval_poll_interval)
                ticket = approval_queue.get_ticket(ticket_id)
                if not ticket:
                    logger.warning(f"Approval ticket {ticket_id} vanished")
                    return

                if ticket.status == ApprovalStatus.APPROVED:
                    logger.info(f"Approval granted for ticket #{ticket_id[:8]}, executing actions")
                    batch_result = await self._guarded_execute(
                        ticket.actions, threat_info
                    )
                    ticket.result = {
                        "succeeded": batch_result.succeeded,
                        "failed": batch_result.failed,
                        "rollback_token": batch_result.batch_rollback_token,
                    }
                    if any(r.success for r in batch_result.results):
                        policy_engine.mark_executed(
                            ticket.policy_name or "",
                            threat_info.get("src_ip", ""),
                        )
                    try:
                        from models import async_session as db_session
                        async with db_session() as s:
                            await self._log_executed_actions(
                                s, batch_result, threat_info,
                                ticket.policy_name or "",
                                auto_execute=False, approval_id=ticket_id,
                                approval_status="approved",
                            )
                    except Exception as log_err:
                        logger.warning(f"Failed to log approved actions: {log_err}")
                    return

                if ticket.status == ApprovalStatus.REJECTED:
                    logger.info(f"Approval rejected for ticket #{ticket_id[:8]}: {ticket.reject_reason}")
                    return

                if ticket.status == ApprovalStatus.EXPIRED:
                    logger.info(f"Approval expired for ticket #{ticket_id[:8]}")
                    return

        except asyncio.CancelledError:
            logger.info(f"Approval poll cancelled for ticket #{ticket_id[:8]}")
        except Exception as e:
            logger.error(f"Approval poll failed for ticket #{ticket_id[:8]}: {e}")
        finally:
            self._running_approvals.pop(ticket_id, None)

    async def _log_executed_actions(
        self,
        session: AsyncSession,
        batch_result: BatchActionResult,
        threat_info: dict,
        policy_name: str,
        auto_execute: bool,
        approval_id: str = "",
        approval_status: str = "",
    ):
        """把 block_ip / rate_limit / send_alert 等真实动作写入响应日志。"""
        rows = action_rows_from_batch(
            batch_result, threat_info, policy_name, auto_execute,
            approval_id=approval_id, approval_status=approval_status,
        )
        for row in rows:
            try:
                await response_logger.log_action(
                    session=session,
                    session_id=row["session_id"],
                    event_id=row["event_id"],
                    threat_info=row["threat_info"],
                    action_name=row["action_name"],
                    action_params=row["action_params"],
                    success=row["success"],
                    result=row["result"],
                    rollback_token=row["rollback_token"],
                    auto_execute=row["auto_execute"],
                    approval_id=row["approval_id"],
                    approval_status=row["approval_status"],
                )
            except Exception as e:
                logger.warning(f"Failed to log action {row.get('action_name')}: {e}")

    async def _update_event_response(
        self,
        session: AsyncSession,
        event_id: Optional[int],
        result: dict,
        threat_info: dict,
    ):
        """将响应结果写回 SecurityEvent.raw_data._response"""
        if not event_id or not session:
            return
        try:
            from models import SecurityEvent
            evt = await session.get(SecurityEvent, event_id)
            if evt:
                response_records = (evt.raw_data or {}).get("_response", [])
                if not isinstance(response_records, list):
                    response_records = []
                # 显式重建 raw_data，确保 JSON 修改被 SQLAlchemy 追踪
                evt.raw_data = {
                    **(evt.raw_data or {}),
                    "_response": response_records + [{
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "policy_name": result.get("policy_name", ""),
                        "actions_executed": result.get("actions_executed", 0),
                        "approval_required": result.get("approval_required", False),
                        "approval_ticket_id": result.get("approval_ticket_id", ""),
                        "batch_result": result.get("batch_result", {}),
                        "threat_info": threat_info,
                    }],
                }
                await session.commit()
                try:
                    from event_store import event_store
                    event_store.invalidate(event_id)
                except Exception:
                    pass
                logger.info(f"Updated event #{event_id} with response result")
        except Exception as e:
            logger.warning(f"Failed to update event response: {e}")

    async def execute_approved_action(self, ticket_id: str) -> Optional[BatchActionResult]:
        """执行已批准的工单动作（手动触发）"""
        ticket = approval_queue.get_ticket(ticket_id)
        if not ticket:
            logger.warning(f"Ticket not found: {ticket_id}")
            return None
        if ticket.status != ApprovalStatus.APPROVED:
            logger.warning(f"Ticket {ticket_id} not approved (status={ticket.status.value})")
            return None

        result = await self._guarded_execute(
            ticket.actions, ticket.threat_info
        )
        ticket.result = {
            "succeeded": result.succeeded,
            "failed": result.failed,
            "rollback_token": result.batch_rollback_token,
        }
        return result

    async def rollback_response(self, rollback_token: str) -> Optional[BatchActionResult]:
        """回滚一次响应"""
        return await response_executor.rollback_batch(rollback_token)


response_orchestrator = ResponseOrchestrator()
