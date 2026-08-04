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

from .response_policies import policy_engine, ThreatActionMap
from .ddos_policy import ddos_policy, DDoSAttackContext, DDoSResponseDecision
from .db_safety import db_safety_policy
from .response_executor import response_executor, BatchActionResult
from .human_approval import approval_queue, ApprovalStatus
from .response_log import response_logger

logger = logging.getLogger(__name__)


class ResponseOrchestrator:
    """响应编排器"""

    def __init__(self):
        self._running_approvals: dict[str, asyncio.Task] = {}  # ticket_id → poll_task
        self._approval_poll_interval = 5  # 每5秒轮询一次审批状态

    async def on_threat_detected(
        self,
        session: AsyncSession,
        threat_info: dict,
        event_id: Optional[int] = None,
        session_id: str = "",
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

        Returns:
            {
                "matched": bool,
                "policy_name": str,
                "actions_executed": int,
                "approval_ticket_id": str (if any),
                "result": BatchActionResult,
            }
        """
        threat_type = threat_info.get("threat_type", "UNKNOWN")
        confidence = threat_info.get("confidence", 0.0)
        severity = threat_info.get("severity", "info")
        src_ip = threat_info.get("src_ip", "")

        logger.info(
            f"Orchestrator: threat detected type={threat_type} "
            f"conf={confidence:.2f} sev={severity} src={src_ip}"
        )

        # 1. 策略匹配
        action_map = policy_engine.match(
            threat_type=threat_type,
            confidence=confidence,
            severity=severity,
            src_ip=src_ip,
        )

        if not action_map.matched:
            logger.info(f"No policy matched for {threat_type}, skipping response")
            return {"matched": False, "policy_name": "", "actions_executed": 0}

        # 1.5 DDoS 分流 — 若为 DDoS 攻击, 走专用策略
        if threat_type == "DDoS_TRAFFIC":
            ddos_result = await self._handle_ddos(
                session, threat_info, action_map, event_id,
            )
            if ddos_result is not None:
                return ddos_result
            # 否则继续走默认流程

        # 1.6 A4 危险动作前置检查 — 在执行前拦截
        a4_violations = self._check_a4_actions(action_map.actions, threat_info)
        if a4_violations:
            logger.warning(
                f"A4 actions blocked: {a4_violations} for {threat_type}"
            )
            return {
                "matched": True,
                "policy_name": action_map.policy_name,
                "actions_executed": 0,
                "a4_blocked": True,
                "a4_violations": a4_violations,
                "reason": "A4 危险动作被前置拦截, 已创建工单",
            }

        # 2. 记录威胁到日志
        await response_logger.log_threat(
            session=session,
            threat_info=threat_info,
            policy_name=action_map.policy_name,
            actions=action_map.actions,
            auto_execute=action_map.auto_execute,
            needs_approval=action_map.needs_approval,
        )

        result = {
            "matched": True,
            "policy_name": action_map.policy_name,
            "actions_executed": 0,
            "approval_required": action_map.needs_approval,
            "auto_execute": action_map.auto_execute,
        }

        # 3. 需要审批
        if action_map.needs_approval:
            if action_map.auto_execute:
                # 先执行再审批（默认放行）
                batch_result = await response_executor.execute_actions(
                    action_map.actions, threat_info
                )
                result["actions_executed"] = batch_result.succeeded
                result["batch_result"] = {
                    "succeeded": batch_result.succeeded,
                    "failed": batch_result.failed,
                    "rollback_token": batch_result.batch_rollback_token,
                }

                # 同时提交审批工单（用于追溯）
                ticket = approval_queue.submit(
                    threat_info=threat_info,
                    policy_name=action_map.policy_name,
                    actions=action_map.actions,
                )
                ticket.status = ApprovalStatus.AUTO_APPROVED
                result["approval_ticket_id"] = ticket.id
            else:
                # 高风险 → 提交审批，等待人工确认
                ticket = approval_queue.submit(
                    threat_info=threat_info,
                    policy_name=action_map.policy_name,
                    actions=action_map.actions,
                )
                result["approval_ticket_id"] = ticket.id
                result["actions_executed"] = 0

                # 启动异步轮询
                task = asyncio.create_task(
                    self._poll_approval(ticket.id, threat_info)
                )
                self._running_approvals[ticket.id] = task

                logger.warning(
                    f"Approval required: ticket #{ticket.id[:8]} for "
                    f"{action_map.policy_name}"
                )

        # 4. 自动执行
        elif action_map.auto_execute:
            batch_result = await response_executor.execute_actions(
                action_map.actions, threat_info
            )
            result["actions_executed"] = batch_result.succeeded
            result["batch_result"] = {
                "succeeded": batch_result.succeeded,
                "failed": batch_result.failed,
                "rollback_token": batch_result.batch_rollback_token,
            }

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
                    batch_result = await response_executor.execute_actions(
                        ticket.actions, threat_info
                    )
                    ticket.result = {
                        "succeeded": batch_result.succeeded,
                        "failed": batch_result.failed,
                        "rollback_token": batch_result.batch_rollback_token,
                    }
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

        result = await response_executor.execute_actions(
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

    # ── DDoS 专用处理 ────────────────────────────────────────

    async def _handle_ddos(
        self,
        session: AsyncSession,
        threat_info: dict,
        action_map: ThreatActionMap,
        event_id: Optional[int],
    ) -> Optional[dict]:
        """DDoS 攻击专用处理 — 区分 6 种场景

        返回 None 表示走默认流程, 返回 dict 表示已处理完毕。
        """
        src_ip = threat_info.get("src_ip", "")
        src_ips = threat_info.get("src_ips", [src_ip] if src_ip else [])
        src_cidrs = threat_info.get("src_cidrs", [])

        ctx = DDoSAttackContext(
            src_ips=src_ips,
            src_cidrs=src_cidrs,
            target_ip=threat_info.get("dst_ip", ""),
            target_service=threat_info.get("target_service", ""),
            traffic_pps=threat_info.get("traffic_pps", 0),
            traffic_gbps=threat_info.get("traffic_gbps", 0.0),
            duration_seconds=threat_info.get("duration_seconds", 0),
            evidence_confidence=threat_info.get("confidence", 0.0),
            evidence_ids=threat_info.get("evidence_ids", []),
            attack_pattern=threat_info.get("attack_pattern", ""),
        )

        decision = ddos_policy.evaluate(ctx)

        logger.info(
            f"[DDoS] category={decision.category.value} "
            f"decision={decision.decision.value} "
            f"reason={decision.reason}"
        )

        # 记录到响应日志
        await response_logger.log_threat(
            session=session,
            threat_info={
                **threat_info,
                "ddos_category": decision.category.value,
                "ddos_decision": decision.decision.value,
            },
            policy_name=f"ddos_{decision.category.value}",
            actions=[{"name": a} for a in decision.allowed_actions],
            auto_execute=False,
            needs_approval=decision.require_human_approval,
        )

        # 根据决策执行
        if decision.decision == DDoSResponseDecision.USE_SCRUBBING_DEVICE:
            # 切换到清洗设备 — 提交工单 + 告警
            ticket = approval_queue.submit(
                threat_info=threat_info,
                policy_name="ddos_scrubbing_device",
                actions=[{
                    "name": "trigger_scrubbing",
                    "params": {
                        "target": decision.safe_targets,
                        "reason": decision.reason,
                    },
                }],
            )
            logger.warning(
                f"[DDoS] 切换到清洗设备, ticket={ticket.id} "
                f"reason={decision.reason}"
            )
            result = {
                "matched": True,
                "policy_name": f"ddos_{decision.category.value}",
                "ddos_decision": decision.decision.value,
                "actions_executed": 0,
                "scrubbing_device_required": True,
                "approval_ticket_id": ticket.id,
                "recommendations": decision.recommendations,
                "reason": decision.reason,
            }
            await self._update_event_response(session, event_id, result, threat_info)
            return result

        if decision.decision == DDoSResponseDecision.DENY_AUTO_RESPONSE:
            # 拒绝自动响应 (RFC1918 封禁等)
            logger.warning(
                f"[DDoS] 自动响应被拒绝: {decision.reason}"
            )
            result = {
                "matched": True,
                "policy_name": f"ddos_{decision.category.value}",
                "ddos_decision": decision.decision.value,
                "actions_executed": 0,
                "denied_actions": decision.denied_actions,
                "reason": decision.reason,
                "require_human_approval": decision.require_human_approval,
            }
            await self._update_event_response(session, event_id, result, threat_info)
            return result

        if decision.decision == DDoSResponseDecision.ISOLATE_INTERNAL_HOST:
            # 内部 DDoS — 只允许隔离/限速, 不封 IP/网段
            # 提交审批工单
            ticket = approval_queue.submit(
                threat_info=threat_info,
                policy_name=f"ddos_{decision.category.value}",
                actions=[
                    {"name": a, "params": {"targets": decision.safe_targets}}
                    for a in decision.allowed_actions
                ],
            )
            logger.info(
                f"[DDoS] 内部主机隔离, ticket={ticket.id} "
                f"actions={decision.allowed_actions}"
            )
            result = {
                "matched": True,
                "policy_name": f"ddos_{decision.category.value}",
                "ddos_decision": decision.decision.value,
                "actions_executed": 0,
                "allowed_actions": decision.allowed_actions,
                "denied_actions": decision.denied_actions,
                "approval_ticket_id": ticket.id,
                "require_human_approval": True,
                "recommendations": decision.recommendations,
                "reason": decision.reason,
            }
            await self._update_event_response(session, event_id, result, threat_info)
            return result

        if decision.decision in (DDoSResponseDecision.ALLOW_AUTO_BLOCK,
                                   DDoSResponseDecision.ALLOW_CIDR_BLOCK):
            # 允许自动封禁 — 走 TAG 流程 (若可用)
            # 此处不直接执行, 返回决策让上层 TAG 处理
            result = {
                "matched": True,
                "policy_name": f"ddos_{decision.category.value}",
                "ddos_decision": decision.decision.value,
                "actions_executed": 0,
                "allowed_actions": decision.allowed_actions,
                "safe_targets": decision.safe_targets,
                "max_ttl_seconds": decision.max_ttl_seconds,
                "require_canary": decision.require_canary,
                "require_auto_rollback": decision.require_auto_rollback,
                "require_health_check": decision.require_health_check,
                "reason": decision.reason,
                "deferred_to_tag": True,  # 实际执行交给 TAG
            }
            await self._update_event_response(session, event_id, result, threat_info)
            return result

        if decision.decision == DDoSResponseDecision.USE_RATE_LIMIT_ONLY:
            # 只允许限速
            actions = [
                {"name": "rate_limit",
                 "params": {"src_ip": ip, "bandwidth_kbps": 100}}
                for ip in decision.safe_targets
            ]
            batch_result = await response_executor.execute_actions(actions, threat_info)
            result = {
                "matched": True,
                "policy_name": f"ddos_{decision.category.value}",
                "ddos_decision": decision.decision.value,
                "actions_executed": batch_result.succeeded,
                "batch_result": {
                    "succeeded": batch_result.succeeded,
                    "failed": batch_result.failed,
                    "rollback_token": batch_result.batch_rollback_token,
                },
                "reason": decision.reason,
            }
            await self._update_event_response(session, event_id, result, threat_info)
            return result

        # REQUIRE_HUMAN_APPROVAL — 提交审批
        ticket = approval_queue.submit(
            threat_info=threat_info,
            policy_name=f"ddos_{decision.category.value}",
            actions=[],
        )
        result = {
            "matched": True,
            "policy_name": f"ddos_{decision.category.value}",
            "ddos_decision": decision.decision.value,
            "actions_executed": 0,
            "approval_ticket_id": ticket.id,
            "require_human_approval": True,
            "reason": decision.reason,
            "recommendations": decision.recommendations,
        }
        await self._update_event_response(session, event_id, result, threat_info)
        return result

    # ── A4 危险动作前置检查 ───────────────────────────────────

    def _check_a4_actions(
        self, actions: list[dict], threat_info: dict,
    ) -> list[dict]:
        """检查动作列表中是否包含 A4 危险动作

        返回 A4 违规列表, 每项 {action, reason, recommendations}。
        若返回空列表则通过。
        """
        violations: list[dict] = []
        src_ip = threat_info.get("src_ip", "")
        target_service = threat_info.get("target_service", "")

        for act in actions:
            name = act.get("name", "")
            params = act.get("params", {})

            a4 = db_safety_policy.check_action(
                tool_name=name,
                parameters=params,
                target=src_ip or params.get("src_ip", ""),
                asset_type=target_service,
            )

            if a4.should_block:
                # 创建工单
                try:
                    approval_queue.submit(
                        threat_info={
                            **threat_info,
                            "a4_blocked": True,
                            "a4_reason": a4.reason,
                            "a4_recommendations": a4.recommendations,
                        },
                        policy_name="a4_block",
                        actions=[act],
                    )
                except Exception as e:
                    logger.error(f"Failed to create A4 ticket: {e}")

                violations.append({
                    "action": name,
                    "blocked_by": a4.blocked_by,
                    "reason": a4.reason,
                    "recommendations": a4.recommendations,
                })

        return violations


response_orchestrator = ResponseOrchestrator()
