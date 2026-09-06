"""MCP Guard Server — 可信工具调用控制网关（核心控制层）。

职责：串联 Registry + Permission + Validator + PolicyEngine + Logger，
构成 Agent 与工具之间的唯一安全通道。

调用链（4层检查）：
    Agent ToolCallRequest
        ↓
    1. Registry 查询（工具是否注册，防幻觉工具）
    2. Permission RBAC 检查（角色是否有权调用）
    3. Validator 参数校验（Pydantic 强类型）
    4. PolicyEngine 规则评估（allow / deny / require_confirmation）
        ↓
    4.5 BehaviorDetector 行为签名（shadow 只打分；confirm/deny 可升级决策）
        ↓
    5. 放行 → 执行工具 / 拒绝 / 等待人工确认（签名 confirm 入审批队列）
    6. Logger 记录审计日志；否决写 audit_trail

注意：call_tool() 为同步方法，在 async 上下文中通过 asyncio.to_thread 调用。
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from .tool_registry import ToolRegistry
from .permission_manager import PermissionManager
from .validator import ParamValidator
from .policy_engine import PolicyEngine
from .call_logger import CallLogger
from .behavior_detector import BehaviorDetector
from .call_record import ToolCallRecord
from .approval_queue import ApprovalQueue

_DECISION_RANK = {"allow": 0, "require_confirmation": 1, "deny": 2}

logger = logging.getLogger(__name__)


@dataclass
class ToolCallRequest:
    """Agent 发起的工具调用请求。"""
    tool_name: str
    arguments: dict
    user_role: str
    reason: str = ""
    request_id: str = ""
    caller: str = ""
    source: str = "mcp_guard"
    session_id: str = ""
    trace_id: str = ""
    event_id: int = 0
    tool_match_method: str = "exact"


@dataclass
class GuardDecision:
    """Guard 决策结果。

    status: allow / deny / require_confirmation
    reason: 决策原因说明
    final_risk: 最终风险等级
    checks: 各层检查明细
    normalized_args: 校验后的规范化参数
    """
    status: str
    reason: str
    final_risk: str = ""
    checks: list = field(default_factory=list)
    normalized_args: dict = None


class McpGuardServer:
    """可信工具调用控制网关。

    Agent 不能直接调用工具，必须通过 McpGuardServer.call_tool() 入口。
    所有调用经过 4 层安全检查后才会被执行。
    """

    def __init__(self):
        # 初始化 4 层检查组件
        self.registry = ToolRegistry()
        self.permission = PermissionManager()
        self.validator = ParamValidator()
        self.policy = PolicyEngine()
        self.logger = CallLogger()
        self.detector = BehaviorDetector()
        self.logger.detector = self.detector
        self.approvals = ApprovalQueue()

    # ------------------------------------------------------------
    # 工具发现（供 Agent 查询可用工具）
    # ------------------------------------------------------------
    def list_tools(self) -> list:
        """列出所有已注册工具。"""
        return self.registry.list_tools()

    # ------------------------------------------------------------
    # 主入口：工具调用（同步方法）
    # ------------------------------------------------------------
    def call_tool(self, request: ToolCallRequest) -> dict:
        """处理 Agent 的工具调用请求，返回完整结果。

        本方法为同步方法，在 async 上下文中应通过 asyncio.to_thread 调用。

        返回结构：
        {
            "decision": "allow" / "deny" / "require_confirmation",
            "reason": "...",
            "final_risk": "...",
            "checks": [...],
            "execution": {...} or null,
        }
        """
        checks = []
        exec_result = None

        # ===== 第1层：工具注册检查（防幻觉工具） =====
        tool_info = self.registry.get_tool(request.tool_name)
        if tool_info is None:
            msg = f"工具 '{request.tool_name}' 未注册，疑似幻觉工具"
            checks.append({"check": "registry", "passed": False, "message": msg})
            decision = GuardDecision(status="deny", reason=msg, checks=checks)
            return self._finish(request, decision, None, None)

        checks.append({
            "check": "registry",
            "passed": True,
            "message": f"工具 '{request.tool_name}' 已注册，风险等级={tool_info.risk_level}",
        })

        # ===== 第2层：RBAC 权限检查 =====
        ok, msg = self.permission.check(request.user_role, request.tool_name)
        checks.append({"check": "permission", "passed": ok, "message": msg})
        if not ok:
            decision = GuardDecision(
                status="deny", reason="权限检查失败: " + msg, checks=checks
            )
            return self._finish(request, decision, None, None)

        # ===== 第3层：参数校验（Pydantic 强类型） =====
        ok, msg, normalized = self.validator.validate(request.tool_name, request.arguments)
        checks.append({"check": "params", "passed": ok, "message": msg})
        if not ok:
            decision = GuardDecision(
                status="deny", reason="参数校验失败: " + msg, checks=checks
            )
            return self._finish(request, decision, None, None)

        # ===== 第4层：规则引擎评估 =====
        decision_status, reason, hit_rules = self.policy.evaluate(
            tool_name=request.tool_name,
            tool_risk_level=tool_info.risk_level,
            arguments=normalized,
            user_role=request.user_role,
        )
        checks.append({
            "check": "policy",
            "passed": decision_status != "deny",
            "message": f"决策={decision_status}, 命中规则={hit_rules}, {reason}",
        })

        decision = GuardDecision(
            status=decision_status,
            reason=reason,
            final_risk=tool_info.risk_level,
            checks=checks,
            normalized_args=normalized,
        )

        return self._finish(request, decision, None, normalized)

    # ------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------
    def _identity(self, request: ToolCallRequest) -> dict:
        caller = getattr(request, "caller", "") or ""
        source = getattr(request, "source", "") or "mcp_guard"
        session_id = getattr(request, "session_id", "") or ""
        trace_id = getattr(request, "trace_id", "") or ""
        event_id = getattr(request, "event_id", 0) or 0
        tool_match_method = getattr(request, "tool_match_method", "") or "exact"
        try:
            from trace_hook import get_trace_context
            ctx = get_trace_context() or {}
            if not caller:
                caller = str(ctx.get("caller") or "")
            if not session_id:
                session_id = str(ctx.get("session_id") or "")
            if not trace_id:
                trace_id = str(ctx.get("trace_id") or "")
            if not event_id:
                event_id = int(ctx.get("event_id") or 0)
        except Exception:
            pass
        return {
            "caller": caller or "unknown",
            "source": source or "mcp_guard",
            "session_id": session_id,
            "trace_id": trace_id,
            "event_id": event_id,
            "tool_match_method": tool_match_method,
        }

    def _make_record(self, request: ToolCallRequest, decision: GuardDecision, normalized) -> ToolCallRecord:
        ident = self._identity(request)
        args = normalized if isinstance(normalized, dict) else (request.arguments or {})
        return ToolCallRecord.from_kwargs(
            user_role=request.user_role,
            tool_name=request.tool_name,
            arguments=args,
            decision=decision.status,
            reason=decision.reason,
            checks=decision.checks,
            caller=ident["caller"],
            source=ident["source"],
            session_id=ident["session_id"],
            trace_id=ident["trace_id"],
            event_id=ident["event_id"],
            tool_match_method=ident["tool_match_method"],
        )

    def _attach_signature_check(self, decision: GuardDecision, rec: ToolCallRecord, report) -> None:
        if report is None:
            return
        rec.signature_score = report.anomaly_score
        rec.signature_reasons = list(report.reasons)
        if report.cold_start:
            msg = report.reasons[0] if report.reasons else "learning"
        elif report.is_anomaly:
            msg = f"偏离 score={report.anomaly_score}: " + "; ".join(report.reasons[:3])
        else:
            msg = f"score={report.anomaly_score}"
        decision.checks.append({
            "check": "behavior_signature",
            "passed": not report.is_anomaly,
            "message": msg,
        })

    def _apply_enforcement(self, request: ToolCallRequest, decision: GuardDecision,
                           rec: ToolCallRecord, report) -> None:
        """按 report.action 升级决策（只升不降）。shadow / 故障不改。"""
        if report is None or report.action in (None, "logged"):
            return
        desired = "deny" if report.action == "deny" else "require_confirmation"
        if _DECISION_RANK[desired] <= _DECISION_RANK.get(decision.status, 0):
            return
        before = decision.status
        decision.status = desired
        decision.reason = "behavior_signature: " + (
            "; ".join(report.reasons[:3]) or f"score={report.anomaly_score}"
        )
        rec.decision = desired
        rec.reason = decision.reason
        self._audit_veto(request, rec, before, desired, report)

    def _enqueue_approval(self, request: ToolCallRequest, decision: GuardDecision,
                          rec: ToolCallRecord, report) -> dict:
        trigger = "behavior_signature" if (
            report is not None and report.action in ("confirm", "deny")
        ) else "policy"
        reasons = list(report.reasons) if report is not None else []
        score = report.anomaly_score if report is not None else None
        decision_reason = decision.reason
        if trigger == "behavior_signature" and reasons:
            decision_reason = "behavior_signature: " + "; ".join(reasons[:3])
        return self.approvals.create_ticket(
            tool_name=request.tool_name,
            arguments=rec.arguments if rec.arguments is not None else (request.arguments or {}),
            user_role=request.user_role,
            reason=request.reason or "",
            decision_reason=decision_reason,
            trigger=trigger,
            signature_score=score,
            signature_reasons=reasons,
        )

    def _audit_veto(self, request: ToolCallRequest, rec: ToolCallRecord,
                    before: str, after: str, report) -> None:
        try:
            from audit_trail import log_action_sync
            log_action_sync(
                actor=rec.caller or "system",
                actor_role=request.user_role or rec.caller_role,
                action="tool.signature_veto",
                target_type="tool",
                target_id=request.tool_name,
                before={"decision": before, "tool": request.tool_name},
                after={
                    "decision": after,
                    "score": None if report is None else report.anomaly_score,
                    "reasons": list(report.reasons[:4]) if report is not None else [],
                    "mode": self.detector.mode(),
                },
                reason=(
                    "; ".join(report.reasons[:3])
                    if report is not None and report.reasons
                    else after
                ),
            )
        except Exception as e:
            logger.warning("signature veto audit_trail failed: %s", e)

    def _emit_degraded(self) -> None:
        try:
            from event_bus import event_bus
            event_bus.publish("alert", {
                "type": "tool_signature_degraded",
                "severity": "high",
                "message": "behavior detector failed; fail-open",
            })
        except Exception:
            pass

    def _finish(self, request: ToolCallRequest, decision: GuardDecision,
                exec_result, normalized) -> dict:
        rec = self._make_record(request, decision, normalized)
        report = None
        try:
            report = self.detector.observe_pre_exec(rec)
        except Exception as e:
            logger.warning("behavior_signature pre_exec failed: %s", e)
            self._emit_degraded()
        self._attach_signature_check(decision, rec, report)
        self._apply_enforcement(request, decision, rec, report)

        if decision.status == "allow":
            args = decision.normalized_args if decision.normalized_args is not None else normalized
            try:
                exec_result = self.registry.execute(request.tool_name, args or {})
            except Exception as e:
                logger.warning("tool execute failed: %s", e)
                exec_result = {"status": "error", "error": str(e)}
        elif decision.status == "require_confirmation":
            ticket = self._enqueue_approval(request, decision, rec, report)
            exec_result = {
                "status": "pending",
                "message": "等待人工确认，工具暂未执行",
                "ticket_id": ticket.get("ticket_id"),
                "trigger": ticket.get("trigger"),
            }
        else:
            exec_result = None

        rec.decision = decision.status
        rec.reason = decision.reason
        if exec_result:
            rec.exec_status = exec_result.get("status")
            rec.exec_result = exec_result if isinstance(exec_result, dict) else None
        try:
            self.detector.observe_post_exec(rec, report)
        except Exception as e:
            logger.warning("behavior_signature post_exec failed: %s", e)
        self._log(request, decision, exec_result, record=rec, report=report)
        if rec.event_id:
            try:
                from observability.thought_events import emit_tool_result
                emit_tool_result(
                    tool_name=rec.tool_name,
                    success=decision.status == "allow",
                    duration_ms=rec.duration_ms,
                    report=report,
                    event_id=rec.event_id,
                    session_id=rec.session_id,
                    trace_id=rec.trace_id,
                )
            except Exception:
                pass
        body = self._build_response(decision, exec_result, report)
        if isinstance(exec_result, dict) and exec_result.get("ticket_id"):
            body["ticket_id"] = exec_result["ticket_id"]
        return body

    def _build_response(self, decision: GuardDecision, exec_result: Optional[dict], report=None) -> dict:
        """构建统一响应结构。"""
        body = {
            "decision": decision.status,
            "reason": decision.reason,
            "final_risk": decision.final_risk,
            "checks": decision.checks,
            "execution": exec_result,
        }
        if report is not None:
            body["signature"] = report.to_dict()
        return body

    def _log(self, request: ToolCallRequest, decision: GuardDecision, exec_result,
             record: Optional[ToolCallRecord] = None, report=None):
        """记录调用审计日志。"""
        exec_status = exec_result.get("status") if exec_result else None
        ident = self._identity(request)
        score = report.anomaly_score if report is not None else None
        reasons = list(report.reasons) if report is not None else None
        if record is not None:
            record.decision = decision.status
            record.exec_status = exec_status
            record.signature_score = score
            record.signature_reasons = reasons or []
        self.logger.log(
            user_role=request.user_role,
            tool_name=request.tool_name,
            arguments=request.arguments,
            decision=decision.status,
            reason=decision.reason,
            checks=decision.checks,
            exec_status=exec_status,
            exec_result=exec_result,
            caller=ident["caller"],
            source=ident["source"],
            session_id=ident["session_id"],
            trace_id=ident["trace_id"],
            event_id=ident["event_id"],
            tool_match_method=ident["tool_match_method"],
            signature_score=score,
            signature_reasons=reasons,
            record=record,
        )


# 全局单例，供平台各模块直接使用
mcp_guard = McpGuardServer()
