"""
看门狗诊断 Agent (Watchdog)

当 HealthMonitor 检测到异常或定时巡检发现退化时，
Watchdog 收集全链路数据并通过 LLM 生成根因分析报告。

触发方式:
  1. HealthMonitor 规则触发（错误率/延迟/卡死）
  2. Scheduler 定时巡检（每 10 分钟）
  3. 手动 API 触发（POST /api/observability/diagnose）

输出三通道:
  - SSE 实时推送（EventBus）
  - PostgreSQL 持久化（diagnostic_reports 表）
  - 告警通知（send_alert）
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class WatchdogAgent:
    """看门狗诊断 Agent"""

    def __init__(self):
        self._last_diagnose_time = 0.0
        self._diagnose_cooldown = 120  # 两次诊断最小间隔（秒）
        self._diagnose_count = 0

    async def diagnose(
        self,
        trigger_reason: str = "manual",
        trigger_stage: str = "",
        context: Optional[dict] = None,
    ) -> dict:
        """
        执行全链路诊断

        Args:
            trigger_reason: 触发原因
            trigger_stage: 触发阶段
            context: HealthMonitor 传入的健康快照

        Returns:
            DiagnosticReport dict
        """
        now = time.time()

        # 冷却检查（避免频繁诊断）
        if now - self._last_diagnose_time < self._diagnose_cooldown:
            logger.info(
                f"[Watchdog] Diagnose skipped (cooldown): "
                f"{now - self._last_diagnose_time:.0f}s < {self._diagnose_cooldown}s"
            )
            return {"skipped": True, "reason": "cooldown"}

        self._last_diagnose_time = now
        self._diagnose_count += 1
        t_start = time.time()

        logger.warning(
            f"[Watchdog] Diagnosing: trigger='{trigger_reason}' stage='{trigger_stage}'"
        )

        # ── 1. 收集诊断数据 ──
        diag_data = self._collect_diagnostic_data(context)

        # ── 2. LLM 根因分析 ──
        llm_analysis = await self._llm_analyze(trigger_reason, trigger_stage, diag_data)

        # ── 3. 构建诊断报告 ──
        report = {
            "id": f"diag-{int(now)}-{self._diagnose_count}",
            "trigger_reason": trigger_reason,
            "trigger_stage": trigger_stage,
            "severity": self._assess_severity(diag_data),
            "stage_metrics": diag_data.get("stage_stats", {}),
            "root_cause": llm_analysis.get("root_cause", "未知"),
            "recommendations": llm_analysis.get("recommendations", []),
            "llm_analysis": llm_analysis.get("narrative", ""),
            "affected_event_count": diag_data.get("affected_events", 0),
            "active_spans": diag_data.get("active_spans", []),
            "recent_errors": diag_data.get("recent_errors", []),
            "circuit_breaker": diag_data.get("circuit_breaker", {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((time.time() - t_start) * 1000, 1),
        }

        # ── 4. 三通道输出 ──
        await self._output_report(report)

        logger.info(
            f"[Watchdog] Diagnosis complete: severity={report['severity']} "
            f"root_cause='{report['root_cause'][:80]}' "
            f"duration={report['duration_ms']}ms"
        )
        return report

    async def patrol(self) -> dict:
        """
        定时巡检（由 scheduler 调用）

        检查全链路健康，全绿则记录 OK，有异常则触发诊断。
        """
        from .health_monitor import health_monitor

        snapshot = health_monitor.get_health_snapshot()

        if snapshot.overall_status == "green":
            return {
                "status": "healthy",
                "message": "全链路健康，无异常",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # 有异常 → 触发诊断
        worst_stage = ""
        worst_reasons = []
        for stage_name, stage_health in snapshot.stages.items():
            if stage_health.status == "red":
                worst_stage = stage_name
                worst_reasons = [stage_health.message]
                break

        return await self.diagnose(
            trigger_reason=f"patrol: {snapshot.overall_status} - {worst_stage}",
            trigger_stage=worst_stage,
            context=snapshot.to_dict(),
        )

    # ── 内部方法 ──

    def _collect_diagnostic_data(self, context: Optional[dict] = None) -> dict:
        """收集全链路诊断数据"""
        from .pipeline_tracer import pipeline_tracer

        data = {
            "stage_stats": pipeline_tracer.get_stage_stats(),
            "active_spans": pipeline_tracer.get_active_spans(),
            "recent_spans": pipeline_tracer.get_recent_spans(limit=30),
            "affected_events": 0,
            "recent_errors": [],
            "circuit_breaker": {},
        }

        # 从健康快照补充
        if context:
            data["stage_stats"] = context.get("stages", data["stage_stats"])
            alerts = context.get("alerts", [])
            data["recent_errors"] = [
                {"stage": a.get("stage"), "reasons": a.get("reasons", [])}
                for a in alerts
            ]

        # 统计受影响事件数
        error_spans = [
            s for s in data["recent_spans"]
            if s.get("status") in ("error", "timeout")
        ]
        data["affected_events"] = len(set(
            s.get("event_id", 0) for s in error_spans if s.get("event_id")
        ))

        # 提取最近错误
        for s in data["recent_spans"]:
            if s.get("error"):
                data["recent_errors"].append({
                    "stage": s.get("stage"),
                    "event_id": s.get("event_id"),
                    "error": s.get("error", "")[:200],
                    "latency_ms": s.get("latency_ms", 0),
                })
        data["recent_errors"] = data["recent_errors"][:10]

        # CAD 熔断器状态
        try:
            from cad import circuit_breaker
            data["circuit_breaker"] = circuit_breaker.get_status()
        except Exception:
            pass

        # LLM trace 最近错误
        try:
            from .pipeline_tracer import pipeline_tracer as pt
            executor_spans = pt.get_recent_spans(stage="executor", limit=10)
            data["executor_recent"] = executor_spans
        except Exception:
            pass

        return data

    async def _llm_analyze(
        self, trigger_reason: str, trigger_stage: str, diag_data: dict
    ) -> dict:
        """LLM 根因分析"""
        try:
            from summary_compression import summary

            # 构建诊断 prompt
            stage_summary = []
            for stage, stats in diag_data.get("stage_stats", {}).items():
                if isinstance(stats, dict):
                    status = stats.get("status", stats.get("message", "?"))
                    err_rate = stats.get("error_rate", 0)
                    p95 = stats.get("p95_latency_ms", 0)
                    last_err = stats.get("last_error", "")[:100]
                    stage_summary.append(
                        f"  {stage}: status={status} error_rate={err_rate:.0%} "
                        f"p95={p95:.0f}ms last_error='{last_err}'"
                    )

            errors_text = "\n".join(
                f"  [{e.get('stage')}] event=#{e.get('event_id')} "
                f"error='{e.get('error', '')[:100]}'"
                for e in diag_data.get("recent_errors", [])[:8]
            )

            active_text = "\n".join(
                f"  [{s.get('stage')}] event=#{s.get('event_id')} "
                f"running={s.get('running_seconds', 0):.0f}s"
                for s in diag_data.get("active_spans", [])[:5]
            )

            cb = diag_data.get("circuit_breaker", {})
            cb_text = (
                f"tripped={cb.get('tripped', False)} "
                f"reason='{cb.get('reason', '')}' "
                f"audit_count={cb.get('audit_count', 0)}"
            )

            prompt = f"""你是安全审计平台的运维诊断专家。以下平台流水线出现了异常，请分析根因并给出修复建议。

## 触发原因
{trigger_reason}
触发阶段: {trigger_stage or '未知'}

## 各阶段健康状态
{chr(10).join(stage_summary) if stage_summary else '  (无数据)'}

## 最近错误
{errors_text if errors_text else '  (无)'}

## 当前卡死的 Span
{active_text if active_text else '  (无)'}

## CAD 熔断器
{cb_text}

## 受影响事件数
{diag_data.get('affected_events', 0)}

## 输出要求（严格 JSON）
{{
    "root_cause": "一句话根因判断",
    "severity": "critical/high/medium/low",
    "narrative": "2-3 段详细分析（中文）：发生了什么、为什么、影响范围",
    "recommendations": ["建议1", "建议2", "建议3"],
    "affected_component": "最可能出问题的组件",
    "auto_recoverable": true/false
}}"""

            from trace_hook import set_trace_context
            set_trace_context(operation="watchdog_diagnose", caller="watchdog")
            result = await summary.llm.chat([
                {"role": "system", "content": "你是运维诊断专家，输出 JSON。"},
                {"role": "user", "content": prompt},
            ])

            # 解析 JSON
            try:
                parsed = json.loads(result)
                return {
                    "root_cause": parsed.get("root_cause", "LLM 未给出根因"),
                    "narrative": parsed.get("narrative", result[:500]),
                    "recommendations": parsed.get("recommendations", []),
                    "severity": parsed.get("severity", "medium"),
                    "affected_component": parsed.get("affected_component", ""),
                    "auto_recoverable": parsed.get("auto_recoverable", False),
                }
            except json.JSONDecodeError:
                return {
                    "root_cause": "LLM 输出解析失败",
                    "narrative": result[:500],
                    "recommendations": ["检查 LLM 输出格式"],
                    "severity": "medium",
                }

        except Exception as e:
            logger.error(f"[Watchdog] LLM analysis failed: {e}")
            # 降级：规则化诊断（不依赖 LLM）
            return self._rule_based_diagnosis(trigger_reason, trigger_stage, diag_data)

    def _rule_based_diagnosis(
        self, trigger_reason: str, trigger_stage: str, diag_data: dict
    ) -> dict:
        """降级诊断（LLM 不可用时）"""
        stage_stats = diag_data.get("stage_stats", {})
        recommendations = []

        # 找出最差的阶段
        worst_stage = trigger_stage
        worst_info = stage_stats.get(trigger_stage, {})
        if isinstance(worst_info, dict):
            if worst_info.get("error_rate", 0) > 0.3:
                recommendations.append(
                    f"阶段 '{trigger_stage}' 错误率过高 "
                    f"({worst_info.get('error_rate', 0):.0%})，"
                    f"最近错误: {worst_info.get('last_error', '未知')}"
                )
            if worst_info.get("p95_latency_ms", 0) > 30000:
                recommendations.append(
                    f"阶段 '{trigger_stage}' P95 延迟过高 "
                    f"({worst_info.get('p95_latency_ms', 0):.0f}ms)，"
                    f"检查 LLM API 或 SSH 连接"
                )

        # 卡死检测
        active = diag_data.get("active_spans", [])
        stuck = [s for s in active if s.get("running_seconds", 0) > 120]
        if stuck:
            recommendations.append(
                f"{len(stuck)} 个 span 卡死超过 120s，"
                f"涉及阶段: {', '.join(s.get('stage', '?') for s in stuck)}"
            )

        # 熔断器
        cb = diag_data.get("circuit_breaker", {})
        if cb.get("tripped"):
            recommendations.append(f"CAD 熔断器已触发: {cb.get('reason', '')}")

        if not recommendations:
            recommendations.append("需人工排查，自动诊断信息不足")

        return {
            "root_cause": f"阶段 '{trigger_stage}' 异常 (规则诊断)",
            "narrative": f"触发原因: {trigger_reason}。" + " ".join(recommendations),
            "recommendations": recommendations,
            "severity": "high" if stuck else "medium",
            "affected_component": trigger_stage,
            "auto_recoverable": False,
        }

    def _assess_severity(self, diag_data: dict) -> str:
        """评估整体严重度"""
        active = diag_data.get("active_spans", [])
        stuck = [s for s in active if s.get("running_seconds", 0) > 120]
        if stuck:
            return "critical"

        stats = diag_data.get("stage_stats", {})
        for stage, st in stats.items():
            if isinstance(st, dict):
                if st.get("error_rate", 0) > 0.5:
                    return "critical"
                if st.get("status") == "red":
                    return "high"
        return "medium"

    async def _output_report(self, report: dict):
        """三通道输出诊断报告"""
        # 通道 1: SSE 推送
        try:
            from event_bus import event_bus
            event_bus.publish("pipeline_health", {
                "type": "diagnostic",
                "severity": report["severity"],
                "trigger": report["trigger_reason"],
                "root_cause": report["root_cause"],
                "recommendations": report["recommendations"][:3],
                "timestamp": report["created_at"],
            })
        except Exception as e:
            logger.debug(f"[Watchdog] SSE publish failed: {e}")

        # 通道 2: DB 持久化
        try:
            from models import async_session as db_session, DiagnosticReport

            async def _persist():
                try:
                    async with db_session() as session:
                        session.add(DiagnosticReport(
                            trigger_reason=report["trigger_reason"][:200],
                            trigger_stage=report.get("trigger_stage", "")[:50],
                            severity=report["severity"][:20],
                            stage_metrics=report.get("stage_metrics", {}),
                            root_cause=report.get("root_cause", "")[:2000],
                            recommendations=report.get("recommendations", []),
                            llm_analysis=report.get("llm_analysis", "")[:5000],
                            affected_event_count=report.get("affected_event_count", 0),
                        ))
                        await session.commit()
                except Exception as e:
                    logger.warning(f"[Watchdog] DB persist failed: {e}")

            loop = asyncio.get_running_loop()
            loop.create_task(_persist())
        except Exception as e:
            logger.debug(f"[Watchdog] DB persist setup failed: {e}")

        # 通道 3: 告警通知
        if report["severity"] in ("critical", "high"):
            try:
                from response_engine.response_registry import response_registry
                await response_registry.execute(
                    "send_alert",
                    title=f"[Watchdog] 流水线诊断: {report['severity'].upper()}",
                    message=(
                        f"触发: {report['trigger_reason']}\n"
                        f"根因: {report['root_cause']}\n"
                        f"建议: {'; '.join(report['recommendations'][:2])}"
                    ),
                    severity=report["severity"],
                    channel="webhook",
                )
            except Exception as e:
                logger.debug(f"[Watchdog] Alert send failed: {e}")

    def get_status(self) -> dict:
        """获取 Watchdog 状态"""
        return {
            "diagnose_count": self._diagnose_count,
            "last_diagnose_time": self._last_diagnose_time,
            "cooldown_seconds": self._diagnose_cooldown,
        }


watchdog = WatchdogAgent()
