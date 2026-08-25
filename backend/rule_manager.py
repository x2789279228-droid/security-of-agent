"""
规则管理器 (Rule Manager)

Sigma 检测规则 + 响应策略的 CRUD、版本管理、沙箱测试。

能力:
  - CRUD: 列出/查看/新增/修改/禁用规则
  - 版本管理: 每次修改自动创建版本快照，支持回滚
  - 沙箱测试: 用历史事件回放测试新规则的命中率/误报率
  - 调优集成: 代理调用 feedback_loop 的调优建议

调用方式:
    from rule_manager import rule_manager
    rules = rule_manager.list_rules("sigma")
    rule_manager.update_rule("sigma", "SIG-001", new_content, "提高阈值")
"""
import logging
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import RuleVersion, SecurityEvent, FeedbackRecord

logger = logging.getLogger(__name__)


class RuleManager:
    """规则管理器"""

    # ── CRUD ──

    def list_rules(self, rule_type: str = "sigma") -> list[dict]:
        """列出规则"""
        if rule_type == "sigma":
            from sigma_detector import sigma_detector
            if hasattr(sigma_detector, "reload"):   # pySigma 引擎: 读 YAML 文件
                from sigma_engine import store
                return store.list_rules()
            return [
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "description": r.description,
                    "severity": r.severity,
                    "attack_type": r.attack_type,
                    "confidence": r.confidence,
                    "action_recommend": r.action_recommend,
                    "conditions": r.conditions,
                    "type": "sigma",
                }
                for r in sigma_detector.rules
            ]
        elif rule_type == "response_policy":
            from response_engine.response_policies import policy_engine
            return [
                {
                    "rule_id": p.name,
                    "name": p.name,
                    "description": p.description,
                    "severity": p.min_severity,
                    "threat_type": p.threat_type,
                    "auto_execute": p.auto_execute,
                    "require_approval": p.require_approval,
                    "priority": p.priority,
                    "type": "response_policy",
                }
                for p in policy_engine.get_policies()
            ]
        return []

    def get_rule(self, rule_type: str, rule_id: str) -> Optional[dict]:
        """获取规则详情"""
        if rule_type == "sigma":
            from sigma_detector import sigma_detector
            if hasattr(sigma_detector, "reload"):   # pySigma: 从 YAML
                from sigma_engine import store
                data = store.get_rule(rule_id)
                return data or None
            for r in sigma_detector.rules:
                if r.rule_id == rule_id:
                    return asdict(r)
        elif rule_type == "response_policy":
            from response_engine.response_policies import policy_engine
            p = policy_engine.get_policy(rule_id)
            if p:
                return {
                    "name": p.name,
                    "threat_type": p.threat_type,
                    "actions": p.actions,
                    "min_confidence": p.min_confidence,
                    "min_severity": p.min_severity,
                    "auto_execute": p.auto_execute,
                    "require_approval": p.require_approval,
                    "priority": p.priority,
                    "cooldown_minutes": p.cooldown_minutes,
                    "description": p.description,
                }
        return None

    def create_rule(
        self, rule_type: str, content: dict, changed_by: str = "admin"
    ) -> dict:
        """新增规则"""
        if rule_type == "sigma":
            from sigma_detector import sigma_detector
            if hasattr(sigma_detector, "reload"):   # pySigma: 写 YAML + 重载编译
                from sigma_engine import store
                result = store.create_rule(content, changed_by=changed_by)
                if result["success"]:
                    sigma_detector.reload()
                return result
            from sigma_detector import SigmaRule
            rule_id = content.get("rule_id", f"SIG-{len(sigma_detector.rules)+1:03d}")
            # 检查重复
            if any(r.rule_id == rule_id for r in sigma_detector.rules):
                return {"success": False, "error": f"规则 {rule_id} 已存在"}

            new_rule = SigmaRule(
                rule_id=rule_id,
                name=content.get("name", ""),
                description=content.get("description", ""),
                severity=content.get("severity", "medium"),
                attack_type=content.get("attack_type", "custom"),
                confidence=content.get("confidence", "medium"),
                action_recommend=content.get("action_recommend", "alert"),
                conditions=content.get("conditions", {}),
            )
            sigma_detector.rules.append(new_rule)
            logger.info(f"[RuleManager] Created sigma rule: {rule_id}")
            return {"success": True, "rule_id": rule_id, "version": 1}

        return {"success": False, "error": f"不支持的规则类型: {rule_type}"}

    def update_rule(
        self, rule_type: str, rule_id: str,
        content: dict, change_summary: str = "",
        changed_by: str = "admin",
    ) -> dict:
        """修改规则（同步更新内存 + 返回待持久化的版本数据）"""
        if rule_type == "sigma":
            from sigma_detector import sigma_detector
            if hasattr(sigma_detector, "reload"):   # pySigma: 写 YAML + 重载
                from sigma_engine import store
                result = store.update_rule(
                    rule_id, content, changed_by=changed_by)
                if result["success"]:
                    sigma_detector.reload()
                    return {
                        "success": True,
                        "rule_id": rule_id,
                        "change_summary": change_summary,
                        "version_data": {
                            "rule_type": "sigma",
                            "rule_id": rule_id,
                            "content": store.get_rule(rule_id) or {},
                            "change_summary": change_summary,
                            "changed_by": changed_by,
                        },
                    }
                return result
            for i, r in enumerate(sigma_detector.rules):
                if r.rule_id == rule_id:
                    # 更新字段
                    for key in ["name", "description", "severity", "attack_type",
                                "confidence", "action_recommend", "conditions"]:
                        if key in content:
                            setattr(sigma_detector.rules[i], key, content[key])
                    logger.info(f"[RuleManager] Updated sigma rule: {rule_id}")
                    return {
                        "success": True,
                        "rule_id": rule_id,
                        "change_summary": change_summary,
                        "version_data": {
                            "rule_type": "sigma",
                            "rule_id": rule_id,
                            "content": asdict(sigma_detector.rules[i]),
                            "change_summary": change_summary,
                            "changed_by": changed_by,
                        },
                    }
            return {"success": False, "error": f"规则 {rule_id} 不存在"}

        elif rule_type == "response_policy":
            from response_engine.response_policies import policy_engine
            policy = policy_engine.get_policy(rule_id)
            if not policy:
                return {"success": False, "error": f"策略 {rule_id} 不存在"}

            for key in ["min_confidence", "min_severity", "auto_execute",
                        "require_approval", "cooldown_minutes", "priority"]:
                if key in content:
                    setattr(policy, key, content[key])

            return {
                "success": True,
                "rule_id": rule_id,
                "change_summary": change_summary,
                "version_data": {
                    "rule_type": "response_policy",
                    "rule_id": rule_id,
                    "content": {
                        "name": policy.name,
                        "threat_type": policy.threat_type,
                        "actions": policy.actions,
                        "min_confidence": policy.min_confidence,
                        "min_severity": policy.min_severity,
                        "auto_execute": policy.auto_execute,
                        "require_approval": policy.require_approval,
                        "priority": policy.priority,
                        "cooldown_minutes": policy.cooldown_minutes,
                    },
                    "change_summary": change_summary,
                    "changed_by": changed_by,
                },
            }

        return {"success": False, "error": f"不支持的规则类型: {rule_type}"}

    def delete_rule(self, rule_type: str, rule_id: str) -> dict:
        """禁用规则（软删除）"""
        if rule_type == "sigma":
            from sigma_detector import sigma_detector
            if hasattr(sigma_detector, "reload"):   # pySigma: 删 YAML + 重载
                from sigma_engine import store
                result = store.delete_rule(rule_id)
                if result["success"]:
                    sigma_detector.reload()
                return result
            sigma_detector.rules = [
                r for r in sigma_detector.rules if r.rule_id != rule_id
            ]
            logger.info(f"[RuleManager] Removed sigma rule: {rule_id}")
            return {"success": True, "rule_id": rule_id}
        return {"success": False, "error": "仅支持 sigma 规则删除"}

    # ── 版本管理 ──

    async def save_version(
        self, session: AsyncSession, version_data: dict
    ) -> dict:
        """保存规则版本到 DB"""
        rule_type = version_data.get("rule_type", "sigma")
        rule_id = version_data.get("rule_id", "")

        # 查找当前最大版本号
        stmt = (
            select(RuleVersion)
            .where(
                RuleVersion.rule_type == rule_type,
                RuleVersion.rule_id == rule_id,
            )
            .order_by(desc(RuleVersion.version))
            .limit(1)
        )
        result = await session.execute(stmt)
        latest = result.scalars().first()
        new_version = (latest.version + 1) if latest else 1

        # 将旧版本标记为非活跃
        if latest:
            latest.is_active = False

        version = RuleVersion(
            rule_type=rule_type,
            rule_id=rule_id,
            version=new_version,
            content=version_data.get("content", {}),
            change_summary=version_data.get("change_summary", ""),
            changed_by=version_data.get("changed_by", ""),
            is_active=True,
        )
        session.add(version)
        await session.commit()
        logger.info(f"[RuleManager] Saved version {new_version} for {rule_type}/{rule_id}")
        return {"success": True, "version": new_version}

    async def get_versions(
        self, session: AsyncSession, rule_type: str, rule_id: str
    ) -> list[dict]:
        stmt = (
            select(RuleVersion)
            .where(
                RuleVersion.rule_type == rule_type,
                RuleVersion.rule_id == rule_id,
            )
            .order_by(desc(RuleVersion.version))
        )
        result = await session.execute(stmt)
        return [
            {
                "id": v.id,
                "version": v.version,
                "change_summary": v.change_summary,
                "changed_by": v.changed_by,
                "is_active": v.is_active,
                "created_at": v.created_at.isoformat() if v.created_at else "",
            }
            for v in result.scalars().all()
        ]

    async def rollback(
        self, session: AsyncSession, rule_type: str, rule_id: str,
        target_version: int, changed_by: str = "admin",
    ) -> dict:
        """回滚到指定版本"""
        stmt = (
            select(RuleVersion)
            .where(
                RuleVersion.rule_type == rule_type,
                RuleVersion.rule_id == rule_id,
                RuleVersion.version == target_version,
            )
        )
        result = await session.execute(stmt)
        target = result.scalars().first()
        if not target:
            return {"success": False, "error": f"版本 {target_version} 不存在"}

        # 应用旧版本内容到内存
        content = target.content or {}
        apply_result = self.update_rule(
            rule_type, rule_id, content,
            change_summary=f"回滚到版本 {target_version}",
            changed_by=changed_by,
        )
        if not apply_result.get("success"):
            return apply_result

        # 保存为新版本
        version_data = apply_result.get("version_data", {})
        version_data["change_summary"] = f"回滚到版本 {target_version}"
        await self.save_version(session, version_data)

        return {"success": True, "rolled_back_to": target_version}

    # ── 沙箱测试 ──

    async def sandbox_test(
        self, session: AsyncSession,
        rule_content: dict, event_ids: list[int] = None,
        limit: int = 100,
    ) -> dict:
        """
        沙箱测试: 用历史事件回放测试新规则

        Returns:
            {hit_count, total_tested, hit_rate, false_positive_count, fp_rate, hits[]}
        """
        from sigma_detector import SigmaDetector, SigmaRule

        # 构建临时规则
        test_rule = SigmaRule(
            rule_id="SANDBOX-TEST",
            name=rule_content.get("name", "sandbox"),
            description=rule_content.get("description", ""),
            severity=rule_content.get("severity", "medium"),
            attack_type=rule_content.get("attack_type", "test"),
            confidence=rule_content.get("confidence", "medium"),
            action_recommend=rule_content.get("action_recommend", "alert"),
            conditions=rule_content.get("conditions", {}),
        )

        # 创建临时检测器
        detector = SigmaDetector.__new__(SigmaDetector)
        detector.rules = [test_rule]

        # 获取测试事件
        if event_ids:
            stmt = select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))
        else:
            stmt = (
                select(SecurityEvent)
                .order_by(desc(SecurityEvent.created_at))
                .limit(limit)
            )
        result = await session.execute(stmt)
        events = result.scalars().all()

        # 回放测试
        hits = []
        t_start = time.time()
        for evt in events:
            event_dict = {
                "event": evt.event_type,
                "type": evt.event_type,
                "severity": evt.severity,
                "src_ip": evt.src_ip,
                "dst_ip": evt.dst_ip,
                "message": evt.message or "",
                **(evt.raw_data or {}),
            }
            detections = detector.detect(event_dict)
            if detections:
                hits.append({
                    "event_id": evt.id,
                    "event_type": evt.event_type,
                    "src_ip": evt.src_ip,
                    "severity": evt.severity,
                    "status": evt.status,
                })

        elapsed_ms = (time.time() - t_start) * 1000

        # 检查误报（命中事件中有多少被标记为 false_positive）
        fp_count = sum(1 for h in hits if h.get("status") == "false_positive")

        return {
            "total_tested": len(events),
            "hit_count": len(hits),
            "hit_rate": round(len(hits) / max(len(events), 1), 4),
            "false_positive_count": fp_count,
            "fp_rate": round(fp_count / max(len(hits), 1), 4),
            "elapsed_ms": round(elapsed_ms, 1),
            "hits": hits[:20],
        }

    # ── 调优集成 ──

    async def get_tuning_suggestions(self, session: AsyncSession) -> list[dict]:
        from feedback_loop import feedback_loop
        return await feedback_loop.generate_tuning_suggestions(session)


rule_manager = RuleManager()
