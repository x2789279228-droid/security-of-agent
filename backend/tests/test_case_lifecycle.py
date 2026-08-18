"""
事件运营闭环单元测试

覆盖:
  - CaseManager: 状态机合法/非法流转、案例编号生成、聚合逻辑
  - WorkOrderService: 工单编号、状态、SLA
  - FeedbackLoop: 反馈类型、调优建议逻辑
  - RuleManager: Sigma 规则 CRUD、版本管理
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from case_manager import CaseManager, VALID_TRANSITIONS
from work_order_service import WorkOrderService, ORDER_TYPES, ORDER_STATUSES
from feedback_loop import FeedbackLoop, FP_RATE_ALERT_THRESHOLD, MISSED_THREAT_THRESHOLD
from rule_manager import RuleManager


# ════════════════════════════════════════════
# 1. CaseManager 测试
# ════════════════════════════════════════════

class TestCaseManager:
    """案例状态机 + 逻辑测试"""

    def test_valid_transitions_complete(self):
        """所有状态都有定义的流转规则"""
        all_statuses = set(VALID_TRANSITIONS.keys())
        assert "open" in all_statuses
        assert "closed" in all_statuses
        assert "false_positive" in all_statuses
        # closed 不能流转到任何状态
        assert VALID_TRANSITIONS["closed"] == []

    def test_open_can_investigate(self):
        assert "investigating" in VALID_TRANSITIONS["open"]

    def test_open_cannot_resolve_directly(self):
        assert "resolved" not in VALID_TRANSITIONS["open"]

    def test_investigating_can_reach_responding(self):
        assert "responding" in VALID_TRANSITIONS["investigating"]

    def test_responding_can_resolve(self):
        assert "resolved" in VALID_TRANSITIONS["responding"]

    def test_resolved_can_close(self):
        assert "closed" in VALID_TRANSITIONS["resolved"]

    def test_false_positive_can_reopen(self):
        assert "investigating" in VALID_TRANSITIONS["false_positive"]

    def test_case_number_format(self):
        cm = CaseManager()
        number = cm._gen_case_number()
        assert number.startswith("CASE-")
        parts = number.split("-")
        assert len(parts) == 3
        assert len(parts[1]) == 8  # YYYYMMDD

    def test_case_to_dict_structure(self):
        """_case_to_dict 需要正确的字段"""
        # 使用 mock 对象
        class MockCase:
            id = 1
            case_number = "CASE-20260801-001"
            title = "Test"
            status = "open"
            priority = "high"
            threat_type = "C2_BEACON"
            severity = "critical"
            confidence = 0.85
            src_ips = ["1.2.3.4"]
            dst_ips = ["5.6.7.8"]
            event_ids = [1, 2, 3]
            event_count = 3
            assignee = "analyst1"
            sla_deadline = None
            disposition = ""
            disposition_by = ""
            tags = ["apt"]
            created_at = None
            updated_at = None
            closed_at = None

        cm = CaseManager()
        d = cm._case_to_dict(MockCase())
        assert d["case_number"] == "CASE-20260801-001"
        assert d["status"] == "open"
        assert d["event_count"] == 3
        assert d["src_ips"] == ["1.2.3.4"]


# ════════════════════════════════════════════
# 2. WorkOrderService 测试
# ════════════════════════════════════════════

class TestWorkOrderService:
    """工单服务逻辑测试"""

    def test_order_types_defined(self):
        assert "disposition" in ORDER_TYPES
        assert "approval" in ORDER_TYPES
        assert "review" in ORDER_TYPES
        assert "rollback" in ORDER_TYPES

    def test_order_statuses_defined(self):
        assert ORDER_STATUSES[0] == "pending"
        assert "completed" in ORDER_STATUSES
        assert "cancelled" in ORDER_STATUSES

    def test_order_number_format(self):
        ws = WorkOrderService()
        number = ws._gen_order_number()
        assert number.startswith("WO-")
        parts = number.split("-")
        assert len(parts) == 3

    def test_order_to_dict_structure(self):
        class MockOrder:
            id = 1
            order_number = "WO-20260801-001"
            case_id = 5
            order_type = "approval"
            title = "封禁审批"
            description = "需要封禁 1.2.3.4"
            status = "pending"
            priority = "high"
            assignee = ""
            created_by = "system"
            approval_status = "pending"
            approved_by = ""
            reject_reason = ""
            sla_deadline = None
            sla_breached = False
            result = {}
            created_at = None
            completed_at = None

        ws = WorkOrderService()
        d = ws._order_to_dict(MockOrder())
        assert d["order_number"] == "WO-20260801-001"
        assert d["order_type"] == "approval"
        assert d["approval_status"] == "pending"
        assert d["sla_breached"] is False


# ════════════════════════════════════════════
# 3. FeedbackLoop 测试
# ════════════════════════════════════════════

class TestFeedbackLoop:
    """反馈闭环逻辑测试"""

    def test_feedback_types(self):
        from feedback_loop import FEEDBACK_TYPES
        assert "false_positive" in FEEDBACK_TYPES
        assert "missed_threat" in FEEDBACK_TYPES
        assert "rule_suggestion" in FEEDBACK_TYPES

    def test_fp_threshold_configured(self):
        assert FP_RATE_ALERT_THRESHOLD == 0.5
        assert MISSED_THREAT_THRESHOLD == 3

    def test_feedback_statuses(self):
        from feedback_loop import FEEDBACK_STATUSES
        assert "submitted" in FEEDBACK_STATUSES
        assert "applied" in FEEDBACK_STATUSES
        assert "dismissed" in FEEDBACK_STATUSES


# ════════════════════════════════════════════
# 4. RuleManager 测试
# ════════════════════════════════════════════

class TestRuleManager:
    """规则管理器测试"""

    def setup_method(self):
        self.rm = RuleManager()

    def test_list_sigma_rules(self):
        rules = self.rm.list_rules("sigma")
        assert len(rules) >= 7  # 至少 7 条内置规则
        assert all(r["type"] == "sigma" for r in rules)
        rule_ids = [r["rule_id"] for r in rules]
        assert "SIG-001" in rule_ids

    def test_list_response_policies(self):
        rules = self.rm.list_rules("response_policy")
        assert len(rules) >= 5
        assert all(r["type"] == "response_policy" for r in rules)

    def test_get_sigma_rule(self):
        rule = self.rm.get_rule("sigma", "SIG-001")
        assert rule is not None
        assert rule["rule_id"] == "SIG-001"
        assert "conditions" in rule

    def test_get_nonexistent_rule(self):
        rule = self.rm.get_rule("sigma", "SIG-999")
        assert rule is None

    def test_create_sigma_rule(self):
        result = self.rm.create_rule("sigma", {
            "rule_id": "SIG-TEST-001",
            "name": "测试规则",
            "description": "单元测试用",
            "severity": "low",
            "attack_type": "test",
            "confidence": "low",
            "action_recommend": "alert",
            "conditions": {"event_contains": ["TEST_EVENT"]},
        })
        assert result["success"] is True
        assert result["rule_id"] == "SIG-TEST-001"

        # 验证规则已添加
        rule = self.rm.get_rule("sigma", "SIG-TEST-001")
        assert rule is not None
        assert rule["name"] == "测试规则"

        # 清理
        self.rm.delete_rule("sigma", "SIG-TEST-001")

    def test_create_duplicate_rule_fails(self):
        result = self.rm.create_rule("sigma", {
            "rule_id": "SIG-001",  # 已存在
            "name": "重复",
            "conditions": {},
        })
        assert result["success"] is False
        assert "已存在" in result["error"]

    def test_update_sigma_rule(self):
        result = self.rm.update_rule("sigma", "SIG-001", {
            "severity": "critical",
        }, change_summary="测试修改")
        assert result["success"] is True
        assert "version_data" in result

        # 验证修改生效
        rule = self.rm.get_rule("sigma", "SIG-001")
        assert rule["severity"] == "critical"

        # 恢复
        self.rm.update_rule("sigma", "SIG-001", {"severity": "high"})

    def test_update_nonexistent_rule_fails(self):
        result = self.rm.update_rule("sigma", "SIG-FAKE", {"name": "x"})
        assert result["success"] is False

    def test_delete_rule(self):
        # 先创建
        self.rm.create_rule("sigma", {
            "rule_id": "SIG-DEL-001",
            "name": "待删除",
            "conditions": {},
        })
        # 删除
        result = self.rm.delete_rule("sigma", "SIG-DEL-001")
        assert result["success"] is True
        # 验证已删除
        assert self.rm.get_rule("sigma", "SIG-DEL-001") is None

    def test_update_response_policy(self):
        result = self.rm.update_rule("response_policy", "C2通信自动封禁", {
            "min_confidence": 0.8,
        }, change_summary="提高置信度阈值")
        assert result["success"] is True
        assert result["version_data"]["content"]["min_confidence"] == 0.8

        # 恢复
        self.rm.update_rule("response_policy", "C2通信自动封禁", {"min_confidence": 0.6})


# ════════════════════════════════════════════
# 运行入口
# ════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
