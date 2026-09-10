"""
控制面安全 (PR1): 审批工单 HMAC 签名 + TTL 分级 + 过期/防重放/防篡改

配合 backend/security_crypto.py (sign_approval / verify_approval / actions_digest)
与 config 中 approval_ttl_minutes / approval_ttl_critical_minutes。

运行: python -m pytest tests/test_control_plane_security.py -q --tb=short (cwd=backend)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from response_engine.human_approval import ApprovalStatus, approval_queue
from security_crypto import actions_digest

# 固定 TTL 档位, 不依赖运行环境 .env (config 默认即 15/10)
_NORMAL_MIN = 15
_CRITICAL_MIN = 10


@pytest.fixture(autouse=True)
def _pin_ttl_settings():
    from config import settings
    saved = (settings.approval_ttl_minutes, settings.approval_ttl_critical_minutes)
    settings.approval_ttl_minutes = _NORMAL_MIN
    settings.approval_ttl_critical_minutes = _CRITICAL_MIN
    yield
    settings.approval_ttl_minutes, settings.approval_ttl_critical_minutes = saved


@pytest.fixture(autouse=True)
def _clean_queue():
    approval_queue._tickets.clear()
    yield
    approval_queue._tickets.clear()


def _submit(name: str = "send_alert", policy: str = "test.response_policy"):
    return approval_queue.submit(
        threat_info={"threat_type": "TEST", "severity": "high", "src_ip": "10.0.0.5"},
        policy_name=policy,
        actions=[{"name": name, "params": {"host": "10.0.0.5"}}],
    )


class TestApprovalTTL:
    def test_isolate_host_uses_critical_ttl(self):
        """隔离类动作(CRITICAL) → 采用 approval_ttl_critical_minutes(10min)。"""
        t = _submit(name="isolate_host")
        assert t.expires_at - t.created_at == pytest.approx(_CRITICAL_MIN * 60, abs=0.01)
        assert t.actions_digest == actions_digest(t.actions)
        assert len(t.sig) == 64, "submit 必须签发 64 位 HMAC 签名"

    def test_disable_account_uses_critical_ttl(self):
        """禁用账户动作(CRITICAL) → critical 档 TTL。"""
        t = _submit(name="disable_account")
        assert t.expires_at - t.created_at == pytest.approx(_CRITICAL_MIN * 60, abs=0.01)

    def test_regular_action_uses_normal_ttl(self):
        """普通动作 → 普通档 TTL(approval_ttl_minutes=15min)。"""
        t = _submit(name="send_alert")
        assert t.expires_at - t.created_at == pytest.approx(_NORMAL_MIN * 60, abs=0.01)


class TestApproveGate:
    def test_valid_approve_works(self):
        t = _submit()
        out = approval_queue.approve(t.id, "secadmin")
        assert out is not None
        assert out.status == ApprovalStatus.APPROVED
        assert out.approved_by == "secadmin"
        assert out.approved_at > 0

    def test_approve_after_expiry_returns_none_and_marks_expired(self):
        """过期工单 → 拒绝并置 EXPIRED(此前缺失的过期检查)。"""
        t = _submit()
        t.expires_at = time.time() - 1
        assert approval_queue.approve(t.id, "admin") is None
        assert t.status == ApprovalStatus.EXPIRED

    def test_approve_tampered_actions_returns_none(self):
        """提交后篡改 actions → digest 重算不一致, 拒绝。"""
        t = _submit()
        t.actions.append({"name": "isolate_host", "params": {"host": "10.0.0.6"}})
        assert approval_queue.approve(t.id, "admin") is None
        assert t.status == ApprovalStatus.PENDING, "篡改不应改变工单状态"

    def test_approve_twice_second_returns_none(self):
        """同一工单二次批准(重放) → 拒绝。"""
        t = _submit()
        first = approval_queue.approve(t.id, "secadmin")
        assert first is not None and first.status == ApprovalStatus.APPROVED
        assert approval_queue.approve(t.id, "admin") is None

    def test_approve_with_wrong_external_sig_returns_none(self):
        """外部传入错误签名 → HMAC 校验失败, 拒绝。"""
        t = _submit()
        assert approval_queue.approve(t.id, "admin", sig="0" * 64) is None
        assert t.status == ApprovalStatus.PENDING

    def test_approve_with_matching_external_sig_works(self):
        """外部审批人回传 submit 时签发的 sig → 批准成功。"""
        t = _submit()
        out = approval_queue.approve(t.id, "admin", sig=t.sig)
        assert out is not None and out.status == ApprovalStatus.APPROVED


class TestRejectGate:
    def test_reject_expired_refused(self):
        t = _submit()
        t.expires_at = time.time() - 1
        assert approval_queue.reject(t.id, "too late") is None
        assert t.status == ApprovalStatus.EXPIRED

    def test_reject_already_processed_refused(self):
        t = _submit()
        approval_queue.approve(t.id, "admin")
        assert approval_queue.reject(t.id, "after approve") is None
        assert t.status == ApprovalStatus.APPROVED

    def test_reject_valid_pending_ok(self):
        t = _submit()
        out = approval_queue.reject(t.id, "false positive", "secadmin")
        assert out is not None and out.status == ApprovalStatus.REJECTED
