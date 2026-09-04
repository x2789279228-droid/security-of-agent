"""
自动封禁链路回归: threat_type 语义推断 + 审计断链补齐 + Uncertain 遏制

修复前: 上游日志 name 为自然语言("C2 通信"), _normalize_fields 只做字段改名
        不推断语义; 审计产出的 threat_type(中文词表)在 audit_full/_audit_llm
        组装落库时被丢弃; orchestrator 收到的 threat_type 退化为中文事件名,
        策略层匹配不上英文枚举, 静默 matched=False 或落入 ANY 兜底。
修复后: _normalize_fields 推断 threat_type 枚举; audit_full/save_result 保留
        并转换为策略层枚举; orchestrator 兜底链 threat_type→event→按名推断;
        未知类型走 Uncertain(5分钟短封 + P1 工单), 不再静默放过。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from correlation_engine import infer_threat_type
from log_ingestion import log_ingestor


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── infer_threat_type: 自然语言/中文词表 → 策略层枚举 ──

def test_infer_c2_with_space():
    # 上游告警名带空格, ZH_EVENT_MAP 精确匹配失败 → 去空格后命中
    assert infer_threat_type("C2 通信") == "C2_BEACON"


def test_infer_exact_zh_map():
    # L1: 凭据类未授权读取归 UNAUTHORIZED_ACCESS，不再误标 DATA_EXFIL
    assert infer_threat_type("未授权获取密码信息") == "UNAUTHORIZED_ACCESS"
    assert infer_threat_type("登录弱密码") == "BRUTE_FORCE"


def test_infer_audit_chinese_vocab():
    # Executor 审计结论使用 audit_schemas.VALID_THREAT_TYPES 中文词表
    assert infer_threat_type("数据外泄") == "DATA_EXFIL"
    assert infer_threat_type("C2") == "C2_BEACON"
    assert infer_threat_type("勒索软件") == "RANSOMWARE"


def test_infer_webshell_and_unmatched():
    assert infer_threat_type("WebShell攻击") == "MALWARE_DETECT"
    assert infer_threat_type("自定义无关事件") == ""
    assert infer_threat_type("") == ""
    assert infer_threat_type(None) == ""


def test_infer_enum_idempotent():
    # 已是枚举值时保持不变(orchestrator 兜底链幂等)
    assert infer_threat_type("C2_BEACON") == "C2_BEACON"
    assert infer_threat_type("DATA_EXFIL") == "DATA_EXFIL"


# ── _normalize_fields: 归一化阶段产出 threat_type ──

def test_normalize_infers_threat_type():
    n = log_ingestor._normalize_fields({
        "name": "C2 通信", "severity": "high",
        "srcIp": "1.2.3.4", "message": "x",
    })
    assert n["event"] == "C2 通信"
    assert n["threat_type"] == "C2_BEACON"


def test_normalize_respects_explicit_threat_type():
    # 上游已显式提供枚举时尊重不覆盖
    n = log_ingestor._normalize_fields({
        "name": "C2 通信", "threat_type": "C2_BEACON",
        "severity": "high", "message": "x",
    })
    assert n["threat_type"] == "C2_BEACON"


# ── 审计断链: audit_full 携带 threat_type, save_result 转枚举注入 merged ──

import pytest

try:
    import temporalio  # noqa: F401
    _HAS_TEMPORALIO = True
except ImportError:
    _HAS_TEMPORALIO = False

_NEED_TEMPORALIO = pytest.mark.skipif(
    not _HAS_TEMPORALIO, reason="环境未安装 temporalio, Temporal 活动不可测"
)

def _fake_round(threat_type_raw: str) -> dict:
    return {
        "round": 1, "mode": "full",
        "audit": {"threat_detected": True, "confidence": 0.8},
        "audit_full": {
            "grounding_score": 1.0, "kb_verification": {}, "schema_valid": True,
            "confidence": 0.8, "threat_detected": True, "severity": "high",
            "needs_human_review": False, "threat_type": threat_type_raw,
        },
        "verdict_full": {"conclusion": "confirmed", "confidence": 0.8,
                         "final_summary": "x"},
        "missed_threats": [], "evidence": [],
    }


@_NEED_TEMPORALIO
def test_save_result_injects_threat_type_into_merged():
    from temporal import activities

    async def _inner():
        # 事件 ID 不存在 → 跳过 DB 写入, 但 merged 注入逻辑仍生效
        return await activities.save_result({
            "event_id": 99999999,
            "log_data": {"event": "未授权获取密码信息", "severity": "high",
                         "src_ip": "9.9.9.5"},
            "all_rounds": [_fake_round("数据外泄")],
            "final_verdict": {},
            "max_rounds": 1,
        })

    merged = _run(_inner())
    assert merged["threat_type"] == "DATA_EXFIL"


@_NEED_TEMPORALIO
def test_save_result_falls_back_to_log_name():
    from temporal import activities

    async def _inner():
        return await activities.save_result({
            "event_id": 99999999,
            "log_data": {"event": "C2 通信", "severity": "critical"},
            "all_rounds": [_fake_round("")],  # 审计未给出 → 回退日志侧推断
            "final_verdict": {},
            "max_rounds": 1,
        })

    merged = _run(_inner())
    assert merged["threat_type"] == "C2_BEACON"


# ── 策略层: Uncertain 遏制含 block_ip(5min) 且不触发 CRITICAL 强制审批 ──

from response_engine.response_policies import (
    MatchStatus, UNCERTAIN_POLICY_NAME, policy_engine,
)
from response_engine.response_registry import has_critical_action


def test_uncertain_contains_block_ip_5min():
    policy_engine.clear_cooldowns()
    am = policy_engine.match(
        threat_type="SOMETHING_ELSE", confidence=0.9, severity="high",
        src_ip="9.9.9.9",
    )
    assert am.matched
    assert am.match_status == MatchStatus.UNCERTAIN
    assert am.policy_name == UNCERTAIN_POLICY_NAME
    names = [a["name"] for a in am.actions]
    assert "send_alert" in names and "block_ip" in names
    block = next(a for a in am.actions if a["name"] == "block_ip")
    assert block["params"]["duration_minutes"] == 5


def test_block_ip_high_not_critical_auto_executable():
    # HIGH 动作不触发强制审批: has_critical_action=False → orchestrator 在
    # 策略 auto_execute=True 时走"先执行 + 补录 AUTO_EXECUTED 工单"分支
    actions = [
        {"name": "send_alert", "params": {}},
        {"name": "block_ip", "params": {"duration_minutes": 5}},
    ]
    assert has_critical_action(actions) is False
    policy_engine.clear_cooldowns()
    am = policy_engine.match(
        threat_type="UNKNOWN_TYPE", confidence=0.9, severity="high",
        src_ip="9.9.9.8",
    )
    assert am.matched
    assert am.match_status == MatchStatus.UNCERTAIN
    assert am.auto_execute is True
    assert am.needs_approval is True


def test_c2_policy_takes_precedence_over_uncertain():
    policy_engine.clear_cooldowns()
    am = policy_engine.match(
        threat_type="C2_BEACON", confidence=0.85, severity="critical",
        src_ip="9.9.9.7",
    )
    assert am.matched
    assert am.match_status == MatchStatus.MATCHED
    assert am.policy_name == "C2通信自动封禁"
    assert am.actions[0]["name"] == "block_ip"


# ── orchestrator 兜底链: threat_type 为空时从 event 名推断 ──

def test_orchestrator_resolves_threat_type_from_event_name():
    from response_engine import response_orchestrator as ro_mod

    captured = {}

    class _FakeUnmatched:
        matched = False
        policy_name = ""
        actions = []
        needs_approval = False
        auto_execute = False
        match_status = MatchStatus.NO_ACTION
        skip_reason = "test_fake"
        category = ""

    def fake_match(**kwargs):
        captured.update(kwargs)
        return _FakeUnmatched()

    orig = ro_mod.policy_engine
    ro_mod.policy_engine = type("PE", (), {"match": staticmethod(fake_match)})()
    try:
        result = _run(ro_mod.response_orchestrator.on_threat_detected(
            session=None,
            threat_info={
                "threat_type": "", "event": "C2 通信",
                "confidence": 0.9, "severity": "high", "src_ip": "9.9.9.6",
            },
        ))
    finally:
        ro_mod.policy_engine = orig

    assert result["matched"] is False  # 未命中即返回, 不触执行路径
    assert result["match_status"] == "no_action"
    assert captured["threat_type"] == "C2_BEACON"
