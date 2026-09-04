"""
v5 修复回归: SIG-007 SSH 暴破规则条件语义 (AND) — 误封禁根因修复

修复前 (pySigma YAML): condition "1 of sel_*" (OR) — 仅 dst_port=22 即命中,
  正常 SSH 登录(USER_LOGIN 成功)被误判暴破 → FastPath 强信号路径误封禁
  良性用户 (2026-09-01 复现: 192.168.1.102/.103 被真实防火墙封禁)。
修复后: condition "sel_port and sel_event" — SSH 端口 AND 登录失败特征同时满足;
  legacy 内置规则同步改为 condition_mode="and" (降级路径语义一致)。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_detector import sigma_detector

ENGINE = type(sigma_detector).__name__


def _benign_login() -> dict:
    return {
        "event": "登录成功", "severity": "low",
        "src_ip": "10.7.0.1", "dst_ip": "192.168.1.10",
        "dst_port": 22, "protocol": "SSH",
        "message": "Normal SSH login success for ops user (office hours)",
    }


def test_benign_ssh_login_not_hit_sig007():
    """正常 SSH 登录成功(dst_port=22)不得命中 SIG-007(误封禁根因)。"""
    r = sigma_detector.detect_for_event(_benign_login())
    hits = [h for h in r.get("hits", []) if str(h.get("rule_id", "")).endswith("007")]
    assert not hits, f"正常登录不应命中 SSH 暴破规则 (engine={ENGINE}): {hits}"


def test_ssh_login_fail_hits_sig007():
    """登录失败(dst_port=22, SSH)应命中 SIG-007(AND 两条件同时满足)。"""
    evt = {
        "event": "登录失败", "severity": "high",
        "src_ip": "10.7.0.9", "dst_ip": "192.168.1.10",
        "dst_port": 22, "protocol": "SSH",
        "message": "SSH login failed for root (attempt 4)",
    }
    r = sigma_detector.detect_for_event(evt)
    hits = [h for h in r.get("hits", []) if str(h.get("rule_id", "")).endswith("007")]
    assert hits, f"SSH 登录失败应命中 SIG-007 (engine={ENGINE})"


def test_fail_pattern_on_wrong_port_not_hit():
    """AND 语义: 登录失败特征但非 SSH 端口不得命中 SIG-007。"""
    evt = {
        "event": "登录失败", "severity": "high",
        "src_ip": "10.7.0.3", "dst_ip": "192.168.1.20",
        "dst_port": 8080, "protocol": "HTTP",
        "message": "login failed on web console",
    }
    r = sigma_detector.detect_for_event(evt)
    hits = [h for h in r.get("hits", []) if str(h.get("rule_id", "")).endswith("007")]
    assert not hits, f"非 SSH 端口不应命中 SIG-007 (engine={ENGINE}): {hits}"


def test_legacy_detector_and_mode_parity():
    """legacy 内置规则同步改为 AND(降级路径语义一致)。"""
    from sigma_detector import SigmaDetector
    det = SigmaDetector()
    rule = next(r for r in det.rules if r.rule_id == "SIG-007")
    assert rule.condition_mode == "and"
    # AND 语义下正常登录不命中
    det._agg_windows.clear()
    benign = {
        "event": "登录成功", "severity": "low", "src_ip": "10.7.0.1",
        "dst_ip": "192.168.1.10", "dst_port": 22, "protocol": "SSH",
        "message": "Normal SSH login success for ops user",
    }
    hits = [h for h in det.detect(benign) if h.rule_id == "SIG-007"]
    assert not hits, "legacy 引擎 AND 语义下正常登录不应命中"
