"""
prompts 模板一致性自动校验 — 验证加固

职责（防止 Prompts 集中化回归）：
  1. 无悬空引用：每个 render()/register() 引用的模板名，在 prompts/ 下有对应 .j2 文件。
  2. 无孤儿模板：prompts/ 下每个 .j2 被至少一处 render()/register() 引用。
  3. 无硬编码 system prompt：非 prompts/ 的 py 文件中，"role":"system" 的 content
     不得是字面量中文 prompt（cad.py 的有意 fallback 快照登记为白名单）。
  4. 模板严格渲染：对每个主模板（含 LLM 调用的模板）以调用点 mock 上下文
     strict_render()，断言不抛 UndefinedError —— 提前暴露 {{var}} 拼写不一致。

说明：tests/conftest.py 已注入 sqlite + env，并确保可以 from prompts import render。
"""
import re
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
PROMPTS_DIR = BACKEND / "prompts"

# 排除的目录/文件（非业务代码）
_EXCLUDE_PY = {"__pycache__", "tests"}
_EXCLUDE_PARTS = ("\\__pycache__\\", "/__pycache__/")


# ────────────────────────────────────────────────
# 1. 收集 render/register 引用 与 模板文件
# ────────────────────────────────────────────────

# 仅匹配独立的 render(...) / strict_render(...)，参数为紧接的字符串字面量。
# 用负向后视避免 'some_render'/'my_register' 等方法名误抓；
# 参数支持跨行（render(\n "audit/xxx"）。
_REF_RE = re.compile(
    r'(?<![A-Za-z_0-9])(?:render|strict_render)\s*\(\s*'
    r'["\']([a-z][a-z0-9_/\-\.]+)["\']',
)


def _iter_py_files():
    for p in BACKEND.rglob("*.py"):
        if any(x in _EXCLUDE_PARTS for x in (str(p),)):
            continue
        rel = p.relative_to(BACKEND)
        parts = rel.parts
        if any(x in _EXCLUDE_PY for x in parts):
            continue
        yield p


def _collect_references() -> set[str]:
    refs: set[str] = set()
    for p in _iter_py_files():
        src = p.read_text(encoding="utf-8", errors="ignore")
        for m in _REF_RE.finditer(src):
            refs.add(m.group(1))
    return refs


def _collect_templates() -> set[str]:
    tpls = set()
    for p in PROMPTS_DIR.rglob("*.j2"):
        rel = p.relative_to(PROMPTS_DIR)
        # 与 loader 的斜杠相对路径保持一致（如 "analysis/summary_compress"）
        name = rel.with_suffix("").as_posix()
        tpls.add(name)
    return tpls


def test_no_dangling_reference():
    """每个 render/register 引用都必须有对应模板文件（防悬空）。"""
    refs = _collect_references()
    templates = _collect_templates()
    missing = sorted(r for r in refs if r not in templates)
    assert not missing, f"引用但模板缺失: {missing}"


def test_no_orphan_template():
    """每个 .j2 模板都至少被一处 render/register 引用（防孤儿）。"""
    refs = _collect_references()
    templates = _collect_templates()
    orphan = sorted(t for t in templates if t not in refs)
    assert not orphan, f"存在未被引用的孤儿模板: {orphan}"


# ────────────────────────────────────────────────
# 2. 无硬编码 system prompt
# ────────────────────────────────────────────────

# cad.py 的 ContextAuditor fallback 快照是有意保留的降级兜底（主路径仍走 render）。
# 其四行 content 的值被允许作为白名单。
_CAD_FALLBACK_SNIPPETS = {
    "你是安全分析专家，输出JSON格式。",
    "你是严谨的安全分析专家。严格遵循输出格式",
    "你是严谨的安全审计专家。只采纳有证据支撑的结论，输出JSON。",
    "你是一个严格的安全审计复核专家，专门负责防幻觉检查。",
}

# system 内容中作为字面量 prompt 出现的启发式特征（逐个匹配，避免复杂嵌套正则）。
_PROMPT_KEYWORDS = ("你是", "你是一个", "担任", "扮演", "输出JSON", "安全审计专家")


def test_no_hardcoded_system_prompt():
    """非 prompts/ 的 py 文件中，system 角色 content 不应是字面量中文 prompt。

    例外：cad.py 的有意 fallback 快照（白名单）。
    启发式：定位 "role": "system" 区域，若其 content 含中文 prompt 关键词
    且不在 render(...) 内、不在白名单内，判为硬编码。
    """
    offenders = []
    for p in _iter_py_files():
        src = p.read_text(encoding="utf-8", errors="ignore")
        # 粗定位 system 段：搜 "system" 附近的中文 prompt 关键词
        for kw in _PROMPT_KEYWORDS:
            start = 0
            while True:
                idx = src.find(kw, start)
                if idx < 0:
                    break
                window = src[max(0, idx - 300):idx + len(kw) + 50]
                start = idx + len(kw)
                # 排除 render(...)/render ( 已渲染的调用点
                if "render(" in window or "render (" in window:
                    continue
                # 排除注释/文档字符串前（"#" 或 """ 前行）
                head = src[:idx]
                if head.rstrip().endswith("#"):
                    continue
                # 排除白名单片段（cad fallback）
                if any(s in window for s in _CAD_FALLBACK_SNIPPETS):
                    continue
                # 仅当处于 system role 上下文才计为硬编码（粗判定：附近有 "system"）
                if "system" in window.lower():
                    offenders.append((str(p), kw, src[max(0, idx - 40):idx + 20]))
    assert not offenders, f"发现疑似硬编码 system prompt: {offenders}"


# ────────────────────────────────────────────────
# 3. 模板严格渲染（变量完整性）
# ────────────────────────────────────────────────

# 模板 → 渲染所需 mock 上下文。仅覆盖"主模板"（LLM user prompt）；*_system 模板大多
# 无变量，统一提供空 dict（语义上 safe）。值均为 mock，仅用于校验模板变量可解析。
_TEMPLATE_VARS: dict[str, dict] = {
    # ── analysis ──
    "analysis/summary_compress": {"text": "输入文本", "max_tokens": 200},
    "analysis/timeline_narrative": {
        "time_range": "1h", "total_events": 1, "critical_count": 1,
        "target_ip": "1.2.3.4", "kill_chain_pos": 1, "kill_chain_total": 3,
        "tactics": "recon", "events_summary": "摘要",
    },
    # ── audit ──
    "audit/agent_a_analyze": {"security_context": "ctx", "user_input": "输入"},
    "audit/agent_b_decision": {"analysis_result": "r", "security_context": "ctx", "user_input": "输入"},
    "audit/agent_c_report": {"analysis_result": "r", "decision_result": "d", "security_context": "ctx", "user_input": "输入"},
    "audit/agent_d_audit": {"context": "ctx"},
    "audit/decomposer_initial_analysis": {"event_json": "{}", "anomaly_score": 0.5, "reasons_str": "无"},
    "audit/executor_deep": {"v_text": "v"},
    "audit/executor_recheck": {"v_text": "v", "threat_detected": True, "threat_type": "C2", "confidence": 0.9},
    "audit/executor_synthesize": {"event_json": "{}", "depth": "standard", "chain_info": "",
                                  "rag_context": "", "deep_section": "", "verification_section": "",
                                  "kb_section": "", "summary_text": "", "verdicts": []},
    "audit/reviewer_review": {"event_json": "{}", "depth": "standard", "sub_tasks_text": "",
                              "llm_analysis": "", "audit_json": "{}", "rag_section": "", "tool_data_raw": ""},
    "audit/sub_auditor_prompt": {"block_text": "block"},
    # ── rag ──
    "rag/evidence_verify": {"claim": "断言", "context": "上下文"},
    "rag/rerank": {"query": "q", "items_text": "items", "top_k": 5},
    "rag/query_rewrite": {"query": "q"},
    "rag/hyde": {"query": "q"},
    # ── security ──
    "security/data_security_classifier_user": {"m": "{}", "body_snippet": "b", "url": "u", "src_ip": "s",
                                               "dst_ip": "d", "rule_hit": "r", "response_size": 1,
                                               "response_content_type": "t"},
    "security/edr_correlation": {"edr_event": "e", "network_event": "n", "correlation_type": "t",
                                 "mitre_technique": "m", "indicators": [], "confidence": 0.9},
    "security/phishing_user": {"det_type": "d", "target": "t", "url": "u", "score": 0.5,
                               "risk_level": "low", "summary_rendered": "s", "indicators": []},
    "security/threat_intel_context": {"src_ip": "s", "dst_ip": "d", "event_type": "e",
                                      "ioc_hits": [], "reputation_scores": [], "hits_str": "h"},
    "security/tls_analyzer": {"src_ip": "s", "dst_ip": "d", "tls_version": "TLS1.2", "cipher_suite": "c",
                              "sni": "n", "cert_subject": "sub", "cert_issuer": "iss",
                              "cert_is_self_signed": False, "risk_score": 0.5,
                              "ja3_hash": "j", "risk_reasons": []},
    "security/traffic_anomaly_user": {"ip": "1.2.3.4", "metric": "m", "current_value": 1.0,
                                      "expected": 0.0, "mean": 0.0, "std": 1.0, "z_score": 1.0,
                                      "reasons": [], "recent_pattern": "p", "seasonal_component": "s"},
    "security/zeroday_sandbox": {"sample_hash": "h", "verdict": "v", "score": 5.0,
                                 "behavior_summary": "b", "signatures": [], "process_str": "p",
                                 "network_str": "n", "techniques_str": "t"},
    "security/red_plan": {
        "level": 0, "coverage": "PORT_SCAN", "catalog": "[]",
        "rag_hints": "(none)", "last_outcome": "blue_win",
        "blue_view": "{}",
    },
    "security/blue_learn": {
        "event_type": "SYN_ENUM", "severity": "medium", "protocol": "tcp",
        "message": "x", "mitre_id": "T1046", "url": "",
    },
    "security/blue_review": {
        "rule_id": "SP-1", "title": "t", "mitre_id": "T1046",
        "attack_type": "SYN_ENUM", "severity": "medium",
        "condition_mode": "or", "event_contains": ["SYN_ENUM"],
        "message_contains": ["半开"], "gates": [],
    },
    # ── tooling ──
    "tooling/post_mortem_review": {"title": "t", "case_number": "c", "threat_type": "th",
                                   "severity": "high", "timeline_text": "tl", "src_ips": [],
                                   "event_count": 1, "fp_count": 0, "disposition": "d"},
    "tooling/watchdog_diagnose": {"trigger_stage": "s", "trigger_reason": "r", "affected_events": [],
                                  "stage_joined": "j", "errors_text": "e", "cb_text": "c",
                                  "active_text": "a"},
}


def test_all_main_templates_strict_render():
    """每个登记的主模板用 mock 上下文 strict_render，断言不抛 UndefinedError。"""
    from prompts import loader

    # system 模板无变量文件清单（自动跳过）
    system_names = {name for name in loader_template_names() if name.endswith("_system")}
    for tpl in sorted(_TEMPLATE_VARS):
        ctx = _TEMPLATE_VARS[tpl]
        loader.strict_render(tpl, **ctx)  # 缺变量抛 UndefinedError → 测试失败


def loader_template_names() -> set[str]:
    """返回 prompts/ 下所有模板名（辅助）。"""
    return _collect_templates()


def test_system_templates_render():
    """所有 *_system 模板（无变量的）也应能正常 render（不抛错）。"""
    from prompts import loader
    system_names = sorted(n for n in _collect_templates() if n.endswith("_system"))
    assert system_names, "未发现 *_system 模板"
    for name in system_names:
        loader.render(name)
