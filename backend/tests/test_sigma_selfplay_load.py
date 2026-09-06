"""Self-Play shadow YAML 必须进 pySigma,且一条坏文件不得拖垮 SIG-001..011。"""
import os
import sys
import tempfile
import uuid

import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_engine.engine import PY_SIGMA_AVAILABLE, PySigmaDetector
from self_play.sigma_export import repair_selfplay_yaml, to_sigma_dict, write_selfplay_rule

pytestmark = pytest.mark.skipif(not PY_SIGMA_AVAILABLE, reason="pySigma not installed")

_SIG = """title: HTTP login
id: aaaaaaaa-0001-0000-0000-000000000001
status: test
logsource:
  category: proxy
  product: generic
detection:
  selection:
    url|contains:
    - /api/auth/login
  condition: selection
level: high
x-soc-id: SIG-001
x-soc-action: block_ip
x-soc-attack_type: brute_force
x-soc-severity: high
x-soc-enabled: true
x-soc-shadow: false
"""

_BAD_ID = """title: Self-Play AUTH_SPRAY
id: sp-sp-deadbeef-001
status: experimental
logsource:
  category: proxy
  product: generic
detection:
  sel_event:
    event|contains:
    - AUTH_SPRAY
  condition: sel_event
level: medium
x-soc-id: SP-DEAD
x-soc-shadow: true
x-soc-action: alert
x-soc-enabled: true
"""


def _layout(tmp: str):
    rules = os.path.join(tmp, "rules")
    shadow = os.path.join(tmp, "rules_selfplay_shadow")
    os.makedirs(rules)
    os.makedirs(shadow)
    return rules, shadow


def _write(path: str, text: str):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _ids(det: PySigmaDetector) -> set[str]:
    return {r["rule_id"] for r in det._rules}


def test_bad_id_is_skipped_without_killing_sig(monkeypatch):
    monkeypatch.setattr("self_play.sigma_export.repair_selfplay_yaml", lambda *_a, **_k: 0)
    with tempfile.TemporaryDirectory() as tmp:
        rules, shadow = _layout(tmp)
        _write(os.path.join(rules, "SIG-001.yml"), _SIG)
        _write(os.path.join(shadow, "SP-DEAD.yml"), _BAD_ID)
        det = PySigmaDetector(rules, enforce=True)
        assert det.stats().get("engine") == "pySigma"
        assert "SIG-001" in _ids(det)
        assert "SP-DEAD" not in _ids(det)
        assert len(det._compiled) >= 1


def test_exported_shadow_yaml_compiles_and_hits():
    with tempfile.TemporaryDirectory() as tmp:
        rules, shadow = _layout(tmp)
        _write(os.path.join(rules, "SIG-001.yml"), _SIG)
        rule = {
            "rule_id": "SP-GOOD",
            "title": "半开连接探测",
            "attack_type": "SYN_ENUM",
            "mitre_id": "T1046",
            "severity": "medium",
            "condition_mode": "or",
            "conditions": {
                "event_contains": ["SYN_ENUM"],
                "message_contains": ["半开连接"],
            },
        }
        written = write_selfplay_rule(rule, shadow=True, rules_dir=shadow)
        data = yaml.safe_load(open(written["path"], encoding="utf-8"))
        uuid.UUID(str(data["id"]))
        assert data["x-soc-id"] == "SP-GOOD"
        assert data["x-soc-shadow"] is True
        det = PySigmaDetector(rules, enforce=True)
        assert "SIG-001" in _ids(det)
        assert "SP-GOOD" in _ids(det)
        assert det.stats().get("shadow_count", 0) >= 1
        hits = det.detect({
            "event": "SYN_ENUM",
            "message": "半开连接探测",
            "url": "",
            "src_ip": "10.0.0.8",
            "severity": "medium",
        })
        sp = [h for h in hits if h.rule_id == "SP-GOOD"]
        assert sp, f"shadow rule should hit ingest path: {[h.rule_id for h in hits]}"
        assert sp[0].action_recommend == "alert"
        assert "[SHADOW]" in (sp[0].description or "")


def test_repair_selfplay_yaml_rewrites_non_uuid_id():
    with tempfile.TemporaryDirectory() as tmp:
        fp = os.path.join(tmp, "SP-DEAD.yml")
        _write(fp, _BAD_ID)
        n = repair_selfplay_yaml(tmp)
        assert n == 1
        data = yaml.safe_load(open(fp, encoding="utf-8"))
        uuid.UUID(str(data["id"]))
        assert data["x-soc-id"] == "SP-DEAD"
        assert data["id"] == to_sigma_dict({"rule_id": "SP-DEAD"})["id"]
        n2 = repair_selfplay_yaml(tmp)
        assert n2 == 0


def test_reload_keeps_sig_when_extra_file_is_broken():
    with tempfile.TemporaryDirectory() as tmp:
        rules, shadow = _layout(tmp)
        _write(os.path.join(rules, "SIG-001.yml"), _SIG)
        det = PySigmaDetector(rules, enforce=True)
        assert "SIG-001" in _ids(det)
        _write(os.path.join(shadow, "BROKEN.yml"), "this is: not: yaml: [[[\n")
        n = det.reload()
        assert n >= 1
        assert "SIG-001" in _ids(det)
        assert det.stats().get("engine") == "pySigma"
        hits = det.detect({"url": "/api/auth/login", "event": "x", "message": "", "src_ip": "1.1.1.1"})
        assert any(h.rule_id == "SIG-001" for h in hits)
