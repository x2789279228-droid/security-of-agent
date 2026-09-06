"""把 Self-Play overlay 条件编译成 Sigma YAML,写入独立目录(不碰 SIG-001..011)。"""
from __future__ import annotations

import logging
import os
import re
import uuid
from datetime import date
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

SELFPLAY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sigma_engine", "rules_selfplay_shadow")
SELFPLAY_DIR = os.path.normpath(SELFPLAY_DIR)


def _safe_id(rule_id: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(rule_id or "SP-UNK"))
    return s.strip("-") or "SP-UNK"


def sigma_uuid_for(rule_id: str) -> str:
    """Sigma 规范要求 id 为 UUID。平台业务 id 仍走 x-soc-id,此处只生成稳定 UUID。"""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"soc:selfplay:{_safe_id(rule_id)}"))


def _is_uuid(value: Any) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except Exception:
        return False


def _sanitize_tags(tags: Any, extra: Optional[list[str]] = None) -> list[str]:
    """pySigma 要求 tag 为 namespace.rest; `self-play` 无点号会被整条拒绝。"""
    out: list[str] = []
    seen: set[str] = set()
    for raw in list(tags or []) + list(extra or []):
        tag = str(raw or "").strip()
        if not tag:
            continue
        if tag == "self-play" or tag == "selfplay":
            tag = "detection.selfplay"
        if "." not in tag:
            tag = f"detection.{tag}"
        if tag not in seen:
            seen.add(tag)
            out.append(tag)
    return out


def _contains(values: Any) -> list[str]:
    if not values:
        return []
    if isinstance(values, (list, tuple)):
        return [str(v) for v in values if str(v).strip()]
    return [str(values)] if str(values).strip() else []


def to_sigma_dict(rule: dict, *, shadow: bool = True) -> dict:
    rid = _safe_id(rule.get("rule_id") or "SP-UNK")
    cond = rule.get("conditions") or {}
    mode = str(rule.get("condition_mode") or "or").lower()
    ev = _contains(cond.get("event_contains"))
    msg = _contains(cond.get("message_contains"))
    url = _contains(cond.get("url_contains"))
    detection: dict[str, Any] = {}
    names = []
    if ev:
        detection["sel_event"] = {"event|contains": ev}
        names.append("sel_event")
    if msg:
        detection["sel_msg"] = {"message|contains": msg}
        names.append("sel_msg")
    if url:
        detection["sel_url"] = {"url|contains": url}
        names.append("sel_url")
    if not names:
        detection["sel_event"] = {"event|contains": [rid]}
        names = ["sel_event"]
    joiner = " and " if mode == "and" else " or "
    detection["condition"] = joiner.join(names)
    mitre = str(rule.get("mitre_id") or "").strip()
    tags = _sanitize_tags(
        [f"attack.{mitre.lower()}"] if mitre else [],
        extra=["detection.selfplay"],
    )
    return {
        "title": str(rule.get("title") or rid)[:200],
        "id": sigma_uuid_for(rid),
        "status": "experimental",
        "description": str(rule.get("title") or rid),
        "date": date.today().strftime("%Y/%m/%d"),
        "author": "blue_reviewer",
        "logsource": {"category": "proxy", "product": "generic"},
        "detection": detection,
        "level": str(rule.get("severity") or "medium"),
        "tags": tags,
        "falsepositives": ["self-play generated; shadow until FP gate holds"],
        "x-soc-id": rid,
        "x-soc-confidence": "medium",
        "x-soc-action": "alert",
        "x-soc-attack_type": str(rule.get("attack_type") or "custom"),
        "x-soc-severity": str(rule.get("severity") or "medium"),
        "x-soc-shadow": bool(shadow),
        "x-soc-source": "self-play",
        "x-soc-enabled": True,
    }


def dump_yaml(rule: dict, *, shadow: bool = True) -> str:
    return yaml.dump(to_sigma_dict(rule, shadow=shadow), allow_unicode=True, sort_keys=False)


def repair_selfplay_yaml(rules_dir: Optional[str] = None) -> int:
    """把目录里非 UUID 的 Sigma id 改成 uuid5(x-soc-id)。volume 残留的 sp-sp-... 靠此修复。"""
    directory = rules_dir or SELFPLAY_DIR
    if not os.path.isdir(directory):
        return 0
    n = 0
    for name in os.listdir(directory):
        if not name.endswith(".yml"):
            continue
        fp = os.path.join(directory, name)
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception as e:
            logger.warning("[selfplay-sigma] repair skip %s: %s", fp, e)
            continue
        if not isinstance(data, dict):
            continue
        rid = _safe_id(data.get("x-soc-id") or os.path.splitext(name)[0] or "SP-UNK")
        changed = False
        if not _is_uuid(data.get("id")):
            data["id"] = sigma_uuid_for(rid)
            changed = True
        data.setdefault("x-soc-id", rid)
        new_tags = _sanitize_tags(data.get("tags"))
        if new_tags != list(data.get("tags") or []):
            data["tags"] = new_tags
            changed = True
        if not changed:
            continue
        try:
            with open(fp, "w", encoding="utf-8") as fh:
                yaml.dump(data, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)
            n += 1
            logger.info("[selfplay-sigma] repaired %s", fp)
        except Exception as e:
            logger.warning("[selfplay-sigma] repair write failed %s: %s", fp, e)
    return n


def write_selfplay_rule(rule: dict, *, shadow: bool = True, rules_dir: Optional[str] = None) -> dict:
    directory = rules_dir or SELFPLAY_DIR
    os.makedirs(directory, exist_ok=True)
    repair_selfplay_yaml(directory)
    rid = _safe_id(rule.get("rule_id") or "SP-UNK")
    data = to_sigma_dict(rule, shadow=shadow)
    fp = os.path.join(directory, f"{rid}.yml")
    with open(fp, "w", encoding="utf-8") as fh:
        yaml.dump(data, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)
    logger.info("[selfplay-sigma] wrote %s shadow=%s", fp, shadow)
    return {"path": fp, "rule_id": rid, "shadow": shadow, "yaml": dump_yaml(rule, shadow=shadow)}


def delete_selfplay_rule(rule_id: str, rules_dir: Optional[str] = None) -> bool:
    directory = rules_dir or SELFPLAY_DIR
    fp = os.path.join(directory, f"{_safe_id(rule_id)}.yml")
    if os.path.isfile(fp):
        os.remove(fp)
        return True
    return False


def reload_sigma() -> bool:
    try:
        from sigma_detector import sigma_detector
        if hasattr(sigma_detector, "reload"):
            sigma_detector.reload()
            return True
    except Exception as e:
        logger.warning("[selfplay-sigma] reload skipped: %s", e)
    return False
