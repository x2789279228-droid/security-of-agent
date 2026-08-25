"""
sigma_engine.store — 规则文件(backend/sigma_engine/rules/*.yml) CRUD

真 Sigma 规则即文件: create/update/delete/toggle/shadow 直接写回 YAML,
再调用 PySigmaDetector.reload() 重编译。返回 dict 与前端/rule_manager 兼容。
"""
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# 平台可编辑的业务字段(写入 x-soc-*)
EDITABLE = {
    "severity": "severity",          # 也映射 level
    "attack_type": "attack_type",
    "confidence": "confidence",
    "action_recommend": "action",
    "shadow_mode": "shadow",
    "enabled": "enabled",
}
YAML_EDITABLE = {"severity": "level"}   # severity → Sigma level

# 幂等 id 生成(与官方 format_sigma、sigma 命名风格一致)
def _next_id(rules_dir: str) -> str:
    ids = []
    for fn in os.listdir(rules_dir):
        m = re.search(r"SIG-(\d+)", fn)
        if m:
            ids.append(int(m.group(1)))
    return f"SIG-{max(ids, default=0) + 1:03d}"


def _files(rules_dir: str) -> List[str]:
    if not os.path.isdir(rules_dir):
        return []
    return sorted(os.path.join(rules_dir, f) for f in os.listdir(rules_dir) if f.endswith(".yml"))


def _load_rules(rules_dir: str) -> List[dict]:
    out = []
    for fp in _files(rules_dir):
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                d = yaml.safe_load(fh) or {}
            out.append(d)
        except Exception as e:
            logger.warning(f"[Sigma/store] skip {fp}: {e}")
    return out


def _rid(data: dict) -> str:
    return str(data.get("x-soc-id") or "") or ""


def list_rules(rules_dir: str = DEFAULT_RULES_DIR) -> List[dict]:
    res = []
    for data in _load_rules(rules_dir):
        res.append({
            "rule_id": _rid(data),
            "name": data.get("title", ""),
            "description": data.get("description", ""),
            "severity": data.get("x-soc-severity") or data.get("level", "low"),
            "attack_type": data.get("x-soc-attack_type", "custom"),
            "confidence": data.get("x-soc-confidence", "medium"),
            "action_recommend": data.get("x-soc-action", "alert"),
            "enabled": bool(data.get("x-soc-enabled", True)),
            "shadow_mode": bool(data.get("x-soc-shadow", False)),
            "type": "sigma",
            "conditions": {"sigma_yaml": yaml.dump(data, allow_unicode=True, sort_keys=False).strip()},
        })
    return res


def get_rule(rule_id: str, rules_dir: str = DEFAULT_RULES_DIR) -> Optional[dict]:
    """获取单条规则详情。返回与 list_rules() 相同包装格式(含 rule_id/severity/conditions 等)。"""
    for data in _load_rules(rules_dir):
        if _rid(data) == rule_id:
            return {
                "rule_id": _rid(data),
                "name": data.get("title", ""),
                "description": data.get("description", ""),
                "severity": data.get("x-soc-severity") or data.get("level", "low"),
                "attack_type": data.get("x-soc-attack_type", "custom"),
                "confidence": data.get("x-soc-confidence", "medium"),
                "action_recommend": data.get("x-soc-action", "alert"),
                "enabled": bool(data.get("x-soc-enabled", True)),
                "shadow_mode": bool(data.get("x-soc-shadow", False)),
                "type": "sigma",
                "conditions": {"sigma_yaml": yaml.dump(data, allow_unicode=True, sort_keys=False).strip()},
            }
    return None


def _pack_rule(data: dict) -> dict:
    """把 rule_mgr 的业务字段写入 Sigma YAML 的 x-soc-* 字段(供 create/update 前落盘)。"""
    out = dict(data)
    mapping = {
        "severity": "x-soc-severity",
        "attack_type": "x-soc-attack_type",
        "confidence": "x-soc-confidence",
        "action_recommend": "x-soc-action",
        "enabled": "x-soc-enabled",
        "shadow_mode": "x-soc-shadow",
    }
    for k, yk in mapping.items():
        if k in data:
            out[yk] = data[k]
    if "name" in data and not out.get("title"):
        out["title"] = data["name"]
    if "description" in data and "description" not in out:
        out["description"] = data["description"]
    # 最小标准 Sigma 占位 detection：匹配平台任意事件(带 rule_id 字段)，保证可编译。
    if "detection" not in out and "sigma_yaml" not in data:
        out["detection"] = {"selection": {"rule_id": out.get("x-soc-id", "")},
                            "condition": "selection"}
    return out


def _file_for(rule_id: str, rules_dir: str) -> Optional[str]:
    for fp in _files(rules_dir):
        data = _load_rule_file(fp)
        if data and _rid(data) == rule_id:
            return fp
    return None


def _load_rule_file(fp: str) -> dict:
    try:
        with open(fp, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def _write(fp: str, data: dict):
    with open(fp, "w", encoding="utf-8") as fh:
        yaml.dump(data, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)


def create_rule(content: dict, rules_dir: str = DEFAULT_RULES_DIR, changed_by: str = "admin") -> dict:
    """新增规则。content: {name, description, severity, attack_type, confidence,
    action_recommend, sigma_yaml(快 Sigma 全文含 detection 与 x-soc-*)} 或完整 rule dict。"""
    data = dict(content)
    rid = data.get("rule_id") or data.get("x-soc-id") or _next_id(rules_dir)
    # 优先用用户提供的 sigma_yaml(标准 Sigma 全文); 否则由业务字段拼一个可编译的最小规则。
    if "sigma_yaml" in data:
        try:
            parsed = yaml.safe_load(data["sigma_yaml"]) or {}
            parsed.setdefault("x-soc-id", rid)
            data = parsed
        except Exception as e:
            return {"success": False, "error": f"sigma_yaml 解析失败: {e}"}
    else:
        data = _pack_rule(data)
    data["x-soc-id"] = rid
    fp = os.path.join(rules_dir, f"{rid}.yml")
    if os.path.exists(fp):
        return {"success": False, "error": f"规则 {rid} 已存在"}
    if "detection" not in data:
        # 兜底：最小标准 Sigma detection(匹配带 rule_id 字段的事件), 保证规则可编译。
        data["detection"] = {"selection": {"rule_id": rid}, "condition": "selection"}
    _write(fp, data)
    logger.info(f"[Sigma/store] created {rid} by {changed_by}")
    return {"success": True, "rule_id": rid, "version": 1, "path": fp}


def update_rule(rule_id: str, patch: dict, rules_dir: str = DEFAULT_RULES_DIR, changed_by: str = "admin") -> dict:
    fp = _file_for(rule_id, rules_dir)
    if not fp:
        return {"success": False, "error": f"规则 {rule_id} 不存在"}
    data = _load_rule_file(fp)
    for k, v in patch.items():
        if k == "action_recommend":
            data["x-soc-action"] = v
        elif k == "attack_type":
            data["x-soc-attack_type"] = v
        elif k == "confidence":
            data["x-soc-confidence"] = v
        elif k == "severity":
            data["x-soc-severity"] = v
            data["level"] = v
        elif k == "enabled":
            data["x-soc-enabled"] = bool(v)
        elif k == "shadow_mode":
            data["x-soc-shadow"] = bool(v)
        elif k in ("name",):
            data["title"] = v
        elif k in ("description", "level", "status", "tags", "logsource", "detection"):
            data[k] = v
        elif k == "sigma_yaml":
            try:
                extra = yaml.safe_load(v) or {}
                data.update({kk: vv for kk, vv in extra.items() if kk not in ("x-soc-id", "id")})
            except Exception as e:
                return {"success": False, "error": f"sigma_yaml 解析失败: {e}"}
    _write(fp, data)
    logger.info(f"[Sigma/store] updated {rule_id} by {changed_by}")
    return {"success": True, "rule_id": rule_id, "version": data.get("version", 1) + 1}


def delete_rule(rule_id: str, rules_dir: str = DEFAULT_RULES_DIR, changed_by: str = "admin") -> dict:
    fp = _file_for(rule_id, rules_dir)
    if not fp:
        return {"success": False, "error": f"规则 {rule_id} 不存在"}
    os.remove(fp)
    logger.info(f"[Sigma/store] deleted {rule_id} by {changed_by}")
    return {"success": True, "rule_id": rule_id}


def toggle(rule_id: str, enable: bool, rules_dir: str = DEFAULT_RULES_DIR) -> dict:
    return update_rule(rule_id, {"enabled": enable}, rules_dir=rules_dir, changed_by="toggle")


def shadow(rule_id: str, on: bool, rules_dir: str = DEFAULT_RULES_DIR) -> dict:
    return update_rule(rule_id, {"shadow_mode": on}, rules_dir=rules_dir, changed_by="shadow")
