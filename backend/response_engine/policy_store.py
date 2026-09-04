"""
response_engine.policy_store — 响应策略 YAML CRUD + 热加载源

策略文件目录: backend/response_engine/policies/*.yml
与 sigma_engine/store 同模式：写回 YAML → PolicyEngine.reload()。
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_POLICIES_DIR = os.path.join(os.path.dirname(__file__), "policies")

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _ensure_dir(policies_dir: str) -> None:
    os.makedirs(policies_dir, exist_ok=True)


def dir_mtime(policies_dir: str = DEFAULT_POLICIES_DIR) -> float:
    """目录内全部 yml 的最大 mtime；空目录返回 0。"""
    if not os.path.isdir(policies_dir):
        return 0.0
    latest = 0.0
    for name in os.listdir(policies_dir):
        if not name.endswith((".yml", ".yaml")):
            continue
        try:
            latest = max(latest, os.path.getmtime(os.path.join(policies_dir, name)))
        except OSError:
            continue
    return latest


def _files(policies_dir: str) -> list[str]:
    if not os.path.isdir(policies_dir):
        return []
    return sorted(
        os.path.join(policies_dir, f)
        for f in os.listdir(policies_dir)
        if f.endswith((".yml", ".yaml"))
    )


def _slug_filename(policy_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", policy_id).strip("-") or "POL-CUSTOM"
    return f"{safe}.yml"


def _load_raw(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            logger.warning(f"[PolicyStore] skip non-mapping {path}")
            return None
        data["_source_path"] = path
        return data
    except Exception as e:
        logger.warning(f"[PolicyStore] skip {path}: {e}")
        return None


def validate_policy_dict(data: dict) -> list[str]:
    """返回校验错误列表；空列表表示合法。"""
    errors: list[str] = []
    name = str(data.get("name") or "").strip()
    if not name:
        errors.append("name 不能为空")
    pid = str(data.get("id") or "").strip()
    if pid and not _SAFE_ID.match(pid):
        errors.append("id 仅允许字母数字与 ._-")
    match = data.get("match") or {}
    if not isinstance(match, dict):
        errors.append("match 必须是对象")
        match = {}
    threat_type = str(match.get("threat_type") or data.get("threat_type") or "").strip()
    category = str(match.get("category") or data.get("category") or "").strip()
    role = str(data.get("role") or "").strip()
    if role != "uncertain_template" and not threat_type and not category:
        errors.append("match.threat_type 与 match.category 不能同时为空")
    sev = str(match.get("min_severity") or data.get("min_severity") or "medium").lower()
    if sev not in _VALID_SEVERITIES:
        errors.append(f"min_severity 非法: {sev}")
    try:
        conf = float(match.get("min_confidence", data.get("min_confidence", 0.5)))
        if conf < 0 or conf > 1:
            errors.append("min_confidence 须在 0..1")
    except (TypeError, ValueError):
        errors.append("min_confidence 须为数字")
    actions = data.get("actions")
    if not isinstance(actions, list) or not actions:
        errors.append("actions 不能为空")
    else:
        for i, act in enumerate(actions):
            if not isinstance(act, dict) or not act.get("name"):
                errors.append(f"actions[{i}] 缺少 name")
            params = act.get("params") or {}
            if "duration_minutes" in params:
                try:
                    dur = int(params["duration_minutes"])
                    if dur < 0 or dur > 43200:
                        errors.append(f"actions[{i}].duration_minutes 超出 0..43200")
                except (TypeError, ValueError):
                    errors.append(f"actions[{i}].duration_minutes 须为整数")
    return errors


def normalize_policy_dict(data: dict) -> dict:
    """把 YAML/API 输入归一成统一结构。"""
    match = dict(data.get("match") or {})
    threat_type = (
        match.get("threat_type")
        or data.get("threat_type")
        or ""
    )
    category = match.get("category") or data.get("category") or ""
    min_confidence = float(match.get("min_confidence", data.get("min_confidence", 0.5)))
    min_severity = str(match.get("min_severity", data.get("min_severity", "medium"))).lower()
    role = str(data.get("role") or "").strip()
    if role == "uncertain_template":
        threat_type = threat_type or "__UNCERTAIN__"
    return {
        "id": str(data.get("id") or "").strip(),
        "name": str(data.get("name") or "").strip(),
        "enabled": bool(data.get("enabled", True)),
        "role": role,
        "description": str(data.get("description") or ""),
        "threat_type": str(threat_type).strip(),
        "category": str(category).strip(),
        "min_confidence": min_confidence,
        "min_severity": min_severity,
        "actions": list(data.get("actions") or []),
        "auto_execute": bool(data.get("auto_execute", True)),
        "require_approval": bool(data.get("require_approval", False)),
        "priority": int(data.get("priority", 10)),
        "cooldown_minutes": int(data.get("cooldown_minutes", 30)),
        "_source_path": data.get("_source_path", ""),
    }


def load_all(policies_dir: str = DEFAULT_POLICIES_DIR) -> list[dict]:
    out: list[dict] = []
    for path in _files(policies_dir):
        raw = _load_raw(path)
        if not raw:
            continue
        errs = validate_policy_dict(raw)
        if errs:
            logger.warning(f"[PolicyStore] invalid {path}: {errs}")
            continue
        out.append(normalize_policy_dict(raw))
    return out


def to_yaml_dict(normalized: dict) -> dict:
    """写回 YAML 的规范结构（不含 _source_path）。"""
    body: dict[str, Any] = {
        "id": normalized.get("id") or "",
        "name": normalized["name"],
        "enabled": bool(normalized.get("enabled", True)),
        "description": normalized.get("description") or "",
        "match": {
            "threat_type": normalized.get("threat_type") or "",
            "min_confidence": float(normalized.get("min_confidence", 0.5)),
            "min_severity": normalized.get("min_severity") or "medium",
        },
        "actions": normalized.get("actions") or [],
        "auto_execute": bool(normalized.get("auto_execute", True)),
        "require_approval": bool(normalized.get("require_approval", False)),
        "priority": int(normalized.get("priority", 10)),
        "cooldown_minutes": int(normalized.get("cooldown_minutes", 30)),
    }
    if normalized.get("category"):
        body["match"]["category"] = normalized["category"]
    if normalized.get("role"):
        body["role"] = normalized["role"]
    return body


def _find_path_by_id_or_name(
    policies_dir: str, rule_id: str,
) -> Optional[str]:
    for path in _files(policies_dir):
        raw = _load_raw(path)
        if not raw:
            continue
        if str(raw.get("id") or "") == rule_id or str(raw.get("name") or "") == rule_id:
            return path
    return None


def get_policy(rule_id: str, policies_dir: str = DEFAULT_POLICIES_DIR) -> Optional[dict]:
    path = _find_path_by_id_or_name(policies_dir, rule_id)
    if not path:
        return None
    raw = _load_raw(path)
    return normalize_policy_dict(raw) if raw else None


def list_policies(policies_dir: str = DEFAULT_POLICIES_DIR) -> list[dict]:
    items = load_all(policies_dir)
    # rule_id 用 name：与 RuleVersion / 旧 get_policy(name) 对齐
    return [
        {
            "rule_id": p["name"],
            "id": p.get("id") or "",
            "name": p["name"],
            "description": p.get("description", ""),
            "severity": p.get("min_severity", "medium"),
            "threat_type": p.get("threat_type", ""),
            "category": p.get("category", ""),
            "auto_execute": p.get("auto_execute", True),
            "require_approval": p.get("require_approval", False),
            "priority": p.get("priority", 10),
            "cooldown_minutes": p.get("cooldown_minutes", 30),
            "min_confidence": p.get("min_confidence", 0.5),
            "actions": p.get("actions", []),
            "enabled": p.get("enabled", True),
            "role": p.get("role", ""),
            "type": "response_policy",
        }
        for p in items
    ]


def create_policy(
    content: dict,
    changed_by: str = "admin",
    policies_dir: str = DEFAULT_POLICIES_DIR,
) -> dict:
    _ensure_dir(policies_dir)
    data = dict(content)
    name = str(data.get("name") or "").strip()
    if not name:
        return {"success": False, "error": "name 不能为空"}
    pid = str(data.get("id") or data.get("rule_id") or "").strip()
    if not pid:
        # 生成 POL-001 风格 id
        nums = []
        for p in load_all(policies_dir):
            m = re.search(r"POL-(\d+)$", str(p.get("id") or ""), re.I)
            if m:
                nums.append(int(m.group(1)))
        pid = f"POL-{max(nums, default=100) + 1:03d}"
    data["id"] = pid
    data["name"] = name
    errs = validate_policy_dict(data)
    if errs:
        return {"success": False, "error": "; ".join(errs)}

    # 重名 / 重 id 检查
    for existing in load_all(policies_dir):
        if existing.get("id") == pid:
            return {"success": False, "error": f"策略 id 已存在: {pid}"}
        if existing.get("name") == name:
            return {"success": False, "error": f"策略 name 已存在: {name}"}

    normalized = normalize_policy_dict(data)
    path = os.path.join(policies_dir, _slug_filename(pid))
    try:
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(
                to_yaml_dict(normalized),
                fh,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except Exception as e:
        return {"success": False, "error": f"写入失败: {e}"}

    logger.info(f"[PolicyStore] created {pid} by {changed_by} → {path}")
    return {
        "success": True,
        "rule_id": pid,
        "version": 1,
        "version_data": {
            "rule_type": "response_policy",
            "rule_id": name,  # 与内存 policy.name 对齐，便于 get_policy/rollback
            "content": to_yaml_dict(normalized),
            "change_summary": "创建响应策略",
            "changed_by": changed_by,
        },
    }


def update_policy(
    rule_id: str,
    content: dict,
    change_summary: str = "",
    changed_by: str = "admin",
    policies_dir: str = DEFAULT_POLICIES_DIR,
) -> dict:
    path = _find_path_by_id_or_name(policies_dir, rule_id)
    if not path:
        return {"success": False, "error": f"策略不存在: {rule_id}"}
    raw = _load_raw(path) or {}
    merged = {**raw, **content}
    # 允许扁平字段覆盖 match.*
    match = dict(merged.get("match") or {})
    for key in ("threat_type", "category", "min_confidence", "min_severity"):
        if key in content:
            match[key] = content[key]
    merged["match"] = match
    # 禁止静默改 id
    merged["id"] = raw.get("id") or merged.get("id") or ""
    if "name" not in content:
        merged["name"] = raw.get("name")
    errs = validate_policy_dict(merged)
    if errs:
        return {"success": False, "error": "; ".join(errs)}
    normalized = normalize_policy_dict(merged)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(
                to_yaml_dict(normalized),
                fh,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except Exception as e:
        return {"success": False, "error": f"写入失败: {e}"}

    logger.info(f"[PolicyStore] updated {rule_id} by {changed_by}")
    return {
        "success": True,
        "rule_id": normalized.get("id") or rule_id,
        "version_data": {
            "rule_type": "response_policy",
            "rule_id": normalized["name"],
            "content": to_yaml_dict(normalized),
            "change_summary": change_summary or "更新响应策略",
            "changed_by": changed_by,
        },
    }


def delete_policy(
    rule_id: str,
    changed_by: str = "admin",
    policies_dir: str = DEFAULT_POLICIES_DIR,
    hard: bool = False,
) -> dict:
    """默认软删除（enabled=false）；hard=True 删除文件。"""
    path = _find_path_by_id_or_name(policies_dir, rule_id)
    if not path:
        return {"success": False, "error": f"策略不存在: {rule_id}"}
    if hard:
        try:
            os.remove(path)
        except OSError as e:
            return {"success": False, "error": str(e)}
        logger.info(f"[PolicyStore] hard-deleted {rule_id} by {changed_by}")
        return {"success": True, "rule_id": rule_id, "deleted": True}

    return update_policy(
        rule_id,
        {"enabled": False},
        change_summary="禁用响应策略",
        changed_by=changed_by,
        policies_dir=policies_dir,
    )


def apply_content_to_file(
    rule_id: str,
    content: dict,
    policies_dir: str = DEFAULT_POLICIES_DIR,
) -> dict:
    """回滚时把版本 content 整份写回。"""
    return update_policy(
        rule_id,
        content,
        change_summary="回滚应用",
        policies_dir=policies_dir,
    )
