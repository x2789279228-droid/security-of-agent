"""阶段3：参数类型转换与默认值补全。

LLM 常见参数问题：
  - 类型错误：limit 传成字符串 "50"，should_alert 传成 "true"
  - 可选字段未传：未传 scan_type（应补 default "fast"）
  - 多余字段：传了不存在的参数（应剥离并记录）
  - 空值：传了空字符串（应视为缺失）

本模块基于 PARAM_SCHEMAS 做软转换，不抛异常（失败留给后续 Schema 校验）。
完全自包含，无外部依赖。
"""
from typing import Tuple, List, Any


# ============================================================
# 平台工具参数 Schema
# 格式: { 字段名: { type, required, default, ... } }
# ============================================================
PARAM_SCHEMAS = {
    # ---- 数据查询 / 分析类 ----
    "event_store.query": {
        "session_id":  {"type": "str", "required": False, "default": None},
        "src_ip":      {"type": "str", "required": False, "default": None},
        "dst_ip":      {"type": "str", "required": False, "default": None},
        "event_type":  {"type": "str", "required": False, "default": None},
        "severity":    {"type": "str", "required": False, "default": None},
        "limit":       {"type": "int", "required": False, "default": 50},
        "offset":      {"type": "int", "required": False, "default": 0},
        "time_range":  {"type": "str", "required": False, "default": "1h"},
    },
    "anomaly.baseline": {
        "metric":      {"type": "str", "required": True},
        "entity":      {"type": "str", "required": False, "default": None},
        "window":      {"type": "str", "required": False, "default": "24h"},
        "threshold":   {"type": "float", "required": False, "default": 2.0},
    },
    "correlation.chains": {
        "entity":      {"type": "str", "required": True},
        "depth":       {"type": "int", "required": False, "default": 3},
        "time_range":  {"type": "str", "required": False, "default": "1h"},
    },
    "causal.graph": {},
    "correlation.temporal": {
        "event_ids":   {"type": "list", "required": False, "default": None},
        "entity":      {"type": "str", "required": False, "default": None},
        "window":      {"type": "str", "required": False, "default": "30m"},
    },
    "correlation.entity_link": {
        "entity":      {"type": "str", "required": True},
        "link_type":   {"type": "str", "required": False, "default": "all"},
        "depth":       {"type": "int", "required": False, "default": 2},
    },
    "vector.search": {
        "query":       {"type": "str", "required": True},
        "top_k":       {"type": "int", "required": False, "default": 5},
        "threshold":   {"type": "float", "required": False, "default": 0.7},
        "namespace":   {"type": "str", "required": False, "default": None},
    },
    "knowledge.search": {
        "query":       {"type": "str", "required": True},
        "top_k":       {"type": "int", "required": False, "default": 5},
        "category":    {"type": "str", "required": False, "default": None},
    },
    "memory_tree.related": {
        "node_id":     {"type": "str", "required": False, "default": None},
        "session_id":  {"type": "str", "required": False, "default": None},
        "depth":       {"type": "int", "required": False, "default": 2},
    },
    "sliding_window.get": {
        "window_id":   {"type": "str", "required": False, "default": "default"},
        "limit":       {"type": "int", "required": False, "default": 20},
    },
    "sliding_window.evicted": {
        "window_id":   {"type": "str", "required": False, "default": "default"},
        "limit":       {"type": "int", "required": False, "default": 10},
    },
    # ---- 响应动作类 ----
    "block_ip": {
        "ip":          {"type": "str", "required": True},
        "duration":    {"type": "int", "required": False, "default": 3600},
        "reason":      {"type": "str", "required": True},
    },
    "isolate_host": {
        "hostname":    {"type": "str", "required": True},
        "isolation_type": {"type": "str", "required": False, "default": "network"},
        "reason":      {"type": "str", "required": True},
    },
    "rate_limit": {
        "target":      {"type": "str", "required": True},
        "rate":        {"type": "int", "required": False, "default": 100},
        "unit":        {"type": "str", "required": False, "default": "req/min"},
        "duration":    {"type": "int", "required": False, "default": 600},
        "reason":      {"type": "str", "required": True},
    },
    "terminate_process": {
        "pid":         {"type": "int", "required": False, "default": None},
        "process_name": {"type": "str", "required": False, "default": None},
        "hostname":    {"type": "str", "required": True},
        "reason":      {"type": "str", "required": True},
    },
    "alert_only": {
        "title":       {"type": "str", "required": True},
        "severity":    {"type": "str", "required": False, "default": "medium"},
        "description": {"type": "str", "required": False, "default": ""},
        "recipients":  {"type": "list", "required": False, "default": None},
    },
    "vulnerability_scan": {
        "target":      {"type": "str", "required": True},
        "scan_type":   {"type": "str", "required": False, "default": "fast"},
        "port_range":  {"type": "str", "required": False, "default": "1-1000"},
    },
}


class ParamCoercer:
    """参数类型转换与补全器。"""

    def coerce(self, tool_name: str, params: dict) -> Tuple[dict, List[tuple]]:
        """返回 (转换后的参数, 变更记录列表)。

        变更记录每项为 (字段名, 动作, before, after)。
        """
        if tool_name not in PARAM_SCHEMAS:
            # 未知工具不做转换，原样返回
            return params, []

        schema = PARAM_SCHEMAS[tool_name]
        result = dict(params) if params else {}
        changes: List[tuple] = []

        # 1. 处理 schema 中定义的字段：类型转换
        for field_name, rules in schema.items():
            value = result.get(field_name)
            expected_type = rules.get("type")

            # 空值视为缺失，移除
            if value is None or value == "":
                if field_name in result:
                    result.pop(field_name, None)
                continue

            # 类型转换
            coerced, ok = self._coerce_type(value, expected_type)
            if ok and coerced != value:
                changes.append((field_name, "type_coerce", value, coerced))
                result[field_name] = coerced

        # 2. 补全可选字段的默认值
        for field_name, rules in schema.items():
            if field_name not in result:
                default = rules.get("default")
                if default is not None:
                    result[field_name] = default
                    changes.append((field_name, "default_fill", None, default))

        # 3. 检测并剥离未知字段
        known_fields = set(schema.keys())
        unknown = [k for k in list(result.keys()) if k not in known_fields]
        for k in unknown:
            old_val = result.pop(k)
            changes.append((k, "strip_unknown", old_val, None))

        return result, changes

    @staticmethod
    def _coerce_type(value: Any, expected_type: str) -> Tuple[Any, bool]:
        """尝试将 value 转为 expected_type，返回 (结果, 是否成功)。"""
        if expected_type == "int":
            if isinstance(value, int) and not isinstance(value, bool):
                return value, True
            if isinstance(value, str):
                try:
                    return int(value), True
                except ValueError:
                    # 尝试浮点转整数（如 "3.0"）
                    try:
                        return int(float(value)), True
                    except ValueError:
                        pass
            if isinstance(value, float):
                return int(value), True
            if isinstance(value, bool):
                return int(value), True
            return value, False

        if expected_type == "float":
            if isinstance(value, float):
                return value, True
            if isinstance(value, int) and not isinstance(value, bool):
                return float(value), True
            if isinstance(value, str):
                try:
                    return float(value), True
                except ValueError:
                    pass
            return value, False

        if expected_type == "str":
            if isinstance(value, str):
                return value, True
            # 数字、布尔转字符串
            if isinstance(value, (int, float, bool)):
                return str(value), True
            return value, False

        if expected_type == "bool":
            if isinstance(value, bool):
                return value, True
            if isinstance(value, str):
                lower = value.strip().lower()
                if lower in ("true", "1", "yes", "是"):
                    return True, True
                if lower in ("false", "0", "no", "否"):
                    return False, True
            if isinstance(value, int):
                return bool(value), True
            return value, False

        if expected_type == "list":
            if isinstance(value, list):
                return value, True
            # 单值包装为列表
            if isinstance(value, (str, int, float)):
                return [value], True
            return value, False

        # 未知类型不做转换
        return value, True
