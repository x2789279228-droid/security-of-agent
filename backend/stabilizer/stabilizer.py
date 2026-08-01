"""Stabilizer 编排器：串联四个修复阶段，输出稳定的工具调用 dict。

调用链：
    LLM 原始输出 (str)
        ↓
    1. JsonRepair        —— JSON 解析容错
    2. ToolResolver      —— 工具名归一化
    3. ParamCoercer      —— 参数类型转换 + 默认补全
    4. SchemaCheck       —— 简单 dict 校验（必填字段检查）
        ↓
    dict: {"tool_name": ..., "parameters": ..., "tool_match_method": ...}

失败时构造 feedback_to_llm（中文），供 Agent 重试时附给 LLM 修正。
完全自包含，无外部依赖。
"""
from typing import Optional

from stabilizer.json_repair import JsonRepair
from stabilizer.tool_resolver import ToolResolver, ALL_TOOLS
from stabilizer.param_coercer import ParamCoercer, PARAM_SCHEMAS
from stabilizer.models import StabilizerResult, RepairStep


class FunctionCallStabilizer:
    """Function Calling 稳定化器：将 LLM 脏输出修复为可执行的工具调用。"""

    # 工具名字段在解析后 dict 中的候选键名（LLM 常用不同字段名）
    NAME_FIELDS = ["tool", "tool_name", "name", "function", "function_name", "action"]
    # 参数字段候选键名
    PARAM_FIELDS = ["parameters", "arguments", "args", "params", "input"]

    def __init__(self):
        self.json_repair = JsonRepair()
        self.tool_resolver = ToolResolver()
        self.param_coercer = ParamCoercer()

    def stabilize(self, raw_output: str) -> StabilizerResult:
        """将 LLM 原始输出稳定化为标准工具调用 dict。

        返回 StabilizerResult:
          - success=True 时 request 为 {"tool_name", "parameters", "tool_match_method"}
          - success=False 时 error / error_type / feedback_to_llm 描述失败原因
        """
        result = StabilizerResult(success=False)

        # ---- 阶段1：JSON 解析容错 ----
        parsed, err = self.json_repair.repair(raw_output)
        if parsed is None:
            result.error_type = "json_error"
            result.error = f"JSON 解析失败: {err}"
            result.feedback_to_llm = self._build_json_feedback(raw_output, err)
            result.repair_steps.append(RepairStep(
                stage="json_parse", action="parse", success=False,
                before=raw_output[:200] if raw_output else "", note=err or ""
            ))
            return result

        result.repair_steps.append(RepairStep(
            stage="json_parse", action="parse", success=True,
            before=raw_output[:80] if raw_output else "", after=str(parsed)[:80]
        ))

        # ---- 提取工具名与参数 ----
        raw_tool_name = self._extract_field(parsed, self.NAME_FIELDS)
        raw_params = self._extract_field(parsed, self.PARAM_FIELDS) or {}
        if not isinstance(raw_params, dict):
            raw_params = {}

        # ---- 阶段2：工具名归一化 ----
        std_name, err, match_method = self.tool_resolver.resolve(raw_tool_name)
        if std_name is None:
            result.error_type = "unknown_tool"
            result.error = err
            result.feedback_to_llm = self._build_tool_feedback(raw_tool_name)
            result.repair_steps.append(RepairStep(
                stage="tool_resolve", action="resolve", success=False,
                before=raw_tool_name, note=err or ""
            ))
            return result

        action = "no_change" if match_method == "exact" else f"normalize:{match_method}"
        result.repair_steps.append(RepairStep(
            stage="tool_resolve", action=action, success=True,
            before=raw_tool_name, after=std_name
        ))

        # ---- 阶段3：参数类型转换 + 默认补全 ----
        coerced_params, changes = self.param_coercer.coerce(std_name, raw_params)
        for field_name, action_name, before, after in changes:
            result.repair_steps.append(RepairStep(
                stage="param_coerce", action=action_name, success=True,
                before=before, after=after, note=field_name
            ))

        # ---- 阶段4：Schema 校验（简单 dict 验证，检查必填字段）----
        validation_errors = self._schema_check(std_name, coerced_params)
        if validation_errors:
            result.error_type = "param_invalid"
            result.error = "; ".join(validation_errors)
            result.feedback_to_llm = self._build_param_feedback(std_name, validation_errors)
            result.repair_steps.append(RepairStep(
                stage="schema_check", action="validate", success=False,
                note="; ".join(validation_errors)
            ))
            return result

        result.repair_steps.append(RepairStep(
            stage="schema_check", action="validate", success=True
        ))

        # ---- 成功：输出稳定工具调用 dict ----
        result.success = True
        result.request = {
            "tool_name": std_name,
            "parameters": coerced_params,
            "tool_match_method": match_method,
        }
        return result

    # ----------------------------------------------------------
    # 阶段4：简单 Schema 校验
    # ----------------------------------------------------------
    @staticmethod
    def _schema_check(tool_name: str, params: dict) -> list:
        """检查必填字段是否存在且非空，返回错误列表（空列表=通过）。"""
        schema = PARAM_SCHEMAS.get(tool_name)
        if schema is None:
            # 无 schema 定义的工具不做校验
            return []

        errors = []
        for field_name, rules in schema.items():
            if rules.get("required", False):
                value = params.get(field_name)
                if value is None or value == "":
                    errors.append(f"缺少必填参数 '{field_name}'")
        return errors

    # ----------------------------------------------------------
    # 内部工具方法
    # ----------------------------------------------------------
    @staticmethod
    def _extract_field(d: dict, candidates: list):
        """从 dict 中按候选键名提取值（不区分大小写）。"""
        # 先精确匹配
        for k in candidates:
            if k in d:
                return d[k]
        # 再忽略大小写匹配
        lower_map = {k.lower(): v for k, v in d.items()}
        for k in candidates:
            if k.lower() in lower_map:
                return lower_map[k.lower()]
        return None

    @staticmethod
    def _build_json_feedback(raw: str, err: str) -> str:
        """构造 JSON 解析失败的中文反馈。"""
        return (
            "你上一次输出的工具调用无法被解析为合法 JSON。\n"
            f"错误信息: {err}\n"
            "请重新输出，要求：\n"
            "1. 使用纯 JSON，不要用 markdown 代码块包裹\n"
            "2. 字段名和字符串值必须使用双引号\n"
            "3. 不要有多余的尾逗号\n"
            '格式示例: {"tool": "event_store.query", "parameters": {"src_ip": "10.0.0.5", "limit": 50}}'
        )

    @staticmethod
    def _build_tool_feedback(raw_name) -> str:
        """构造工具名无法识别的中文反馈。"""
        allowed = ", ".join(ALL_TOOLS)
        return (
            f"你调用的工具 '{raw_name}' 不存在。\n"
            f"可用工具列表: {allowed}\n"
            "请从上述列表中选择正确的工具名重新调用。"
        )

    @staticmethod
    def _build_param_feedback(tool_name: str, errors: list) -> str:
        """构造参数校验失败的中文反馈。"""
        return (
            f"工具 '{tool_name}' 的参数校验失败：\n"
            + "\n".join(f"- {e}" for e in errors)
            + "\n请修正参数后重新调用。"
        )


# ============================================================
# 全局单例，供平台各模块直接导入使用
# ============================================================
stabilizer = FunctionCallStabilizer()
