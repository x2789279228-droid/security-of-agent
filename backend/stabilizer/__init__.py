"""Stabilizer 模块：修复 LLM 输出的不规范工具调用。

四阶段管线：
  1. JsonRepair     —— JSON 解析容错（代码块剥离、尾逗号、单引号等）
  2. ToolResolver   —— 工具名归一化（精确 / 前缀 / 别名 / 模糊匹配）
  3. ParamCoercer   —— 参数类型转换 + 默认值补全
  4. SchemaCheck    —— 必填字段校验

用法:
    from stabilizer import stabilizer, StabilizerResult

    result: StabilizerResult = stabilizer.stabilize(llm_raw_output)
    if result.success:
        tool_name = result.request["tool_name"]
        params = result.request["parameters"]
    else:
        # result.feedback_to_llm 可直接附给 LLM 做重试提示
        ...
"""
from stabilizer.stabilizer import FunctionCallStabilizer, stabilizer
from stabilizer.models import StabilizerResult, RepairStep

__all__ = [
    "FunctionCallStabilizer",
    "StabilizerResult",
    "RepairStep",
    "stabilizer",
]
