"""阶段1：JSON 解析容错。

LLM 输出的 function call 常见脏数据形态：
  - 被 markdown 代码块包裹：```json ... ```
  - 使用单引号而非双引号
  - 尾部多余逗号
  - 字段名未加引号
  - 混入自然语言前缀："调用工具：{...}"
  - 嵌套转义错误

本模块尝试逐级修复，输出干净的 dict。
完全自包含，无外部依赖。
"""
import re
import json
from typing import Tuple, Optional


class JsonRepair:
    """JSON 修复器：从脏文本中提取并修复 JSON。"""

    # 匹配 markdown 代码块中的 JSON
    CODE_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)

    def repair(self, raw: str) -> Tuple[Optional[dict], Optional[str]]:
        """返回 (解析结果, 错误信息)。成功时错误为 None。"""
        if not raw or not isinstance(raw, str):
            return None, "输入为空或非字符串"

        text = raw.strip()

        # ---- 策略1：直接解析（最快路径）----
        result, err = self._try_parse(text)
        if result is not None:
            return result, None

        # ---- 策略2：剥离 markdown 代码块 ----
        stripped = self._strip_code_block(text)
        if stripped != text:
            result, err = self._try_parse(stripped)
            if result is not None:
                return result, None

        # ---- 策略3：从文本中抽取最外层 { ... } ----
        extracted = self._extract_json_object(text)
        if extracted:
            result, err = self._try_parse(extracted)
            if result is not None:
                return result, None

        # ---- 策略4：逐字符修复常见错误 ----
        repaired = self._fix_common_errors(extracted or stripped)
        result, err = self._try_parse(repaired)
        if result is not None:
            return result, None

        return None, f"JSON 解析失败，最终尝试: {repaired[:100]}"

    def _try_parse(self, text: str) -> Tuple[Optional[dict], Optional[str]]:
        """尝试 json.loads，仅接受 dict 结果。"""
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return obj, None
            return None, f"解析成功但非对象: {type(obj).__name__}"
        except json.JSONDecodeError as e:
            return None, str(e)

    def _strip_code_block(self, text: str) -> str:
        """剥离 markdown 代码块包裹。"""
        match = self.CODE_BLOCK_RE.search(text)
        if match:
            return match.group(1).strip()
        return text

    def _extract_json_object(self, text: str) -> str:
        """从混杂文本中提取最外层 { ... }（支持嵌套和字符串内花括号）。"""
        start = text.find("{")
        if start == -1:
            return ""
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        # 未闭合时返回剩余部分，让后续修复策略处理
        return text[start:]

    def _fix_common_errors(self, text: str) -> str:
        """修复常见 JSON 语法错误。"""
        # 单引号 -> 双引号（仅未转义的）
        text = re.sub(r"(?<!\\)'", '"', text)

        # 尾部多余逗号：}, ] 前的逗号
        text = re.sub(r",\s*([}\]])", r"\1", text)

        # 字段名未加引号：{ip: ...} -> {"ip": ...}
        text = re.sub(r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_.]*)\s*:", r'\1"\2":', text)

        return text
