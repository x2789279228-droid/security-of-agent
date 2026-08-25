"""
sigma_engine.backend_keywords — keywords 全文搜索兼容的 SQLite backend

背景:
    pySigma-backend-sqlite 的 SQLiteBackend 对 Sigma `keywords`(即 ConditionValueExpression,
    "value-only" 全文搜索)直接抛 SigmaFeatureNotSupportedByBackendError, 导致 SQLi/XSS/SSTI
    等大量使用 keywords 的 SigmaHQ web 规则无法编译接入。

本模块继承 SQLiteBackend, 重写 convert_condition_val_str/num:
  - 把 value-only 的 keywords 转成对"平台通用文本字段"的 OR LIKE 匹配,
    近似 Sigma "在所有字符串字段中搜索" 的语义, 又能在平台 web 事件上实际命中。
  - 匹配字段集合可用 KEYWORD_FIELDS 类常量配置(平台字段扩充时在此追加), 与
    sigma_engine/engine.py 的 _ensure_table 补列保持一致(字段列必须存在, 否则 SQL 报错)。

用法:
    在 sigma_engine/engine.py 中把 SQLiteBackend() 替换为 SigmaKeywordsBackend()。
"""
import re

from sigma.backends.sqlite import sqliteBackend as SQLiteBackend
from sigma.conditions import ConditionValueExpression

# 平台 web 事件中承载文本内容的通用字段(keywords 匹配目标)。
# 必须与 engine._ensure_table 补齐的列集合一致。
KEYWORD_FIELDS = [
    "url",
    "cs-uri-query",
    "message",
    "details",
    "http.url",
    "event",
]


def _escape_like(value: str) -> str:
    """转义 LIKE 模式中的特殊字符(配合 ESCAPE '\\'): 反斜杠→\\\\, %→\\%, _→\\_。"""
    return (
        value
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
        .replace("'", "''")  # SQL 字符串引号转义
    )


class SigmaKeywordsBackend(SQLiteBackend):
    """SQLite backend 扩展: 支持 Sigma keywords(value-only)全文搜索。"""

    # 可通过子类/实例覆盖, 用于平台字段扩充。
    KEYWORD_FIELDS = KEYWORD_FIELDS

    def _keyword_like_expr(self, value: str) -> str:
        """为每个文本字段生成 `f LIKE '%value%' ESCAPE '\\'`, 用 OR 连接。"""
        escaped = _escape_like(value)
        parts = []
        for field in self.KEYWORD_FIELDS:
            qf = f"{self.field_quote}{field}{self.field_quote}"
            parts.append(f"{qf} LIKE '%{escaped}%' ESCAPE '\\'")
        return "(" + " OR ".join(parts) + ")"

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state
    ):
        """value-only 字符串(keywords) → 对文本字段的 OR LIKE。"""
        value = cond.value
        return self._keyword_like_expr(str(value))

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state
    ):
        """value-only 数字(keywords) → 对文本字段的 OR LIKE(数值转字符串字形匹配)。"""
        return self._keyword_like_expr(str(cond.value))
