"""阶段2：工具名归一化。

LLM 输出的工具名常见不规范形态：
  - 大小写错误：Event_Store.Query / EVENT_STORE_QUERY
  - 分隔符错误：event-store-query / eventstorequery
  - 同义名称：query_events / search_events
  - 拼写错误：event_store.querys

本模块按以下顺序尝试解析：
  1. 精确匹配
  2. 前缀匹配（输入是标准名的前缀或反之）
  3. 模糊匹配（difflib.SequenceMatcher，阈值 >= 0.6）

完全自包含，仅依赖标准库 difflib。
"""
import difflib
from typing import Tuple, Optional, List


# ============================================================
# 平台工具白名单
# ============================================================

# 数据查询 / 分析类工具
PLATFORM_TOOLS: List[str] = [
    "event_store.query",
    "anomaly.baseline",
    "correlation.chains",
    "correlation.temporal",
    "correlation.entity_link",
    "vector.search",
    "knowledge.search",
    "memory_tree.related",
    "sliding_window.get",
    "sliding_window.evicted",
]

# 响应动作类工具
RESPONSE_TOOLS: List[str] = [
    "block_ip",
    "isolate_host",
    "rate_limit",
    "terminate_process",
    "alert_only",
    "vulnerability_scan",
]

# 合并为完整工具列表
ALL_TOOLS: List[str] = PLATFORM_TOOLS + RESPONSE_TOOLS

# 预置别名：常见同义 / 缩写工具名 -> 标准工具名
TOOL_ALIASES = {
    # 数据查询类
    "query_events":       "event_store.query",
    "search_events":      "event_store.query",
    "event_query":        "event_store.query",
    "events":             "event_store.query",
    # 异常检测
    "baseline":           "anomaly.baseline",
    "anomaly_baseline":   "anomaly.baseline",
    "detect_anomaly":     "anomaly.baseline",
    # 关联分析
    "chains":             "correlation.chains",
    "correlation_chains": "correlation.chains",
    "temporal":           "correlation.temporal",
    "entity_link":        "correlation.entity_link",
    # 向量 / 知识检索
    "search":             "vector.search",
    "vector_search":      "vector.search",
    "embedding_search":   "vector.search",
    "knowledge":          "knowledge.search",
    "knowledge_search":   "knowledge.search",
    "rag_search":         "knowledge.search",
    # 记忆树
    "memory_tree":        "memory_tree.related",
    "related":            "memory_tree.related",
    # 滑动窗口
    "sliding_window":     "sliding_window.get",
    "window_get":         "sliding_window.get",
    "evicted":            "sliding_window.evicted",
    # 响应类
    "block":              "block_ip",
    "ban_ip":             "block_ip",
    "block_address":      "block_ip",
    "firewall_block":     "block_ip",
    "isolate":            "isolate_host",
    "quarantine":         "isolate_host",
    "host_isolation":     "isolate_host",
    "limit":              "rate_limit",
    "throttle":           "rate_limit",
    "kill":               "terminate_process",
    "kill_process":       "terminate_process",
    "alert":              "alert_only",
    "notify":             "alert_only",
    "vuln_scan":          "vulnerability_scan",
    "scan":               "vulnerability_scan",
}


class ToolResolver:
    """工具名归一化解析器。"""

    # difflib 相似度阈值（0~1，越高越严格）
    FUZZY_THRESHOLD = 0.6

    def resolve(self, raw_name: str) -> Tuple[Optional[str], Optional[str], str]:
        """返回 (标准工具名, 错误信息, 匹配方式)。

        匹配方式：exact / prefix / alias / fuzzy / none
        """
        if not raw_name or not isinstance(raw_name, str):
            return None, "工具名为空", "none"

        name = raw_name.strip()

        # 1. 精确匹配
        if name in ALL_TOOLS:
            return name, None, "exact"

        # 2. 规范化匹配：统一小写 + 将 - 和空格替换为 _ 或 .
        normalized = self._normalize(name)
        for std_name in ALL_TOOLS:
            if self._normalize(std_name) == normalized:
                return std_name, None, "exact"

        # 3. 前缀匹配：输入是标准名的前缀，或标准名是输入的前缀
        prefix_match = self._prefix_match(normalized)
        if prefix_match:
            return prefix_match, None, "prefix"

        # 4. 别名匹配
        alias_key = name.lower().replace(" ", "_").replace("-", "_")
        if alias_key in TOOL_ALIASES:
            return TOOL_ALIASES[alias_key], None, "alias"

        # 5. 模糊匹配：difflib.SequenceMatcher
        best_match = None
        best_ratio = 0.0
        for std_name in ALL_TOOLS:
            ratio = difflib.SequenceMatcher(None, normalized, self._normalize(std_name)).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = std_name

        if best_match and best_ratio >= self.FUZZY_THRESHOLD:
            return best_match, None, "fuzzy"

        return None, f"无法识别工具名: '{raw_name}'", "none"

    @staticmethod
    def _normalize(name: str) -> str:
        """规范化工具名：小写，- 和空格统一为 _，去掉多余分隔符。"""
        s = name.lower().strip()
        s = s.replace("-", "_").replace(" ", "_")
        # 将连续多个 _ 或 . 合并
        while "__" in s:
            s = s.replace("__", "_")
        return s

    @staticmethod
    def _prefix_match(normalized: str) -> Optional[str]:
        """前缀匹配：找唯一前缀命中的标准工具名。"""
        candidates = []
        for std_name in ALL_TOOLS:
            std_norm = ToolResolver._normalize(std_name)
            # 输入是标准名前缀（至少4字符避免误匹配）
            if len(normalized) >= 4 and std_norm.startswith(normalized):
                candidates.append(std_name)
            # 标准名是输入前缀
            elif len(std_norm) >= 4 and normalized.startswith(std_norm):
                candidates.append(std_name)
        # 仅在唯一命中时返回，避免歧义
        if len(candidates) == 1:
            return candidates[0]
        return None
