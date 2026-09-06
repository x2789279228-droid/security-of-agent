"""阶段2：工具名归一化。

LLM 输出的工具名常见不规范形态：
  - 大小写错误：Event_Store.Query / EVENT_STORE_QUERY
  - 分隔符错误：event-store-query / eventstorequery
  - 同义名称：query_events / search_events

解析顺序（PR1 / P0-6）：
  1. 精确匹配（含大小写/分隔符归一）
  2. 显式别名表

禁止：
  - 前缀匹配（"alert" 误命中 alert_only）
  - difflib 模糊匹配（阈值 0.6 会把干扰工具"纠正"成最近白名单工具）
  未知工具必须 abstain，不得执行。
"""
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
    "causal.graph",
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
    "causal_graph":       "causal.graph",
    "causal":             "causal.graph",
    # 向量 / 知识检索（不用过短别名 "search"/"knowledge"，避免干扰工具误匹配）
    "vector_search":      "vector.search",
    "embedding_search":   "vector.search",
    "knowledge_search":   "knowledge.search",
    "rag_search":         "knowledge.search",
    # 记忆树
    "memory_tree":        "memory_tree.related",
    # 滑动窗口
    "sliding_window":     "sliding_window.get",
    "window_get":         "sliding_window.get",
    "window_evicted":     "sliding_window.evicted",
    # 响应类 — 只保留明确别名，禁止 block/kill/scan/alert 等短词
    "ban_ip":             "block_ip",
    "block_address":      "block_ip",
    "firewall_block":     "block_ip",
    "quarantine":         "isolate_host",
    "host_isolation":     "isolate_host",
    "throttle":           "rate_limit",
    "kill_process":       "terminate_process",
    "notify_only":        "alert_only",
    "vuln_scan":          "vulnerability_scan",
}


class ToolResolver:
    """工具名归一化解析器。只做精确匹配 + 显式别名，未知则 abstain。"""

    def resolve(self, raw_name: str) -> Tuple[Optional[str], Optional[str], str]:
        """返回 (标准工具名, 错误信息, 匹配方式)。

        匹配方式：exact / alias / none
        """
        if not raw_name or not isinstance(raw_name, str):
            return None, "工具名为空", "none"

        name = raw_name.strip()

        # 1. 精确匹配
        if name in ALL_TOOLS:
            return name, None, "exact"

        # 2. 规范化匹配：统一小写 + 将 - 和空格替换为 _
        normalized = self._normalize(name)
        for std_name in ALL_TOOLS:
            if self._normalize(std_name) == normalized:
                return std_name, None, "exact"

        # 3. 显式别名（含归一化后的别名键）
        alias_key = self._normalize(name).replace(".", "_")
        if alias_key in TOOL_ALIASES:
            return TOOL_ALIASES[alias_key], None, "alias"
        if name.lower() in TOOL_ALIASES:
            return TOOL_ALIASES[name.lower()], None, "alias"

        return None, f"无法识别工具名: '{raw_name}'（已拒绝模糊/前缀匹配）", "none"

    @staticmethod
    def _normalize(name: str) -> str:
        """规范化工具名：小写，- 和空格统一为 _，去掉多余分隔符。"""
        s = name.lower().strip()
        s = s.replace("-", "_").replace(" ", "_")
        while "__" in s:
            s = s.replace("__", "_")
        return s
