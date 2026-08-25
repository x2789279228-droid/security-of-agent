"""
sigma_engine.mapping — 薄版字段映射 pipeline（平台归一化事件 → Sigma 标准字段）

用途: 供引入 SigmaHQ 社区规则时, 把平台 ingest 的归一化事件(见 COMMUNITY_RULES_GUIDE.md
第 1 节字段表)转换为社区规则索引使用的 Sigma 标准字段名。
强调"薄": 只覆盖平台现有字段即可直接命中的映射; 新增日志源时按尾部规范扩展。
"""
from typing import Dict, Any

# ── 平台字段 → 常见 Sigma 标准字段 别名表 ──
# 值为可选的 sigma 等价字段; 键为平台字段名。同一平台字段可对应多个 sigma 字段。
PLATFORM_TO_SIGMA: Dict[str, list[str]] = {
    "event": ["event", "event.category", "category"],     # 平台归一化事件类型
    "event_type": ["event", "event.category"],
    "src_ip": ["src_ip", "source.ip"],
    "source_ip": ["src_ip", "source.ip"],
    "dst_ip": ["dst_ip", "destination.ip"],
    "dest_ip": ["dst_ip", "destination.ip"],
    "url": ["url", "http.url", "http.url_original", "cs-uri-query", "cs-uri-stem"],      # web 规则常用(SigmaHQ webserver 多用 cs-uri-query)
    "message": ["message", "details"],
    "dst_port": ["dst_port", "destination.port"],
    "protocol": ["protocol", "network.protocol"],
    "server": ["server", "destination.hostname"],
    "host": ["host", "destination.hostname"],
    # SigmaHQ web(webserver) 补充字段
    "method": ["method", "http.method", "cs-method"],
    "status": ["status", "http.response.status_code", "sc-status"],   # HTTP 状态码 (SigmaHQ 用 sc-status 做 filter)
    "user_agent": ["user_agent", "http.user_agent", "cs-user-agent"],
    "referer": ["referer", "http.referrer", "cs-referer"],
}

__all__ = ["PLATFORM_TO_SIGMA", "apply_mapping"]


def apply_mapping(event: Dict[str, Any]) -> Dict[str, Any]:
    """把平台事件(含 src_ip/dst_ip(可含端口)/url/... )转为 Sigma 标准字段 dict。

    端口: 若 dst_ip 形如 "1.2.3.4:9200", 拆出 dst_port。
    输出 = {sigma_field: value}, 同字段名同时保留平台原名, 便于规则双名引用。
    """
    out: Dict[str, Any] = {}
    for src, targets in PLATFORM_TO_SIGMA.items():
        if src in event and event[src] is not None:
            v = event[src]
            if isinstance(v, str) and ":" in str(v) and src in ("dst_ip", "dest_ip"):
                host, _, port = str(v).rpartition(":")
                if port.isdigit():
                    v = host
                    out["dst_port"] = int(port)
            out[src] = v
            for t in targets:
                if t not in out:
                    out[t] = v
    # 保留平台其余字段(便于依赖字段的映射/调试)
    for k, v in event.items():
        out.setdefault(k, v)
    return out


MAPPING_NOTE = '''
## 新增日志源时如何补映射

在 PLATFORM_TO_SIGMA 中为平台新字段增加一行:
    "your_field": ["sigma.same_or_mapped"]

- 优先映射到 Sigma 标准字段(如 network.protocol / destination.port), 便于 SigmaHQ 直接引用;
- 若社区规则只依赖平台则知字段名相同, 可省略;
- 映射只在"社区规则(未含平台字段名)"上生效; 平台自有规则仍用原名直接匹配;
- 每加一个日志源建议: 1) 扩展 mapping; 2) 用 dry_run_import 对样本验证命中率后再灰度。
'''
