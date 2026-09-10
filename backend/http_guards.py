"""HTTP source guards: IP allowlist, optional service token, optional mTLS header."""
from __future__ import annotations

import hmac
import ipaddress
from typing import Optional

from fastapi import Request

_CRITICAL_PREFIXES = (
    "/api/response/execute",
    "/api/response/rollback",
    "/api/response/simulate",
    "/api/response/approvals",
    "/api/firewall",
)

# ══════════════════════════════════════════════════════════════════════════
# HTTP 全局限流策略(2026-09-10 重定)
#
# 唯一限流点:app.py::rate_limit_middleware(60s 滑窗,sharded by rate key)。
# 旧策略只豁免 10 个前缀,运营中心其余 39 个业务域(168 条路由)全部落进同一个
# 120/min 共桶 → 页面并发 + SSE 重连 + 3s 轮询互相挤爆,表现为大面积 429。
#
# 新策略(默认豁免 + 高危点名):
#   1. RATE_LIMIT_WHITELIST —— 业务域/运营只读端点一律豁免,不再按"系统旁观者"
#      视角挑选;新增业务域应同步补这里(测试 test_route_classification 会强制)。
#   2. RATE_LIMIT_FORCED —— 只对"不可逆高危动作 + LLM 重端点"点名限流,
#      命中后使用独立桶命名空间(crit:),不与普通流量互相占额度。
#   3. settings.rate_limit_whitelist —— 现场可追加前缀,无需改代码。
# 认证端点自身仍有防爆破 429(routers/auth.py),响应动作层另有
# security_guard/rate_limiter.py 的 30/min,不依赖本白名单。
# ══════════════════════════════════════════════════════════════════════════

# 豁免前缀(按字母序;匹配规则:path == p 或 path.startswith(p + "/"))
RATE_LIMIT_WHITELIST = (
    # 基础设施 / 探针 / 文档
    "/api/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/metrics",
    # 自身已有限流的认证域(登录/注册有暴力破解 429)
    "/api/auth",
    # 只读成本/反馈/评测/知识库(前端并发查询,被限会空页)
    "/api/llm",
    "/api/feedback",
    "/api/rag",
    "/api/eval",
    # 防火墙 / 响应引擎查询态(高危动作另见 RATE_LIMIT_FORCED)
    "/api/firewall",
    "/api/response",
    # 日志与记忆(ingest 高频入站;events 为 Monitor 轮询/SSE)
    "/api/logs",
    "/api/memories",
    # 会话 / 思维树 / 全局统计 / SSE 控制面
    "/api/stats",
    "/api/tree",
    "/api/window",
    "/api/summary",
    "/api/context",
    "/api/events",
    "/api/chat",
    # 安全审计流水线(Audit-LLM 四层 / CAD 独立监督 / Sigma)
    "/api/audit-llm",
    "/api/audit-trail",
    "/api/cad",
    "/api/sigma",
    "/api/causal",
    # MCP Guard 观测(调用本身用 /guard/call,见 FORCED)
    "/api/guard",
    # 可观测性 / Agent 轨迹(Monitor 首屏高频 hydration)
    "/api/agent-traces",
    "/api/observability",
    # 安全事件查询 / 异常 / 攻击链
    "/api/security",
    "/api/security-guard",
    # 运营闭环:案例 / 工单 / 复盘 / KPI / 规则 / 学习闭环
    "/api/cases",
    "/api/work-orders",
    "/api/post-mortems",
    "/api/ops",
    "/api/rules",
    "/api/learn-loop",
    # 数据接入与管道
    "/api/sources",
    "/api/kafka",
    "/api/cep",
    "/api/pipeline",
    "/api/assets",
    # 检测域
    "/api/ndr",
    "/api/edr",
    "/api/intel",
    "/api/sandbox",
    "/api/phishing",
    "/api/llm-enhancer",
    "/api/data-security",
    # 自博弈 / 能力矩阵
    "/api/self-play",
    "/api/capabilities",
)

# 点名强制限流:即使前缀已豁免,也必须计入全局限流(独立 crit: 桶)
# 取值 = 路径前缀归一化后的元组;None 表示不限方法,元组表示仅这些方法
_SUFFIX_SET = (None, ("POST",), ("PUT", "DELETE", "PATCH"), ("POST", "PUT", "DELETE", "PATCH"))

RATE_LIMIT_FORCED = {
    # 响应链:执行/回滚/审批/策略写 → 不可逆,且可能被自动化脚本连打
    "/api/response/execute": None,
    "/api/response/rollback": None,
    "/api/response/clear-cooldowns": ("POST",),
    "/api/response/approvals": ("POST",),
    "/api/response/policies": ("POST", "PUT", "DELETE", "PATCH"),
    # 防火墙连接/批量回滚(SSH 到宿主机,重资源)
    "/api/firewall/connect": None,
    "/api/firewall/rollback-all": None,
    # MCP Guard 真实工具调用(4 层检查后可能落到真实资产动作)
    "/api/guard/call": None,
    "/api/guard/calls/flush": ("POST",),
    # 日志高频写入口(2026-09-01 曾因同机 ingest 打 429 而单独豁免,此处按前缀精确限流)
    "/api/logs/ingest": None,
    "/api/logs/analyze": None,
    "/api/logs/reset-stuck": ("POST",),
    # 规则引擎写动作(含 Sigma 开关/回滚)
    "/api/rules": ("POST", "PUT", "DELETE", "PATCH"),
    # 学习闭环:立即执行 + 应用/回滚动作
    "/api/learn-loop/run": None,
    "/api/learn-loop/actions": ("POST",),
    # CAD 监督端点的写动作(改阈值/重置熔断/人工覆盖)
    "/api/cad/audit-context": ("POST",),
    "/api/cad/circuit-breaker/reset": ("POST",),
    "/api/cad/thresholds": ("PUT",),
    "/api/cad/override": ("POST",),
    # 触发型重端点(LLM / 沙箱 / 关联分析 / 回放)
    "/api/security/review": ("POST",),
    "/api/causal/query": ("POST",),
    "/api/causal/learn": ("POST",),
    "/api/cep/replay": ("POST",),
    "/api/intel/match": ("POST",),
    "/api/sandbox/submit": ("POST",),
    "/api/assets/discovery": ("POST",),
    # 自博弈开赛 / 复核批跑(LLM 重,可被脚本连打)
    "/api/self-play/matches": ("POST",),
    "/api/self-play/review/run": ("POST",),
    # 钓鱼检测批跑(LLM/附件解析)
    "/api/phishing/detect": ("POST",),
    # 数据源注册/吊销(安全面)
    "/api/sources/register": ("POST",),
    "/api/sources/revoke": ("POST",),
}

# 追加白名单的解析缓存(按原始串缓存,避免每请求 split)
_EXTRA_WHITELIST_CACHE: tuple = ("", ())


def _extra_whitelist() -> tuple:
    """settings.rate_limit_whitelist 的解析结果(逗号分隔前缀,去空/补 /api 前缀外的原样)。"""
    global _EXTRA_WHITELIST_CACHE
    raw = ""
    try:
        raw = getattr(_settings(), "rate_limit_whitelist", "") or ""
    except Exception:
        raw = ""
    if raw != _EXTRA_WHITELIST_CACHE[0]:
        parsed = tuple(item.strip() for item in raw.split(",") if item.strip())
        _EXTRA_WHITELIST_CACHE = (raw, parsed)
    return _EXTRA_WHITELIST_CACHE[1]


def _match(path: str, prefixes) -> bool:
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def is_rate_limit_whitelisted(path: str) -> bool:
    """True if path is exempt from the global 60s HTTP sliding-window limiter."""
    return _match(path, RATE_LIMIT_WHITELIST) or _match(path, _extra_whitelist())


def is_rate_limit_forced(path: str, method: str) -> bool:
    """True if path must be rate-limited even though its prefix is whitelisted.

    RATE_LIMIT_FORCED 是"精确前缀 → 允许的方法集(None=所有方法)"的表;
    取最长匹配,避免 /api/response/policies 的放宽覆盖 /api/response/execute。
    """
    m = (method or "").upper()
    best_len = -1
    forced = False
    for prefix, methods in RATE_LIMIT_FORCED.items():
        if path == prefix or path.startswith(prefix + "/"):
            if methods is not None and m not in methods:
                continue
            if len(prefix) > best_len:
                best_len, forced = len(prefix), True
    return forced


def rate_limit_decision(path: str, method: str) -> tuple:
    """限流判定:(是否计入全局限流, 桶命名空间)。

    优先级: 强制限流(crit) > 豁免(None) > 全局默认。
    """
    if is_rate_limit_forced(path, method):
        return True, "crit"
    if is_rate_limit_whitelisted(path):
        return False, None
    return True, "std"


def _settings():
    from config import settings
    return settings


def parse_allowlist(raw: str) -> list:
    out = []
    for part in (raw or "").split(","):
        item = part.strip()
        if not item:
            continue
        try:
            if "/" in item:
                out.append(ipaddress.ip_network(item, strict=False))
            else:
                out.append(ipaddress.ip_network(item + ("/128" if ":" in item else "/32"), strict=False))
        except ValueError:
            continue
    return out


def client_ip(request: Request) -> str:
    settings = _settings()
    if getattr(settings, "trust_proxy", False):
        xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if xff:
            return xff
    if request.client and request.client.host:
        return request.client.host
    return ""


def ip_allowed(ip: str, allowlist: list, allow_loopback: bool) -> bool:
    if not allowlist:
        return True
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if allow_loopback and addr.is_loopback:
        return True
    return any(addr in net for net in allowlist)


def allowlist_blocks(request: Request) -> Optional[str]:
    """Return error detail if blocked, else None."""
    path = request.url.path
    if not any(path == p or path.startswith(p + "/") for p in _CRITICAL_PREFIXES):
        return None
    settings = _settings()
    raw = getattr(settings, "api_allowlist", "") or ""
    nets = parse_allowlist(raw)
    if not nets:
        return None
    ip = client_ip(request)
    if ip_allowed(ip, nets, bool(getattr(settings, "api_allowlist_allow_loopback", True))):
        return None
    return f"source IP not allowed: {ip or 'unknown'}"


def service_token_ok(request: Request) -> bool:
    settings = _settings()
    expected = getattr(settings, "service_token", "") or ""
    if not expected:
        return False
    got = request.headers.get("X-SOC-Service-Token") or ""
    if len(got) != len(expected):
        return False
    return hmac.compare_digest(got, expected)


def mtls_blocks(request: Request) -> Optional[str]:
    settings = _settings()
    if not getattr(settings, "mtls_enforce", False):
        return None
    verify = (request.headers.get("X-SSL-Client-Verify") or "").strip().upper()
    if verify == "SUCCESS":
        return None
    return "client certificate required"
