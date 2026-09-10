"""
PR2 控制面: http_guards IP 白名单单元测试

覆盖:
  - parse_allowlist: 空/单IP/CIDR/IPv6/非法项
  - ip_allowed: CIDR 命中/拒绝、空白名单全放行、loopback 开关、非法 IP
"""
import asyncio
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http_guards import (
    ip_allowed,
    is_rate_limit_forced,
    is_rate_limit_whitelisted,
    parse_allowlist,
    rate_limit_decision,
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestParseAllowlist:
    def test_empty_raw_returns_empty_list(self):
        assert parse_allowlist("") == []
        assert parse_allowlist(None) == []
        assert parse_allowlist("   ") == []

    def test_single_ip_becomes_host_network(self):
        nets = parse_allowlist("10.0.0.5")
        assert nets == [ipaddress.ip_network("10.0.0.5/32")]

    def test_cidr_ipv4_and_ipv6_mixed(self):
        nets = parse_allowlist("10.0.0.0/8, 192.168.1.1, ::1")
        assert ipaddress.ip_network("10.0.0.0/8") in nets
        assert ipaddress.ip_network("192.168.1.1/32") in nets
        assert ipaddress.ip_network("::1/128") in nets

    def test_invalid_entries_skipped(self):
        nets = parse_allowlist("999.1.2.3, 10.0.0.0/8, not-an-ip, /24")
        assert nets == [ipaddress.ip_network("10.0.0.0/8")]

    def test_host_bits_relaxed(self):
        # strict=False: 10.0.0.5/8 归一化为 10.0.0.0/8 而不是抛错
        nets = parse_allowlist("10.0.0.5/8")
        assert nets == [ipaddress.ip_network("10.0.0.0/8")]


class TestIpAllowed:
    def test_cidr_allows_and_denies(self):
        nets = parse_allowlist("10.0.0.0/8")
        assert ip_allowed("10.1.2.3", nets, allow_loopback=False) is True
        assert ip_allowed("1.2.3.4", nets, allow_loopback=False) is False

    def test_empty_allowlist_allows_all(self):
        assert ip_allowed("1.2.3.4", [], allow_loopback=False) is True
        assert ip_allowed("8.8.8.8", None, allow_loopback=False) is True

    def test_invalid_ip_denied_when_allowlist_set(self):
        nets = parse_allowlist("10.0.0.0/8")
        assert ip_allowed("not-an-ip", nets, allow_loopback=False) is False
        assert ip_allowed("", nets, allow_loopback=False) is False

    def test_loopback_flag(self):
        nets = parse_allowlist("10.0.0.0/8")
        assert ip_allowed("127.0.0.1", nets, allow_loopback=True) is True
        assert ip_allowed("127.0.0.1", nets, allow_loopback=False) is False

    def test_ipv6_net_matches_ipv6_addr(self):
        nets = parse_allowlist("fd00::/8")
        assert ip_allowed("fd00::1", nets, allow_loopback=False) is True
        assert ip_allowed("2001:db8::1", nets, allow_loopback=False) is False


class TestRateLimitWhitelist:
    """2026-09-10 策略重定:业务域/运营只读默认豁免,高危端点改由 RATE_LIMIT_FORCED 点名"""

    def test_rag_prefix_is_exempt(self):
        assert is_rate_limit_whitelisted("/api/rag") is True
        assert is_rate_limit_whitelisted("/api/rag/stats") is True
        assert is_rate_limit_whitelisted("/api/rag/documents") is True
        assert is_rate_limit_whitelisted("/api/rag/search") is True
        assert is_rate_limit_whitelisted("/api/rag/verify") is True

    def test_eval_prefix_is_exempt(self):
        assert is_rate_limit_whitelisted("/api/eval") is True
        assert is_rate_limit_whitelisted("/api/eval/report") is True
        assert is_rate_limit_whitelisted("/api/eval/runs") is True

    def test_existing_console_prefixes_still_exempt(self):
        assert is_rate_limit_whitelisted("/api/health") is True
        assert is_rate_limit_whitelisted("/api/logs/events") is True
        assert is_rate_limit_whitelisted("/api/logs/events/stream") is True
        assert is_rate_limit_whitelisted("/api/response/policies") is True
        assert is_rate_limit_whitelisted("/api/auth/login") is True

    def test_operations_center_domains_are_exempt(self):
        """运营中心重灾板块(2026-09-10 前全部落 120/min 共桶)"""
        for path in (
            "/api/cases",
            "/api/cases/1/timeline",
            "/api/work-orders",
            "/api/work-orders/1/approve",
            "/api/agent-traces",
            "/api/agent-traces/stats",
            "/api/agent-traces/by-event",
            "/api/agent-traces/daily",
            "/api/agent-traces/event/7",
            "/api/observability/active-pipelines",
            "/api/observability/recent-pipelines",
            "/api/observability/recent-thought-chains",
            "/api/observability/thought-chain/7",
            "/api/security/events",
            "/api/security/anomalies",
            "/api/security/chains",
            "/api/causal/graph",
            "/api/causal/candidates",
            "/api/cad/status",
            "/api/audit-llm/pipeline/7",
            "/api/audit-llm/stats",
            "/api/tree/stats",
            "/api/tree/nodes",
            "/api/window/abc",
            "/api/guard/status",
            "/api/guard/signatures",
            "/api/rules",
            "/api/learn-loop/runs",
            "/api/post-mortems/1",
            "/api/ops/kpi",
            "/api/self-play/matches",
            "/api/phishing/stats",
            "/api/ndr/flows",
            "/api/edr/events",
            "/api/assets",
            "/api/kafka/status",
        ):
            assert is_rate_limit_whitelisted(path) is True, path

    def test_infra_endpoints_are_exempt(self):
        assert is_rate_limit_whitelisted("/metrics") is True
        assert is_rate_limit_whitelisted("/docs") is True
        assert is_rate_limit_whitelisted("/redoc") is True
        assert is_rate_limit_whitelisted("/openapi.json") is True

    def test_unrelated_api_is_not_exempt(self):
        """未归类的路径仍走全局限流(前缀不误伤:不按子串匹配)"""
        assert is_rate_limit_whitelisted("/api/ragazine") is False
        assert is_rate_limit_whitelisted("/api/evaluate") is False
        assert is_rate_limit_whitelisted("/api/cases-archive") is False
        assert is_rate_limit_whitelisted("/api/unknown-domain") is False
        assert is_rate_limit_whitelisted("/") is False
        assert is_rate_limit_whitelisted("/apix/cases") is False


class TestRateLimitForced:
    """高危/不可逆端点即使前缀已豁免,也必须计入限流(crit 桶)"""

    def test_high_risk_actions_are_forced(self):
        for path, method in (
            ("/api/response/execute", "POST"),
            ("/api/response/rollback", "POST"),
            ("/api/firewall/connect", "POST"),
            ("/api/firewall/rollback-all", "POST"),
            ("/api/guard/call", "POST"),
            ("/api/logs/ingest", "POST"),
            ("/api/logs/ingest/batch", "POST"),
            ("/api/logs/analyze", "POST"),
            ("/api/logs/reset-stuck", "POST"),
            ("/api/learn-loop/run", "POST"),
            ("/api/learn-loop/actions/3/apply", "POST"),
            ("/api/security/review", "POST"),
            ("/api/cad/thresholds", "PUT"),
            ("/api/cad/override/3", "POST"),
            ("/api/causal/query", "POST"),
            ("/api/cep/replay", "POST"),
            ("/api/sandbox/submit", "POST"),
            ("/api/self-play/review/run", "POST"),
            ("/api/phishing/detect/email", "POST"),
            ("/api/sources/revoke", "POST"),
        ):
            counted, namespace = rate_limit_decision(path, method)
            assert counted is True and namespace == "crit", (path, method, counted, namespace)

    def test_method_sensitive_entries(self):
        """/api/response/approvals:读豁免,审批动作强制"""
        assert rate_limit_decision("/api/response/approvals", "GET") == (False, None)
        assert rate_limit_decision("/api/response/approvals", "POST") == (True, "crit")
        assert rate_limit_decision("/api/response/approvals/9/approve", "POST") == (True, "crit")
        assert rate_limit_decision("/api/response/approvals/9/preview", "POST") == (True, "crit")

    def test_rules_write_only(self):
        assert rate_limit_decision("/api/rules", "GET") == (False, None)
        assert rate_limit_decision("/api/rules", "POST") == (True, "crit")
        assert rate_limit_decision("/api/rules/sigma/sig-1", "PUT") == (True, "crit")
        assert rate_limit_decision("/api/rules/sigma/sig-1/versions", "GET") == (False, None)

    def test_idempotent_operator_records_stay_exempt(self):
        """运营中心的幂等记录类写操作不应被点名限流(3s 轮询/演练批量调用)"""
        for path, method in (
            ("/api/phishing/drill/3/record", "POST"),
            ("/api/cases/3/status", "PUT"),
            ("/api/work-orders/3/status", "PUT"),
            ("/api/observability/diagnose", "POST"),
            ("/api/ops/kpi/snapshot", "POST"),
            ("/api/self-play/learned-rules/3/status", "POST"),
        ):
            assert rate_limit_decision(path, method) == (False, None), (path, method)

    def test_whitelisted_get_on_forced_prefix_is_not_forced(self):
        assert is_rate_limit_forced("/api/logs/events", "GET") is False
        assert is_rate_limit_forced("/api/causal/graph", "GET") is False
        assert is_rate_limit_forced("/api/guard/calls", "GET") is False

    def test_unclassified_path_still_uses_global_limiter(self):
        assert rate_limit_decision("/api/ragazine", "GET") == (True, "std")
        assert rate_limit_decision("/", "GET") == (True, "std")


class TestExtraWhitelistEnv:
    """SHARED_MEMORY_RATE_LIMIT_WHITELIST:现场追加前缀,不改代码"""

    def test_env_appended_prefix_is_exempt(self, monkeypatch):
        from config import settings
        monkeypatch.setattr(settings, "rate_limit_whitelist", "/api/custom-thing, /api/other")
        try:
            assert is_rate_limit_whitelisted("/api/custom-thing") is True
            assert is_rate_limit_whitelisted("/api/custom-thing/sub") is True
            assert is_rate_limit_whitelisted("/api/other") is True
            # 追加项不覆盖点名限流:forced 优先级更高
            assert rate_limit_decision("/api/custom-thing", "GET") == (False, None)
        finally:
            monkeypatch.undo()
            monkeypatch.setattr(settings, "rate_limit_whitelist", "")
            is_rate_limit_whitelisted("/api/custom-thing")

    def test_empty_env_keeps_default_behaviour(self):
        from config import settings
        assert not (settings.rate_limit_whitelist or "").strip()
        assert is_rate_limit_whitelisted("/api/unknown-domain") is False

    def test_env_addition_does_not_disable_whitelist(self, monkeypatch):
        """追加项只增不减:默认豁免的前缀不会因为设置了 env 而失效"""
        from config import settings
        monkeypatch.setattr(settings, "rate_limit_whitelist", "/api/custom-thing")
        try:
            assert is_rate_limit_whitelisted("/api/cases") is True
            assert is_rate_limit_whitelisted("/api/custom-thing") is True
            assert rate_limit_decision("/api/cases", "GET") == (False, None)
            # forced 点名优先级高于 whitelist:数据源 ingest 即便前缀被追加豁免仍限流
            assert rate_limit_decision("/api/logs/ingest", "POST") == (True, "crit")
        finally:
            monkeypatch.setattr(settings, "rate_limit_whitelist", "")


class TestJwtRevoke:
    def test_logout_blocks_jti(self):
        async def t():
            from auth import create_access_token, decode_access_token, revoke_jti
            import jwt as _jwt
            from config import settings
            token = create_access_token("alice", role="operator")
            payload = _jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
            await decode_access_token(token)
            await revoke_jti(payload["jti"], ttl_sec=60)
            from fastapi import HTTPException
            try:
                await decode_access_token(token)
                raise AssertionError("revoked token should 401")
            except HTTPException as e:
                assert e.status_code == 401
                assert "revoked" in str(e.detail).lower()
        _run(t())


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
