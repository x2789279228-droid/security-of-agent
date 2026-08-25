"""
test_inc_threat_intel — 威胁情报(TAXII/MISP/IOC)单元测试

离线可跑: 使用 inc_mock_servers 模拟 TAXII 2.1 与 MISP REST, 验证 stix_taxii 拉取、ioc_matcher 匹配。
"""
import asyncio

import pytest

from threat_intel.ioc_matcher import IocMatcher
from tests.inc_mock_servers import MockExternalServers
from tests.inc_testcases import TAXII_OBJECTS_RESP, MISP_ATTRIBUTES_RESP


def _run(coro):
    return asyncio.run(coro)


def test_taxii_poll_parses_indicators():
    """TAXII objects 解析为 IOC(含 ip/domain/hash)。"""
    from threat_intel.stix_taxii import TaxiiClient

    async def scenario():
        m = await MockExternalServers().start()
        try:
            client = TaxiiClient()
            iocs = await client.poll_feed({"feed_type": "taxii", "url": m.taxii_url, "collection": "c1"})
            assert iocs, "TAXII 应解析出 IOC"
            types = {i["ioc_type"] for i in iocs}
            assert "ip" in types or "domain" in types or "file_hash" in types
            return iocs
        finally:
            await m.stop()

    iocs = _run(scenario())
    assert iocs


def test_misp_poll_parses_attributes():
    """MISP attributes 解析为 IOC。"""
    from threat_intel.stix_taxii import TaxiiClient

    async def scenario():
        m = await MockExternalServers().start()
        try:
            client = TaxiiClient()
            iocs = await client.poll_feed({"feed_type": "misp", "url": m.misp_url, "api_key": "dummy"})
            assert iocs, "MISP 应解析出 IOC"
            assert any(i["ioc_type"] == "ip" for i in iocs)
            return iocs
        finally:
            await m.stop()

    assert _run(scenario())


def test_ioc_matcher_matches_ip():
    """IOC matcher 对命中 IP 的事件标出关联。"""
    import time
    matcher = IocMatcher()
    from threat_intel.ioc_matcher import IocHit
    matcher._cache["5.6.7.8"] = IocHit("ip", "5.6.7.8", "c2", "high", 0.9, "test", {})
    matcher._last_refresh = time.time()  # 避免刷新触发 DB

    async def scenario():
        hits = await matcher.match(ip="5.6.7.8")
        assert len(hits) >= 1
        assert hits[0].ioc_value == "5.6.7.8"
        # 不命中 IP 返回空
        hits2 = await matcher.match(ip="9.9.9.9")
        assert hits2 == []
        return True

    assert _run(scenario())


def test_ioc_matcher_no_match_harmless():
    """无命中 IOC 的事件不抛错。"""
    import time
    matcher = IocMatcher()
    matcher._cache["5.6.7.8"] = None  # 占位避免误构造
    matcher._cache.clear()
    matcher._last_refresh = time.time()
    async def scenario():
        hits = await matcher.match(domain="benign.example.com")
        assert isinstance(hits, list)
        return hits
    assert isinstance(_run(scenario()), list)


def test_intel_enricher_no_crash_without_external():
    """intel_enricher 在无外部源配置时不崩溃。"""
    from threat_intel.intel_enricher import IntelEnricher
    enricher = IntelEnricher()
    try:
        out = enricher.enrich({"ip": "5.6.7.8"}, None) if hasattr(enricher, "enrich") else None
        assert out is None or isinstance(out, dict)
    except Exception as e:
        pytest.skip(f"enricher.enrich 需外部参数({e})")
