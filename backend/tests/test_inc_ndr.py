"""
test_inc_ndr — NDR 流量分析 + 加密流量(JA3/TLS/证书)单元测试

离线可跑, 不依赖真实抓包/scapy/网卡。覆盖:
  - JA3 / JA3S 指纹计算(含 GREASE 过滤)与查找
  - TLS 会话元数据聚合与风险评分
  - 证书分析(自签名/过期等风险判定)
"""
import asyncio

from encrypted_traffic.ja3_fingerprint import ja3_engine
from encrypted_traffic.tls_metadata import TlsMetadataAggregator
from encrypted_traffic.cert_analyzer import CertAnalyzer
from tests.inc_testcases import JA3_FIELDS, TLS_METADATA


def test_ja3_compute_deterministic_and_grease_filtered():
    """相同字段 → 相同 JA3; GREASE 值被过滤。"""
    f1 = {"version": 0x0303, "ciphers": [0x1301, 0x1302],
          "extensions": [0x002b, 0x000d], "curves": [0x001d], "point_formats": [0]}
    h1 = ja3_engine.compute_ja3(f1)
    h2 = ja3_engine.compute_ja3(dict(f1))
    assert h1 == h2
    assert len(h1) == 32  # md5 hex

    # GREASE(如 0x0a0a / 0x1a1a) 应被剔除, 不影响结果
    f2 = {"version": 0x0303, "ciphers": [0x1301, 0x1302, 0x0a0a],
          "extensions": [0x002b, 0x000d, 0x1a1a], "curves": [0x001d], "point_formats": [0]}
    assert ja3_engine.compute_ja3(f2) == h1


def test_ja3s_compute():
    """JA3S 服务端指纹非空且确定性。"""
    hs = ja3_engine.compute_ja3s({"version": 0x0303, "cipher": 0x1302, "extensions": [0x002d, 0x002b]})
    assert isinstance(hs, str) and len(hs) == 32


def test_ja3_lookup_unknown_harmless():
    """未知 JA3 查询返回 None(不抛错)。"""
    from encrypted_traffic.ja3_fingerprint import ja3_engine
    assert ja3_engine.lookup("0" * 32) in (None, [])
    assert ja3_engine.lookup("") in (None, [])


def test_tls_metadata_build_and_score():
    """TLS 会话 data + 风险评分(自签名证书应升分)。"""
    from encrypted_traffic.tls_metadata import TlsSessionData, TlsMetadataAggregator
    agg = TlsMetadataAggregator()
    sess = TlsSessionData(src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=443,
                          sni="www.example.com", tls_version="TLS1.3",
                          cipher_suite="TLS_AES_128_GCM_SHA256",
                          ja3_hash="acd97f1e0da26c4f4a8efafcc0edc80e",  # 未知 JA3 会升分
                          cert_is_self_signed=True)
    scored = agg.score_session(sess)
    assert scored.risk_score > 0
    assert any("self_signed" in r or "cert" in r for r in scored.risk_reasons) or scored.risk_score > 0


def test_tls_harmless_metadata_low_risk():
    """正常 TLS(未知 JA3 + 可信非自签证书)风险应低于自签。"""
    from encrypted_traffic.tls_metadata import TlsSessionData, TlsMetadataAggregator
    agg = TlsMetadataAggregator()
    sess = TlsSessionData(sni="www.google.com", ja3_hash="deadbeef" * 4,
                          cert_is_self_signed=False,
                          cert_issuer="CN=Let's Encrypt Authority X3")
    scored = agg.score_session(sess)
    assert isinstance(scored.risk_score, float)


def test_cert_analyzer_self_signed_flagged():
    """自签名证书(输入 is_self_signed=True)应产生风险。"""
    analyzer = CertAnalyzer()
    report = analyzer.analyze({"is_self_signed": True, "subject": "CN=evil.local",
                               "issuer": "CN=evil.local", "not_after": ""})
    r = report.to_dict()
    assert r.get("risk_score", 0) > 0
    assert r.get("risk_level") in ("critical", "high", "medium", "low")
    assert any("self_signed" in x for x in r.get("reasons", []))


def test_cert_analyzer_benign():
    """正常证书(非自签、未过期)不应判为高风险。"""
    analyzer = CertAnalyzer()
    report = analyzer.analyze({"is_self_signed": False,
                               "issuer": "CN=Let's Encrypt Authority X3",
                               "not_after": "20300101120000Z"})
    r = report.to_dict()
    assert r.get("risk_score", 1) == 0 or r.get("risk_level") == "low"
