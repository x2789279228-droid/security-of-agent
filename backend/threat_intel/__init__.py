"""
威胁情报对接 — STIX/TAXII + MISP + IOC 匹配 + 信誉查询

子模块:
  stix_taxii     — TAXII 2.1 客户端 / STIX Bundle 解析
  ioc_matcher    — IOC 实时匹配引擎（IP/域名/哈希/URL）
  reputation     — IP/域名信誉查询（多源聚合）
  intel_enricher — 事件富化（将 IOC 命中结果附加到安全事件）
"""
