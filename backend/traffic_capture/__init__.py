"""
NDR 流量采集引擎 — 高速抓包 + 流聚合 + PCAP 存储

子模块:
  capture_engine  — 网卡抓包（libpcap / DPDK / AF_PACKET）
  flow_aggregator — 五元组流聚合与超时管理
  pcap_store      — PCAP 文件轮转、分层存储与清理
"""
