"""
EDR 融合 — Sysmon / Windows Event Log 接入与跨源关联

子模块:
  edr_adapter      — EDR 数据接入适配器（Kafka 消费 / API 接收）
  sysmon_parser    — Sysmon 事件解析（EventID 1-25）
  winevent_parser  — Windows Event Log 解析（Security / System）
  cross_correlator — 网络流量 × 终端遥测跨源关联
"""
