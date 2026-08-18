"""
流量基线增强 — 网络流量画像 + 对等组分析 + 季节性分解

子模块:
  traffic_profiler — 主机/子网流量画像（带宽、连接率、协议分布）
  peer_group       — 对等组行为分析（同角色主机偏离检测）
  seasonal         — 时间序列季节性分解（STL）+ 异常检测
  llm_anomaly      — P0.S 流量大模型：3σ 异常后 LLM 语义判定
"""

from .llm_anomaly import llm_anomaly_engine, should_trigger_llm

__all__ = ["llm_anomaly_engine", "should_trigger_llm"]
