# OTel Trace 采样策略

> 对应升级建议 #10「OTel 完整化」之采样部分。
> 结论：**保持全量导出 + 关键 span 由 SDK 侧 `soc.importance` 标记**，不启用 collector 尾部采样。

## 为什么保持全量导出

- **事件量级**：本 SOC 平台的 trace 由 Flink 作业 + 后端审计流水线产生，单日 span 量在中低规模，全量导出对 Tempo/网络带宽可承受，无需为省存储而丢失链路保真。
- **保真优先**：全量导出保证任意一次告警/审计可完整回溯（公安部 176 号令「全程溯源」要求）。若按比率采样（如 50%），可能丢掉关键告警链路。
- **tail_sampling 有已知 bug**：当前 otel-collector 0.159.0 的 `tail_sampling` 处理器存在 span 丢弃问题，强行启用会**丢失重要 trace**，得不偿失。已从 `config/otel/otel-collector.yaml` 移除。

## `soc.importance` 属性（关键 span 标记）

所有打点都在 span 上设置 `soc.importance`，用于按重要性过滤，无需开采样器：

| 取值 | 含义 | 打点位置 |
|---|---|---|
| `important` | 告警 / 审计关键链路 | `pipeline_tracer.py`（关键审计阶段）、`kafka_consumer.py`（`security-alerts` 消费）、告警场景 |
| `normal` | 常规日志/事件链路 | `HttpTraceMiddleware`（HTTP 请求兜底）、`flink TraceUtil.startSpan` 默认 |

两侧一致性（已核实）：
- **backend**：`observability/pipeline_tracer.py` L151、`kafka_consumer.py` L309、`otel_setup.py` HttpTraceMiddleware L111。
- **flink（Java）**：`com.soc.util.TraceUtil.startSpan` L134 默认 `soc.importance = "normal"`，告警作业内命中攻击链时标 `important`。

## 过滤方式（Grafana / Jaeger）

在 TEMPO 里按重要性过滤 trace：

```bash
{ .soc.importance = "important" }
```

- Grafana：`config/grafana/provisioning/dashboards/tempo-apm.json` 已含「Important/Audit Traces」面板，固定用上述 traceql。
- Jaeger：`http://localhost:16686` 查询页可按该 span tag 过滤。

## 未来：可逆的按重要性采样

若未来事件量放大到必须裁剪，推荐**可逆升级路径**（不一次性启用有 bug 的 tail_sampling）：
1. 先全部归一化 `soc.importance` 标记（本页所述，已完成）。
2. 升级 otel-collector 到修复 tail_sampling 丢弃问题的稳定版后，再考虑按 `soc.importance = "important"` 100% 保留、`normal` 按比率（`TraceIdRatioBased`）裁剪。
3. 切换前用 Grafana 重要性面板核对关键链路不被裁剪。

> 当前 SOC 量级下此步未做；仅在全量导出基础上保留可扩展的标记来支撑未来按重要性采样。
