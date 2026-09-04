# 攻击闭环修复计划（2026-08-29）

基于杀伤链复测 `demo_1787978353`（PORT_SCAN → BRUTE_FORCE → C2_BEACON → DATA_EXFIL）。

## 问题与优先级

| 优先级 | 问题 | 根因 | 修复 |
|--------|------|------|------|
| P0 | 响应日志只有 `policy_match`，运营侧看不到 `block_ip`/`rate_limit` | Orchestrator 只调 `log_threat`，未把 `BatchActionResult` 逐条 `log_action`；API `to_dict` 丢掉 `action_result` | 执行后逐条落库；API 返回 `execution_mode`/`verified` |
| P0 | SSH 假成功：无密钥仍尝试 `/root/.ssh/id_rsa`，失败再 stub | `SSHTransport.enabled` 只看 host+user；compose 默认密钥路径与 entrypoint 复制路径不一致 | 无有效私钥则禁用 SSH；默认密钥指向 `/tmp/ssh/id_rsa` |
| P1 | 新 session 并进旧案 `CASE-…DA1E04F2` | 同 session 未命中后回落到「同 src_ip + 30min」 | 有 `session_id` 时只按 session 聚合，禁止跨 session 吸案 |
| P1 | 标题停在 `[MEDIUM] PORT_SCAN`；无工单；状态停在 `open` | 聚合路径不改写标题；`_maybe_auto_dispatch` 仅新建案触发，medium 起步永远不派单 | 随杀伤链升级标题/类型；优先级升到 high/critical 时补派单并推进 `responding` |
| P1 | PORT_SCAN 被 LLM 抬成 `critical`；phantom MITRE | 合并取威胁轮最高严重度；忠实度闸不剥离幻觉 ATT&CK | 按事件/Sigma 封顶；从 `mitre_techniques` 去掉证据中不存在的 Txxxx |
| P2 | Flink `No running jobs` | 作业未提交 | 重新提交 LogValidation / AnomalyDetection / Sigma 聚合作业 |

## 非目标

- 不在本次强行打通 Windows 防火墙真封禁（宿主机需存在可挂载的 SSH 私钥且 sshd 可达）。
- 不重写 Audit-LLM 提示词；忠实度仍走软降级，只约束严重度与 MITRE 字段。

## 验收（已复测）

Session `fix_1787980484`（事件 #564–#567）：

1. 独立案例 `CASE-20260829-DE7CEE61`，标题 `[CRITICAL] DATA_EXFIL - 192.168.1.100`，`status=responding`，工单 `WO-20260829-F3C89C5F`。
2. 响应日志含 `block_ip` / `rate_limit` / `send_alert`，`execution_mode` 为 `stub` 或 `log`（无宿主机 SSH 私钥，属预期）。
3. PORT_SCAN 审计 severity=`high`（不再 critical）；C2 幻觉技术写入 `stripped_mitre`（如 T1090.002）。
4. 单元测试：`test_case_automation` 10 passed；veto/faithfulness/response logs 合计 55 passed。
5. Flink：`LogValidationJob`、`AnomalyDetectionJob` RUNNING；`SigmaThresholdAggregationJob` 曾 RESTARTING。

部署：开发机已 `docker cp` 热更新 backend。正式环境请：

```bash
docker compose up -d --build backend
docker exec soc-flink-jobmanager /opt/flink/submit-jobs.sh flink-jobmanager
```
