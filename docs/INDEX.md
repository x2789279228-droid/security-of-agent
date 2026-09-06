# 文档索引

本目录是 **shared-memory-platform** 的全部文档。

## 学习与上手

> 推荐第一次接触本项目的人从这里开始。

- **[study-guide/知识手册.md](./study-guide/知识手册.md)** ⭐ — **主推荐**：一份连贯、贯穿式、可从头读到尾的学习手册（18 章，71 KB）
- **[study-guide/速查.md](./study-guide/速查.md)** — 5 分钟读懂（评委/速通视角，1 页）
- **[study-guide/总览-PDF风.md](./study-guide/总览-PDF风.md)** — 项目总览·PDF 排版版（25-40 页，彝海 PDF 风格，配图丰富）
- **[study-guide/](./study-guide/README.md)** — 完整的项目学习手册（11 篇 + 速查 + 知识手册 + PDF 总览）
  - [00 项目地图](./study-guide/00-overview.md)
  - [01 架构总览](./study-guide/01-architecture.md)
  - [02 数据流与事件生命周期](./study-guide/02-data-flow.md)
  - [03 后端核心模块](./study-guide/03-backend-modules.md)
  - [04 Flink 流处理作业](./study-guide/04-flink-jobs.md)
  - [05 平台自审计体系](./study-guide/05-self-audit.md)
  - [06 前端架构与页面](./study-guide/06-frontend.md)
  - [07 数据模型与消息契约](./study-guide/07-data-model.md)
  - [08 部署、运维与调优](./study-guide/08-deployment.md)
  - [09 推荐学习路径](./study-guide/09-learning-path.md)
  - [10 常见问题与陷阱](./study-guide/10-faq.md)

## 运维与生产化

- [deployment.md](./deployment.md) — 部署手册（端口矩阵、TLS、CI/CD）
- [advanced_capabilities.md](./advanced_capabilities.md) — NDR/EDR/威胁情报/0day/反钓鱼的对接与验证
- **技术栈升级提案**（滚动 5 版，v1→v5，每版在上一版基础上"修正 + 反例 + 落地"）
  - [upgrade-proposals/2026-q3-tech-stack-upgrade.md](./upgrade-proposals/2026-q3-tech-stack-upgrade.md) — v1.0（初版基线，2026-08-25）
  - [upgrade-proposals/2026-q3-tech-stack-upgrade-v2.md](./upgrade-proposals/2026-q3-tech-stack-upgrade-v2.md) — v2.0（Flink 2.2 LTS + OCSF + UEBA-ML + Tier 1 分诊 + MCP 2025-11）
  - [upgrade-proposals/2026-q3-tech-stack-upgrade-v3.md](./upgrade-proposals/2026-q3-tech-stack-upgrade-v3.md) — v3.0（实装度核验 + 6 大反例）
  - [upgrade-proposals/2026-q3-tech-stack-upgrade-v4.md](./upgrade-proposals/2026-q3-tech-stack-upgrade-v4.md) — v4.0（24 项 + 6 大生产反例 + 5 维度交叉验证）
  - [upgrade-proposals/2026-q3-tech-stack-upgrade-v5.md](./upgrade-proposals/2026-q3-tech-stack-upgrade-v5.md) — v5.0（揭榜挂帅合规 + TCO 矩阵 + 7/14/30 天决策树 + 12 大反例）⭐ **建议执行版**
  - [upgrade-proposals/2026-q3-red-blue-selfplay.md](./upgrade-proposals/2026-q3-red-blue-selfplay.md) — v9 红蓝自博弈(已落地 MVP)
  - [upgrade-proposals/2026-q3-tool-behavior-signature.md](./upgrade-proposals/2026-q3-tool-behavior-signature.md) — Tool 行为签名 / UEBA-for-AI（PR1–PR6 已落地,创新矩阵 #7）
  - [upgrade-proposals/2026-q3-tee-gm-crypto.md](./upgrade-proposals/2026-q3-tee-gm-crypto.md) — TEE 推理 + 国密合规（创新矩阵 #10；取代 v5 §4.2 国密草图）

## 仓库根目录的其它文档

- [../README.md](../README.md) — 项目自述（启动、快速使用）
- [../security_audit_report.md](../security_audit_report.md) — 渗透审计报告（早期）

## 安全审计与修复计划

- [security-audit/AUDIT_REPORT.md](./security-audit/AUDIT_REPORT.md) — 平台安全审计
- [security-audit/attack-perf-large-scale-2026-09-02.md](./security-audit/attack-perf-large-scale-2026-09-02.md) — 大规模攻击压测
- [security-audit/threat-policy-uncertain-fix-plan-2026-09-02.md](./security-audit/threat-policy-uncertain-fix-plan-2026-09-02.md) — 问题 3：未知 threat_type 静默放过 → 分级降噪 / 策略外置 / 分类树 / 行为基线

## 跨项目审计

`D:\揭榜挂帅\audit\` 下有项目状态审查与历史排查报告：

- [审计 · 项目状态桌面审查](D:\揭榜挂帅\audit\00-项目状态桌面审查.md) — mavis 经理视角的现状评估与开放风险
- [审计 · 日志中心根因排查报告](D:\揭榜挂帅\audit\02-日志中心根因排查报告.md) — 80% 高危事件卡"待审计"问题的根因与修复

## 贡献

- 文档错漏请直接修改并提 PR
- 章节有缺失请在 issue 中标注
- 维护者：mavis
- 文档最近一次大审计：2026-08-25 15:30（与 v5 升级方案同步；修正了 Flink 1.18→1.19.3 错记）
