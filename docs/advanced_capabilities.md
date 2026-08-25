# 高级安全能力：NDR / EDR / 威胁情报 / 0day / 反钓鱼 — 对接与验证

> 这些能力代码实现相对完整（backend 模块、`app.py` 接线、`config.py` 开关都在），但**默认全部关闭**
> 且依赖外部数据源/基础设施。本文档说明如何在生产启用与对接，以及如何离线验证。
> 关联单元测试见 `backend/tests/test_inc_*.py`（全部离线可跑，不依赖真实外部服务）。

## 0. 共同说明

- 每项能力由 `config.py` 中的 `*_enabled` 开关控制，默认 `False`。
- 外部 HTTP 对接统一用 **aiohttp**（已在依赖中）；离线测试用 `tests/inc_mock_servers.py` 起的
  aiohttp 服务器模拟 CAPE/TAXII/MISP。
- 启用的统一入口在 `backend/app.py`：按开关 `import` 对应模块并 `start()` / 注册 handler。
- LLM 增强（可选）分别由 `llm_*_enabled` + 预算控制，用于生成叙事/解读，不影响基础检测。

---

## 1. NDR 流量分析（+ 加密流量 JA3/TLS）

**代码位置**：`traffic_capture/`（采集/流聚合/pcap 落盘）、`encrypted_traffic/`（JA3/JA3S/JA4、TLS 元数据、证书分析、mitm 解密代理）。

**对接方式**：`CaptureEngine` 在授权网卡上基于 **scapy (libpcap)** 采集，数据包 → `FlowAggregator`/`PcapStore`/`ProtocolDissector` 处理管线（handler 注册见 `app.py`），结果写 Kafka（`ndr-flows`/`ndr-tls-sessions`/`ndr-pcap-meta`）。

**配置**（`config.py`）：
```
capture_enabled=true            # 开启采集
capture_interface=eth0          # 授权抓包网卡
capture_method=libpcap          # libpcap(可用) | af_packet/dpdk(占位,可选高性能)
capture_bpf_filter=''           # BPF 过滤
mitm_enabled=false              # TLS 解密代理(可选,需独立部署 CA+mitmproxy)
tls_risk_*                       # 证书/JA3 风险权重
```

**生产化前提**：
- 宿主机 **root 抓包权限** + `scapy`（依赖列表已含）。
- 可选增强：`af_packet`/`dpdk` 后端、`mitm_proxy`（透明解密，需部署自签 CA 到终端信任链）——二者的 `run()` 均为占位/脚本生成，属可选高性能路径，非必需。

**离线验证**：`python -m pytest tests/test_inc_ndr.py`（JA3 计算/GREASE 过滤、TLS 风险评分、证书自签判定）。

---

## 2. EDR 融合

**代码位置**：`edr_fusion/`（sysmon_parser、winevent_parser、edr_adapter、cross_correlator、llm_correlation）。

**对接方式**：`edr_adapter.ingest(event_dict)` 用 **HTTP 推送**接收 EDR/Sysmon 事件；同时可消费 Kafka topic（`sysmon_kafka_topic`/`winevent_kafka_topic`）从数据总线取 Sysmon/Windows Event 日志。

**配置**：
```
edr_enabled=true
edr_correlation_window=300      # 跨源关联窗口(秒)
sysmon_kafka_topic / winevent_kafka_topic   # Kafka 消费 topic
```

**生产化前提**：对接真实 EDR/Sysmon → 通过 HTTP `ingest()` 推入或经 Kafka 汇聚。字段契约与 `sysmon_parser`/`winevent_parser` 解析一致（Windows Event XML / JSON）。

**离线验证**：`python -m pytest tests/test_inc_edr.py`（Sysmon XML 解析、dict 解析、ingest 归一化）。

---

## 3. 威胁情报（MISP / TAXII / IOC）

**代码位置**：`threat_intel/`（stix_taxii 客户端、ioc_matcher、reputation、intel_enricher、llm_context）。

**对接方式**：`TaxiiClient.poll_feed(feed_config)` 拉取 IOC——支持
- **TAXII 2.1**：`feed_type=taxii`, `url`, `collection`
- **MISP REST**：`feed_type=misp`, `url`, `api_key`

拉取结果可写入 DB / 供 `ioc_matcher` 做事件 IOC 匹配。

**配置**：
```
intel_enabled=true
misp_url / misp_api_key / misp_verify_ssl
taxii_url / taxii_user / taxii_password
intel_poll_interval=60          # 拉取间隔(分钟)
```

**生产化前提**：可访问的 MISP/TAXII 服务器（外网或内网情报源），含凭据。

**离线验证**：`python -m pytest tests/test_inc_threat_intel.py`（mock TAXII/MISP 拉取、IOC matcher 命中）。

---

## 4. 0day 检测（沙箱 + 行为分析）

**代码位置**：`zeroday_detect/`（sandbox_connector、behavior_analyzer、variant_cluster、llm_behavior）。

**对接方式**：`sandbox_connector` 对接 **CAPE / Cuckoo** 沙箱 API（`submit_file`/`submit_url` → `get_status`/`get_report`/`wait_for_completion`）；`sandbox_auto_submit` 对高危告警自动提交样本。

**配置**：
```
sandbox_enabled=true
sandbox_type=cape              # cape | cuckoo
sandbox_api_url=http://<沙箱>:8090
sandbox_api_key=...
sandbox_auto_submit=false       # 高危自动提交
sandbox_timeout=300
```

**生产化前提**：独立部署 **CAPE/Cuckoo 沙箱**（注意：CAPE 官方镜像在 Docker Hub 不可用，须替换为真实镜像，见 `docs/deployment.md`）。

**离线验证**：`python -m pytest tests/test_inc_zeroday.py`（mock CAPE 的 submit/status/report/wait 全链路）。

---

## 5. 反钓鱼（7 类检测器）

**代码位置**：`phishing_guard/`（email/web/domain/attachment/sms/qrcode/bec 检测器 + scoring 聚合 + llm_dimension）。

**对接方式**：通过 **API**（`routers/phishing`）接收邮件/URL/短信/二维码/BEC 内容检测——`PhishingGuard.detect_email/detect_web/...` 对结构化 Request 返回 `PhishingVerdict`。**不主动连 SMTP/IMAP**，生产通过邮件系统以 Webhook/网关推入或由 SIEM 提取正文调用。

**配置**：
```
# 反钓鱼本身无独立外部依赖; LLM 增强可选:
llm_phishing_enabled=false
```

**生产化前提**：邮件系统 → 网关/Webhook → `/api/phishing/*` 推入邮件全文/URL；或 SIEM 侧提取匹配 `EmailPhishingRequest` 等结构后调用。

**离线验证**：`python -m pytest tests/test_inc_phishing.py`（7 类检测器 + 聚合 verdict）。

---

## 6. 测试覆盖小结（本次新增）

| 能力 | 测试文件 | 通过数 |
|---|---|---|
| NDR/JA3/TLS/证书 | `tests/test_inc_ndr.py` | 7 |
| EDR | `tests/test_inc_edr.py` | 7 |
| 威胁情报 | `tests/test_inc_threat_intel.py` | 5 |
| 0day/沙箱 | `tests/test_inc_zeroday.py` | 6 |
| 反钓鱼 | `tests/test_inc_phishing.py` | 9 |
| 基座 | `tests/inc_mock_servers.py` / `tests/inc_testcases.py` | — |

全部**离线可跑**（不依赖真实 CAPE/MISP/TAXII/EDR/邮件/抓包），全量 `python -m pytest tests/` 232 passed。
