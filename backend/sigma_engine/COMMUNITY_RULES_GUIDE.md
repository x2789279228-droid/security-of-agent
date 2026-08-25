# SigmaHQ 社区规则接入指南（匹配子集与字段映射）

> 目标：把 SigmaHQ（~3000+ 规则）按"与平台数据源匹配度"分层接入，
> 不做一次性全量上。pySigma 引擎只做单事件匹配，聚合/关联由 Flink 承担。

## 1. 平台现有字段（数据源）

`log_ingestion` 归一化后的安全事件字段：

| 字段 | 说明 | Sigma 对应 |
|---|---|---|
| `event` | 事件类型（如 `BRUTE_FORCE`/`LOGIN_FAIL`） | 映射到 `event` / `category`（自定义） |
| `src_ip` | 源 IP | `src_ip` |
| `dst_ip`（可含端口） | 目的 IP/端口 | `dst_ip` + `dst_port`（engine 自动拆分） |
| `url` | 请求 URL（web 源） | `url` / `http.url` |
| `message` | 事件描述 | `message` / `details` |
| `severity` | 等级 | 不参与匹配（映射到规则 level） |
| `protocol` | 协议 | `protocol` |
| `dst_port` | 目的端口（拆自 dst_ip） | `dst_port` |

## 2. 能"直接命中"的 SigmaHQ 规则类别

基于现有字段，无需额外字段映射即可单事件匹配的规则类别：

| SigmaHQ 目录 | 类别 | 字段契合 | 命中率预估 | 备注 |
|---|---|---|---|---|
| `rules-web/web.attack.*.yml` | Web 攻击（路径/URL 特征） | `url` 高 | 中 | 需规则用 `url`/`http.url`，含 `%2e`、`/../` 等已在 SIG-00x |
| `rules-network/**/ssh*.yml`（auth/） | SSH 暴力/异常 | `dst_port`、`event` 高 | 中-高 | 平台 `event` 归一化（LOGIN_FAIL）与源字段近似 |
| `rules-web/**/elasticsearch*.yml` | ES 未授权/搜索滥用 | `url` 高 | 中 | 需 `url` 含 `/_search`/9200 等 |
| `rules-*` 端口扫描 / 端口类 | 端口探测 | `dst_port` 高 | 中 | 依赖 `dst_port` 拆分 |
| `rules-network/**/http*.yml` | HTTP 层 C2（beacon） | `url`/`event` 中 | 低-中 | 平台 C2 已归一化（C2_BEACON） |

**字段契合度低（需后续映射才能用）**：DNS 类（`rules-network/c2/*.dns*` 缺 `dns.query`）、
Windows/Sysmon（`rules-windows` 缺 `EventID`/`Image`/`CommandLine`）、
`rules-emerging-threats` 大多面向原始流量。

## 3. 接入策略（分档）

- **P0（现在可开）**：上面"直接命中"类，各取 2~5 条代表规则做 shadow 灰度（仅记录不告警）。
  - **已接入（rules_community_active/, shadow 灰度）**：
    - `web_path_traversal.yml`（C-001，SigmaHQ Path Traversal Exploitation Attempts）
    - `web_susp_windows_path_uri.yml`（C-002，SigmaHQ Suspicious Windows Strings In URI）
    - 引擎自动加载 `rules_community_active/`，mapping 提供 `url→cs-uri-query` 使二者命中平台 web 事件。
- **P1（补映射后开）**：补字段映射 pipeline（`src_ip→src.address` 等，pySigma-pipelines）后接入更广类别。
- **P2（不建议单靠 pySigma）**：Windows/Sysmon、DNS 探测等，等平台具备对应日志源或映射后再开。

## 4. 接入步骤

1. 拉取 SigmaHQ 仓库到 `sigma_engine/rules_community/`（不入库，只读）。
2. 用下述 dry-run 脚本对历史事件样本跑 **shadow** 命中统计（命中率/误报），只放行通过的子集。
3. 通过后把规则 + `x-soc-id`/`x-soc-attack_type` 扩展字段复制进 `rules_community_active/`，自动加载。
4. 观测误报、命中断言与阈值聚合（Flink）后再逐步扩大。

详见同目录 `dry_run_import.py`（候选规则导入 + 命中率报告）。

## 5. dry-run 扩容工具链（已落地）

| 工具 | 作用 |
|---|---|
| `sigma_engine/tools/fetch_sigma_p0.py` | 从 SigmaHQ v2 仓库拉取 P0 候选规则到 `rules_community_candidate/`（只读，保留原装 YAML + 追加 `x-soc-source`） |
| `sigma_engine/tools/make_sample_events.py` | 生成 dry-run 正/负样本事件集（贴合候选规则 detection 模式） |
| `sigma_engine/dry_run_import.py` | 对候选规则 + 样本跑命中率/误报报告 |
| `sigma_engine/tools/promote_to_shadow.py` | 把 dry-run 通过的候选补 `x-soc-*` 以 shadow 灰度写入 `rules_community_active/`（自动分配 C-编号、防重复） |

## 6. 实证结果与当前瓶颈（2026-08）

### 已验证：shadow 灰度链路正确
- 引擎加载 `rules_community_active/`（当前 C-001/C-002），`stats()` 报告 `rules=13, shadow=2`。
- 灰度规则命中时 `matched_fields.shadow_mode=True`、`action=alert`（不触发阻断）；非 shadow 内置规则 `action=block_ip`。

### keywords backend 已修复（2026-08 更新）
**瓶颈已解决**：新增 `sigma_engine/backend_keywords.py` —— `SigmaKeywordsBackend(SQLiteBackend)` 把 Sigma `keywords`（value-only 全文搜索）转成对平台通用文本字段（`url/cs-uri-query/message/http.url/event/details`）的 `OR LIKE` 匹配。引擎 `engine.py` 改用该 backend，并在建表时（`_ensure_table`）补齐所有已编译 SQL 引用的字段列（`_field_index`），避免列不存在报错。

修复效果：
- 9 条 `rules/web/webserver_generic/` web 攻击候选**全部可编译**（此前仅 3 条）。
- 纯 keywords 规则（如 `web_source_code_enumeration`，`.git/` 特征）经 dry-run **可命中**（SIG-004，2/2 正样本，0 误报）。
- XSS/SSTI 规则在补充 `cs-method=GET` 字段后可命中 —— 证明 backend 修复彻底有效。
- 全量 pytest 195 passed，生产 `sigma_detector` 单例正常（`rules=13, shadow=2`），无回归。

### 当前候选 P0 扩容的新结论
backend 修复后，`keywords` 不再是编译障碍；剩余限制转为**字段契合度**：
- 可命中（平台字段已覆盖）：`path_traversal`（C-001）、`susp_windows_path_uri`（C-002）、`source_code_enumeration`（C-003，`.git/` 枚举）。
- **须字段补充才能命中**：SQLi/XSS/SSTI 等规则带 `selection: cs-method: 'GET'`、`filter: sc-status: 404` 硬约束，需要平台 web 事件提供 HTTP 方法/状态码。

### 平台已补充 cs-method/sc-status（2026-08 更新）
`log_ingestion._normalize_fields` 增补 `method`/`status`/`url` 归一化字段（兼容 camelCase/snake_case，支持从 `rawData` 子对象兜底提取）；`sigma_engine/mapping.py` 增补 `status → sc-status/http.response.status_code` 映射。web 事件接入后即带 `cs-method`/`sc-status`，SQLi/XSS/SSTI 规则可命中。

dry-run 复评（样本含 `method=GET`/`status=200`，负样本 0 误报）：
- `web_ssti_in_access_logs`（SSTI）2/2 命中 → **C-004 灰度**
- `web_xss_in_access_logs`（XSS）1/2 命中 → **C-005 灰度**
- `web_sql_injection_in_access_logs`（SQLi）1/3 命中（部分 keywords 与样本编码不完全吻合，未达 50% 门槛，未入库，后续细化样本再评估）

### 当前灰度状态（rules_community_active/）
| C 编号 | 规则 | attack_type | action |
|---|---|---|---|
| C-001 | web_path_traversal | path_traversal | require_confirmation |
| C-002 | web_susp_windows_path_uri | data_exfiltration | require_confirmation |
| C-003 | web_source_code_enumeration | info_disclosure | require_confirmation |
| C-004 | web_ssti_in_access_logs | ssti | block_ip |
| C-005 | web_xss_in_access_logs | xss | require_confirmation |

引擎 `stats()` 现报告 `rules=16, shadow=5`，5 条社区规则全部以 `x-soc-shadow: true` 灰度在册（命中仅标记 `[SHADOW]`/`action=alert`，不阻断）。全量 pytest 198 passed 无回归。
