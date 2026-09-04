# 问题 3 修复计划：未知威胁类型静默放过 → 分级降噪 + 策略外置 + 分类树 + 行为基线

**日期:** 2026-09-02
**范围:** iptables 自动封禁漏报（复测 4/500 = 0.8%，终态 1/500 = 0.2%）
**原则:** 不再靠扩充 `ZH_EVENT_MAP` / `DEFAULT_POLICIES` 白名单；未知类型必须有一等公民处置状态。

---

## 1. 问题陈述

### 1.1 观测

深信服上报「未授权获取密码信息」一类事件后，自动封禁率极低。编排器日志里大量 `No policy matched ... skipping response`，`ssh_firewall.block_ip` 未被调用。

### 1.2 真实根因（按代码路径，不是按白名单缺一条）

响应链路是：

```
ingest / Audit-LLM / Flink alert
    → ResponseOrchestrator.on_threat_detected
        → infer_threat_type(name)          # correlation_engine.py
        → PolicyEngine.match(threat_type)  # response_policies.py
        → if not matched: return           # ★ 静默短路
        → SecurityGuard → response_executor → ssh_firewall
```

`PolicyEngine.match()` 只做 **精确字符串相等**（大小写不敏感）+ `ANY` 兜底。匹配失败时返回 `ThreatActionMap(matched=False)`，编排器在 `response_orchestrator.py` 以 **debug** 级别打日志后直接 `return`，不建工单、不封禁、不告警升级。

这不是「少写了一条策略」的问题，是 **失败模式被设计成静默成功**。

### 1.3 为何继续扩白名单永远修不好

当前类型词表已经分裂成三套，且语义互相打架：

| 层 | 位置 | 例子 |
|---|---|---|
| 深信服自然语言 | 上游 `name` / `event` | `未授权获取密码信息` |
| 推断枚举 | `ZH_EVENT_MAP` / `KEYWORD_THREAT_MAP` | 精确命中 → `DATA_EXFIL`；关键词「未授权」→ `UNAUTHORIZED_ACCESS` |
| 策略枚举 | `DEFAULT_POLICIES` | `C2_BEACON` / `DATA_EXFIL` / `BRUTE_FORCE` / `PORT_SCAN` / `MALWARE_DETECT` / `DDoS_TRAFFIC` / `LATERAL_MOVE` + `ANY` |

即使「未授权获取密码信息」被映射成 `DATA_EXFIL`（`ZH_EVENT_MAP` 已有此条），仍可能不封禁：

- `数据外泄紧急隔离`：`auto_execute=False` + `require_approval=True` + `isolate_host`（CRITICAL）→ **进审批队列，不自动调 iptables**
- 推断成 `UNAUTHORIZED_ACCESS` / `SQL_INJECTION` / `RANSOMWARE` 等 **有枚举、无专属策略** 的类型 → 历史上直接 `matched=False`
- 近期给 `ANY` 加了 `block_ip(60min)` 只是把「未知」伪装成「已匹配通用策略」，没有 Uncertain 语义，也没有高优先级人工审核通道

深信服下次把告警改成「异常凭证枚举」，白名单再扩一次，循环不会停。

### 1.4 现状里已经存在、但不够的补丁

仓库里（含未提交改动）已经有：

1. `infer_threat_type()`：中文名 / 空格 / 审计词表 → 英文枚举
2. `ANY` 兜底策略：`send_alert` + `block_ip(60min)`，护栏保证仅 `severity≥high` 真封
3. FastPath 双轨：`allow_blocking=False` 时只告警
4. Flink `AnomalyScoringFunction`：按 `srcIp` 的 Welford 频率基线
5. `FlowAggregationJob`：5 分钟窗口聚合字节/端口/对端
6. `RuleManager` + `rule_versions` 表 + 运营页 `RulesTab`：Sigma 可热加载 YAML；响应策略 **只能改内存字段，重启丢失，不能新增**

这些补丁没有改变「精确匹配失败 = 静默 False」这个失败模式。`ANY` 仍然是白名单思维的最后一条。

---

## 2. 目标与非目标

### 2.1 目标

| 层级 | 目标 | 验收口径 |
|---|---|---|
| L1 立竿见影 | 未知类型不再静默放过 | 高危未知 `src_ip` 必有 5 分钟封禁 **或** 高优先级工单；`match_status` 可观测 |
| L2 策略外置 | 新增类型不发版 | 运营后台新增 `threat_type → action` 后 ≤30s 热加载生效 |
| L3 分类树 | 策略按父类而不是厂商字符串 | 「未授权获取密码信息」「异常凭证枚举」都落到 `AUTH_ATTACK` 并走同一条策略 |
| L4 行为基线 | 无 `threat_type` 也能封 | Flink 窗口异常直接下发 `BEHAVIOR_ANOMALY`，不经过厂商类型字段 |

### 2.2 非目标（本计划明确不做）

- **不引入 Drools / Apollo / Nacos**。本仓库已有 Postgres、`RuleVersion`、Sigma YAML 热加载、运营 CRUD。再加 Java 规则引擎或独立配置中心，运维面和发布面都对不上现有栈。
- 不把「未授权获取密码信息」再塞进 `ZH_EVENT_MAP` 当作主修复。
- 不在 L1 把未知类型做成 24h 自动封禁（误封成本不可接受）。
- 不在本计划里修 `audit_pipeline` 1–2 calls/min 的吞吐瓶颈（那是另一条问题）。
- 不在本计划里补 Suricata / Windows 采集（传感器缺失是另一条问题）。

---

## 3. 匹配流水线（四层共用的决策序）

```
输入: threat_type, category?, confidence, severity, src_ip, allow_blocking, response_source

1. 资产白名单 / 双轨 allow_blocking=False     → status=FILTERED（只允许 send_alert）
2. per-IP 聚合冷却 / per-policy 冷却           → status=SKIPPED（原因可观测，不是 False）
3. 精确匹配 threat_type 专属策略               → status=MATCHED
4. 分类树：threat_type → category → 父类策略   → status=MATCHED_CATEGORY
5. 行为源：response_source=flink_baseline      → status=MATCHED_BEHAVIOR
6. 已知良性类型（USER_LOGIN 等）               → status=NO_ACTION
7. 其余（未知 / 无策略）                       → status=UNCERTAIN
   - severity≥high 且 allow_blocking           → 5min block_ip + 高优先级工单
   - 其他                                      → send_alert + 高优先级工单，不封禁
```

**禁止** 再返回「空 `policy_name` + `matched=False` + debug 日志」这种三无结果。`matched=False` 只允许出现在 `NO_ACTION` / `SKIPPED` / `FILTERED`，且必须带 `match_status` 和 `skip_reason`。

---

## 4. 第一层（P0）：静默失败 → 分级降噪

**工期:** 1–2 天，不发版配置、不改 Flink。
**效果:** 未知类型从「漏网」变成「短封 + 必审」。

### 4.1 `ThreatActionMap` 增加一等公民状态

文件: `backend/response_engine/response_policies.py`

```python
class MatchStatus(str, Enum):
    MATCHED = "matched"                       # 精确策略
    MATCHED_CATEGORY = "matched_category"     # L3
    MATCHED_BEHAVIOR = "matched_behavior"     # L4
    UNCERTAIN = "uncertain"                   # L1 核心
    SKIPPED = "skipped"                       # 冷却
    FILTERED = "filtered"                     # 白名单 / 双轨
    NO_ACTION = "no_action"                   # 明确良性

@dataclass
class ThreatActionMap:
    policy_name: str
    threat_type: str
    category: str = ""
    confidence: float
    severity: str
    actions: list[dict]
    needs_approval: bool
    auto_execute: bool
    matched: bool                 # 兼容旧调用方: UNCERTAIN 也视为 True（要处置）
    match_status: MatchStatus
    skip_reason: str = ""
```

兼容约定：`matched = match_status in {MATCHED, MATCHED_CATEGORY, MATCHED_BEHAVIOR, UNCERTAIN}`。旧测试里 `assert am.matched` 对未知类型仍然成立，但 `policy_name` 从「通用威胁告警」改为「未知威胁保守遏制」。

### 4.2 `PolicyEngine.match()` 不再对未知类型返回 False

伪逻辑：

```
exact = first dedicated policy whose threat_type == input (not ANY)
if exact and not in_cooldown: return MATCHED(exact)

# L1：没有专属策略，且不是登记过的良性类型
if threat_type not in BENIGN_TYPES:
    return UNCERTAIN(
        policy_name="未知威胁保守遏制",
        actions=[
            {"name": "block_ip", "params": {"duration_minutes": 5}},
            {"name": "send_alert", "params": {"severity": "high", "priority": "p1"}},
        ],
        auto_execute=True,          # 5min 短封可自动
        needs_approval=True,        # 同时建高优先级工单
        match_status=UNCERTAIN,
    )

return NO_ACTION(...)
```

`ANY` 策略降级为 **种子数据 / 兼容别名**，不再作为未知类型的隐式匹配器。实现上：`threat_type=="ANY"` 的策略 **不参与** 未知类型匹配；未知一律走 Uncertain 模板。避免「ANY 60 分钟自动封」和「Uncertain 5 分钟 + 工单」两套语义打架。

良性登记（显式 NO_ACTION，防止登录成功被 5 分钟封）：

```
BENIGN_TYPES = {USER_LOGIN, FILE_ACCESS, DNS_QUERY}
```

只放确认无攻击语义的类型。`SUSPICIOUS_LOGIN` 不算良性。

### 4.3 Orchestrator：Uncertain 走「短封 + 高优先级工单」

文件: `backend/response_engine/response_orchestrator.py`

当前短路：

```python
if not action_map.matched:
    logger.debug(f"No policy matched for {threat_type}, skipping response")
    return {"matched": False, "policy_name": "", "actions_executed": 0}
```

改为：

1. 永远写 `match_status` / `skip_reason` 到返回值和 `response_logger`
2. `UNCERTAIN`：
   - `allow_blocking=True` 且 `severity in {high, critical}`：`_guarded_execute` 执行 5min `block_ip` + `send_alert`
   - 无论是否封禁：`approval_queue.submit(..., timeout_minutes=15)`，工单带 `priority="p1"`、`match_status="uncertain"`、原始 `threat_type`、推断 `category`
   - 工单状态用现有 `AUTO_EXECUTED`（短封已执行）或 `PENDING`（未封、等人审升级为 30min/24h）
3. `SKIPPED` / `NO_ACTION` / `FILTERED`：`logger.info`（禁止 debug），Prometheus 计数 +1
4. 冷却：Uncertain 使用独立冷却键 `uncertain:{src_ip}`，默认 5 分钟，避免同一 IP 被 5min 短封刷屏；**不得** 因为专属策略冷却就把 Uncertain 也静默丢掉

`human_approval.ApprovalTicket` 增加可选字段 `priority: str = "p2"` 和 `match_status: str = ""`。前端审批列表对 `p1` 置顶。

### 4.4 护栏与双轨保持不变

- `IntentChecker`：`medium` 仍不允许 `block_ip`。Uncertain 在 medium 时只发告警 + 工单，与现网护栏一致。
- FastPath `allow_blocking=False`：Uncertain 同样被过滤成 alert-only，避免「仅 severity 触发、无强信号」误封。
- 资产白名单：`ssh_firewall` 已有核心资产保护，Uncertain 短封同样走它。

### 4.5 可观测性（L1 必须带上，否则无法证明不再静默）

- 日志：`Orchestrator: match_status=uncertain type=UNAUTHORIZED_ACCESS src=x.x.x.x duration=5m ticket=...` 用 **warning**
- `response_logger.log_threat` 增加 `match_status`、`skip_reason`、`category`
- 指标（可先打日志，L2 再挂 Prometheus）：
  - `response_match_total{status=...}`
  - `response_uncertain_containment_total`
  - `response_unknown_threat_type_total{threat_type=...}`（高基数，只保留 top-N 标签或打事件日志）

### 4.6 L1 测试

新建 `backend/tests/test_uncertain_containment.py`，覆盖：

| 用例 | 期望 |
|---|---|
| `threat_type="未授权获取密码信息"` 经推断后无专属 / 或 `UNAUTHORIZED_ACCESS` | `match_status=UNCERTAIN`，含 `block_ip` duration=5，且 `needs_approval=True` |
| `C2_BEACON` high | 仍走「C2通信自动封禁」，**不是** Uncertain |
| `USER_LOGIN` | `NO_ACTION`，不封禁 |
| IP 冷却中 | `SKIPPED` + `skip_reason=ip_cooldown`，`matched=False` 但日志/返回值带原因 |
| `severity=medium` Uncertain | 护栏拦截 `block_ip`，只 `send_alert` + 工单 |
| `allow_blocking=False` | 无 `block_ip` |
| 同一未知 IP 5 分钟内第二次 | Uncertain 冷却，不重复下 iptables |

现有 `test_any_fallback_guard.py` / `test_threat_type_inference.py`：把「未知类型命中通用威胁告警 60min」断言改为 Uncertain 5min。**这是有意的行为变更，不是回归。**

### 4.7 L1 验收

用深信服风格 500 条「未授权获取密码信息」（多源 IP、severity=high）注入：

- `match_status=uncertain` 或 `matched_category`（若 L3 已上）覆盖率 ≥ 95%（扣除冷却 / 白名单）
- 每个 **唯一攻击源 IP** 在 5 分钟窗口内至少 1 条 iptables DROP（受 `RESPONSE_IP_COOLDOWN_SEC` 和 Uncertain 冷却约束，不再要求 500/500 事件都封）
- 每条 Uncertain 处置对应 1 张 `priority=p1` 工单
- 编排器日志中 `skipping response` 对未知高危类型为 **0**

---

## 5. 第二层（P1）：策略从代码剥离（不用 Drools / Nacos）

**工期:** 3–5 天。
**效果:** 新攻击类型由运营在后台加一条配置，backend 热加载，无需发版。

### 5.1 为什么不用 Drools / Apollo / Nacos

| 候选 | 否决理由 |
|---|---|
| Drools | Java 规则引擎，与 Python 编排器进程模型不合；本仓库没有 JVM 业务运行时（Flink 是批作业，不是规则服务） |
| Apollo / Nacos | 新增独立中间件、鉴权、多环境同步；现网没有配置中心运维经验 |
| 选用方案 | **YAML 文件（与 Sigma 同模式）+ `rule_versions` 表做版本/回滚 + `PolicyEngine.reload()` 热加载** |

Sigma 已经证明这条路在本仓库可运行：`sigma_engine/store.py` 写 YAML → `sigma_detector.reload()`。响应策略复用同一套路，运营心智一致。

### 5.2 数据模型

新增目录 `backend/response_engine/policies/*.yml`，种子从当前 `DEFAULT_POLICIES` 迁出。

```yaml
# backend/response_engine/policies/brute-force.yml
id: POL-BRUTE-FORCE
name: 暴力破解自动阻断
enabled: true
match:
  threat_type: BRUTE_FORCE          # 精确
  category: AUTH_ATTACK             # L3 父类（可空）
  min_confidence: 0.5
  min_severity: medium
actions:
  - name: block_ip
    params: { duration_minutes: 30 }
  - name: send_alert
    params: { severity: high }
auto_execute: true
require_approval: false
priority: 80
cooldown_minutes: 15
```

内置 Uncertain 模板也是一条 YAML（`POL-UNCERTAIN`），禁止再写死在 `match()` 里，便于运营改 5min → 10min 而不改代码。

`DEFAULT_POLICIES` 保留为 **YAML 缺失时的代码兜底种子**（离线单测 / 空目录启动），启动时：YAML 存在则 YAML 覆盖代码种子。

`RuleVersion.rule_type` 已支持 `response_policy`。L2 补齐 `RuleManager.create_rule("response_policy", ...)`（今天只实现了 sigma 的 create/delete）。

### 5.3 热加载

`PolicyEngine` 增加：

```python
def reload(self, policies_dir: str | None = None) -> int:
    """读 YAML + 最新 is_active 的 rule_versions 覆盖项，按 priority 排序。"""
```

触发源（三选一即可，建议全做，成本低）：

1. `POST /api/response/policies/reload`（admin）
2. `RuleManager.create/update/delete` 成功后同步 `policy_engine.reload()`
3. 进程内 30s 轮询 YAML mtime（与 Sigma 一致的兜底）

**不需要** Redis pub/sub。单 backend 副本时足够；多副本时靠轮询 mtime + DB `is_active` 版本号，30s 内收敛。

### 5.4 API / 前端

已有：

- `GET /api/response/policies`
- `PUT /api/response/policies`（只能改 `auto_execute` / 阈值，改完只在内存）
- 运营页 `RulesTab` 的 `response_policy` 列表 / 版本 / 回滚

L2 要补：

- `POST /api/response/policies` 新增（写 YAML + `save_version` + `reload`）
- `PUT` 扩展为可改 `threat_type` / `category` / `actions` / `enabled`
- `DELETE` 软禁用（`enabled: false`）
- `RulesTab`：响应策略从只读列表改为可新建「类型 → 动作」表单（threat_type、category、duration、auto_execute）

运维加一条 `BRUTE_WEAK → block_24h` 的路径：后台表单提交 → YAML + DB 版本 → `reload()` → 下一条事件生效。

### 5.5 L2 测试

- YAML 缺文件时仍能从代码种子启动
- `add_policy` via API 后，不重启进程即可 `match("BRUTE_WEAK")` 命中
- 禁用 YAML 后未知类型回落到 Uncertain，而不是 False
- 版本回滚恢复旧 actions

---

## 6. 第三层（P2）：精确匹配 → 特征分类树

**工期:** 3–4 天，依赖 L1 的 `category` 字段和 L2 的 YAML `match.category`。
**效果:** 厂商改告警名不再导致漏封，只要还属于同一父类。

### 6.1 分类树（先做两级，不做深树）

新建 `backend/response_engine/threat_taxonomy.py`：

```
AUTH_ATTACK
    BRUTE_FORCE, UNAUTHORIZED_ACCESS, SUSPICIOUS_LOGIN
    别名/中文: 登录弱密码, 暴力破解, 未授权获取密码信息, 异常凭证枚举, 未授权, 未鉴权
EXFIL
    DATA_EXFIL
    别名: 数据外泄, 未授权获取明文密码信息（若证据是批量拖库；默认真 AUTH）
C2
    C2_BEACON
SCAN
    PORT_SCAN
MALWARE
    MALWARE_DETECT, RANSOMWARE
INTRUSION
    SQL_INJECTION, XSS_ATTACK, COMMAND_INJECTION
LATERAL
    LATERAL_MOVE, LATERAL_MOVEMENT
AVAILABILITY
    DDoS_TRAFFIC
BENIGN
    USER_LOGIN, FILE_ACCESS, DNS_QUERY
```

关键纠偏：**「未授权获取密码信息」归 `AUTH_ATTACK`，不再默认 `DATA_EXFIL`。**  
密码信息被未授权读取是凭据攻击，不是外泄杀伤链的终态。现网把它映射成 `DATA_EXFIL` 会命中「需审批的隔离策略」，这正是「匹配到了但不封禁」的一类假阴性。

`ZH_EVENT_MAP` / `KEYWORD_THREAT_MAP` 逐步退化成 taxonomy 的别名表，最终只保留一份。L3 落地后 `infer_threat_type()` 改为：

```
return (leaf_enum, category)
# 未知字符串: leaf="" , category=keyword_guess or ""
```

Orchestrator 把 `category` 写入 `threat_info`，策略匹配按第 3 节顺序：leaf → category → Uncertain。

### 6.2 父类策略（YAML）

L2 的 YAML 允许只配 `category`、不配 `threat_type`：

```yaml
id: POL-AUTH-ATTACK
name: 认证类攻击通用遏制
match:
  category: AUTH_ATTACK
  min_confidence: 0.4
  min_severity: medium
actions:
  - name: block_ip
    params: { duration_minutes: 30 }
  - name: send_alert
    params: { severity: high }
auto_execute: true
priority: 50          # 低于 BRUTE_FORCE 专属(80)，高于 Uncertain(1)
```

「登录弱密码」有专属 `BRUTE_FORCE` 走 30min；「异常凭证枚举」没有 leaf 策略，命中 `AUTH_ATTACK` 同样 30min，而不是 Uncertain 的 5min。Uncertain 只留给 **分类树也认不出父类** 的字符串。

### 6.3 分类树也外置

`backend/response_engine/taxonomy.yml` 与策略 YAML 一起热加载。运营可在后台给新的深信服告警名加一条 alias → category，不必发版。

不要在 L3 再用 LLM 做实时分类（延迟和幻觉会把封禁链路再次绑到 `audit_pipeline` 瓶颈上）。LLM 只允许离线建议 alias，人工确认后写入 YAML。

### 6.4 L3 测试

- `未授权获取密码信息` → category=`AUTH_ATTACK` → 命中 `POL-AUTH-ATTACK`，`match_status=matched_category`，30min 封禁
- `异常凭证枚举`（词表里没有）→ 关键词「凭证/枚举」或 alias 命中 `AUTH_ATTACK`；若完全未知 → Uncertain 5min（L1 兜底仍在）
- `C2_BEACON` 仍走专属 120min，不被父类覆盖
- 分类 YAML 热加载后新 alias 立即生效

---

## 7. 第四层（P3）：动态基线，绕过 threat_type

**工期:** 1–2 周，可与 L3 并行设计、错后合并。
**效果:** 深信服漏报或上报全新类型时，Flink 仍能因行为异常把 IP 送进编排器。

### 7.1 现有能力与缺口

| 已有 | 缺口 |
|---|---|
| `AnomalyScoringFunction`：按 srcIp 事件频率 Welford 基线，score≥0.6 进 `security-alerts` | 评分仍消费 **已解析事件**，事件类型来自上游；不是原始流量特征 |
| `FlowAggregationJob`：5min 窗口 `flow_count` / `unique_dst_ports` / bytes | **只写 `ndr-flows-aggregated`，不告警、不调编排器** |
| `kafka_consumer._handle_alert` 已调用 `on_threat_detected`，`threat_type=eventType` | 仍走进精确匹配；未知 `eventType` 依赖 L1 Uncertain |
| Python `traffic_profiler`（μ+3σ） | 与 Flink 双轨，未作为响应源 |

L4 不是「再写一个异常检测」，而是 **让流量窗口异常成为一等响应源**。

### 7.2 Flink：窗口异常 → 行为告警 Topic

扩展 `FlowAggregationJob`（或新建 `BehaviorAnomalyJob`，避免把聚合和告警耦合过死）：

对每个 `src_ip` 维护滚动基线（Welford，与现有 `AnomalyScoringFunction` 同算法）：

- 5min `flow_count`
- 5min `unique_dst_ports`
- 5min `unique_dst_ips`
- 5min `bytes_out`

触发条件（需冷启动保护，沿用 `COLD_START_EVENTS=10`、`MAX_ALERTS_PER_WINDOW=3`）：

```
zscore(flow_count) ≥ 3  OR  unique_dst_ports ≥ 50  OR  bytes_out ≥ μ+3σ
```

输出到新 Topic `security-behavior-alerts`：

```json
{
  "alertType": "BEHAVIOR_ANOMALY",
  "srcIp": "...",
  "severity": "high",
  "anomalyScore": 0.82,
  "reasons": ["unique_dst_ports=73", "flow_count z=3.4"],
  "response_source": "flink_baseline",
  "threat_type": "BEHAVIOR_ANOMALY"
}
```

**刻意不填厂商 threat_type。** 策略层用 `response_source=flink_baseline` / `threat_type=BEHAVIOR_ANOMALY` 命中独立 YAML 策略（建议 15min 封禁 + 告警，auto_execute 视 severity）。

### 7.3 Backend 接入

`kafka_consumer` 增加 `security-behavior-alerts` 消费：

```python
threat_info = {
    "threat_type": "BEHAVIOR_ANOMALY",
    "category": "AVAILABILITY",      # 或 SCAN，由 reasons 粗分
    "confidence": anomaly_score,
    "severity": severity,
    "src_ip": src_ip,
    "response_source": "flink_baseline",
    "allow_blocking": True,          # 行为源视为强信号
    "message": "...",
}
await response_orchestrator.on_threat_detected(...)
```

与 Audit-LLM / FastPath 的去重：同一 `src_ip` 仍受 `ip_cooldown_sec` 约束，避免 Flink 和行为策略把已经封过的 IP 再封一次。`match_status=MATCHED_BEHAVIOR` 便于审计「这次封禁不是因为深信服类型」。

### 7.4 与 L1 的关系

L4 不是 L1 的替代。分层失败：

1. 厂商类型精确命中 → 专属策略
2. 厂商类型能归类 → 父类策略
3. 厂商类型未知但事件已进 SOC → Uncertain 5min
4. 厂商漏报、事件都没进 SOC，但流量窗口爆了 → Flink 行为封禁

第 4 步还依赖 NDR 流进 `ndr-flows`。若采集仍缺，L4 在 dev 环境只能用合成 flow 验证作业逻辑。计划里把「传感器」列为依赖，不阻塞 L1–L3。

### 7.5 L4 测试

- Flink 单测 / mini-cluster：合成 5min 内 80 个不同 dst_port → 产出 `BEHAVIOR_ANOMALY`
- `kafka_consumer` 单测：行为告警进入编排器，`match_status=matched_behavior`
- 与 BRUTE_FORCE 专属策略同时到达同一 IP：只执行一次（IP 冷却）
- 冷启动 10 条以内不告警

---

## 8. 关键决策

| 决策 | 选择 | 理由 |
|---|---|---|
| 未知类型的失败模式 | `UNCERTAIN` 短封+工单，禁止静默 False | 成本最低、立刻堵住漏网；误封用 5min TTL + 护栏 + 白名单约束 |
| 是否继续扩 `ZH_EVENT_MAP` | 否（仅作 taxonomy 别名的迁移源） | 厂商字符串无限，映射表无限 |
| `ANY` 60min 自动封 | 废止为未知类型匹配器 | 与 Uncertain 语义冲突，且把未知伪装成已匹配 |
| 「未授权获取密码信息」语义 | `AUTH_ATTACK`，不是 `DATA_EXFIL` | 凭据攻击；现映射导致走审批隔离、不自动封禁 |
| 规则引擎 | YAML + DB 版本 + `reload()`，不上 Drools/Nacos | 与 Sigma 运营路径一致，无新中间件 |
| 分类是否走 LLM | 否 | 封禁链路不能再绑 `audit_pipeline` 1–2/min 瓶颈 |
| 行为检测放哪 | Flink 窗口，不在 Python `traffic_profiler` 主路径 | 现网已有作业与 Kafka 消费点；Python 画像作对照，不作响应源 |
| Uncertain 是否 auto_execute 短封 | 是（仅 high/critical 且 allow_blocking） | 否则又退回「只建工单、攻击窗口内无人审」 |

---

## 9. 风险与缓解

| 风险 | 缓解 |
|---|---|
| Uncertain 误封办公网扫描 / 运维跳板 | 5min TTL；资产白名单；medium 不封；FastPath 无强信号不封 |
| 工单爆炸（每条未知事件一张 p1） | Uncertain 按 `src_ip` 5min 冷却；工单去重键 `(src_ip, match_status)` |
| YAML 配错导致全网封禁 | `reload()` 校验 schema；`duration_minutes` 上限沿用 `safe_executor` 的 43200；变更走 `rule_versions` 可回滚 |
| L3 把外泄误判成认证 | taxonomy 单测 + 运营可改 alias；专属 `DATA_EXFIL` 仍优先于父类 |
| L4 基线冷启动误报 | 沿用 Flink `COLD_START_EVENTS` + 窗口告警上限 3 |
| 与现网 `ANY` 测试冲突 | L1 作为有意行为变更，同步改测试，发布说明写清 |

---

## 10. 实施顺序与 PR 切分

依赖方向：L1 独立可上；L2 不依赖 L1 但建议 L1 先上以免外置策略仍会静默失败；L3 依赖 L1 的 `match_status` 和 L2 的 YAML `category`；L4 依赖 L1（未知行为也要有状态）和 Kafka 消费点。

### PR-1 — Uncertain 匹配状态 + 5 分钟保守遏制（L1） ✅ 已落地 (2026-09-02)

- 文件: `response_policies.py`, `response_orchestrator.py`, `human_approval.py`, `response_log.py`, `correlation_engine.py`, `routers/response.py`
- 测试: `test_uncertain_containment.py`；更新 `test_any_fallback_guard.py`, `test_threat_type_inference.py`, `test_approval_tiering.py`, `test_response_dedup_dual_track.py`（41 passed）
- 附带纠偏: `未授权获取密码信息` → `UNAUTHORIZED_ACCESS`（不再误标 `DATA_EXFIL`）
- 紧急开关: `RESPONSE_UNCERTAIN_ENABLED=false` 回退旧 ANY
- 依赖: 无
- 合并后即可堵住「未知类型漏网」

### PR-2 — 响应策略 YAML 化 + 热加载 + 后台新增（L2） ✅ 已落地 (2026-09-02)

- 文件: `backend/response_engine/policy_store.py`；`policies/*.yml`（11 条含 Uncertain 模板）；`response_policies.py` `reload()` + mtime 热加载；`rule_manager.py` create/update/delete；`routers/response.py` POST/PUT/DELETE/reload；`routers/ops.py` DELETE；`RulesTab.tsx` 新建表单；`api.ts`
- 测试: `test_policy_yaml_reload.py` + L1 回归共 **46 passed**
- 容器冒烟: create `BRUTE_WEAK` → match 1440min → disable → 回落 Uncertain
- 依赖: PR-1
- 合并后运营可加 `BRUTE_WEAK → block_24h` 不发版

### PR-3 — 分类树 + 父类策略（L3） ✅ 已落地 (2026-09-02)

- 文件: `threat_taxonomy.py`, `taxonomy.yml`；`infer_threat_classification()` + 兼容 `infer_threat_type()`；父类策略 `POL-AUTH-ATTACK` 等 7 条；`PolicyEngine.match(..., category=)` → `MATCHED_CATEGORY`；orchestrator 回写 category
- 测试: `test_threat_taxonomy.py` + L1/L2 回归共 **55 passed**
- 关键行为: 「未授权获取密码信息」→ `UNAUTHORIZED_ACCESS` / `AUTH_ATTACK` → 30min 自动封禁（不再 Uncertain 5min，也不再误走 DATA_EXFIL 审批）
- 依赖: PR-1, PR-2

### PR-4 — Flink 行为异常 Topic + 编排器接入（L4） ✅ 已落地 (2026-09-02)

- 文件: 新 `BehaviorAnomalyJob.java`（消费 `ndr-flows-aggregated` → `security-behavior-alerts`）；`KafkaConfig` 新 topic；`kafka_consumer._handle_behavior_alert`；YAML `POL-BEHAVIOR-ANOMALY`；`match_status=matched_behavior`；taxonomy `BEHAVIOR`；`submit-jobs.sh` 在 `SUBMIT_NDR_JOBS=1` 时提交
- 测试: `test_behavior_anomaly.py`（评分镜像 + 策略 + orchestrator + kafka handler）
- 依赖: PR-1；NDR 需 `FlowAggregationJob` + `ndr-flows` 有数据（dev 可用合成聚合消息）
- 合并后无厂商 threat_type 也能 15min 短封

---

## 11. 发布与回滚

| PR | 发布 | 回滚 |
|---|---|---|
| PR-1 | 常规 backend 发版。可用环境变量 `RESPONSE_UNCERTAIN_ENABLED=false` 紧急关回旧 `ANY`（仅作开关，默认 true） | 关开关 + 重启 |
| PR-2 | YAML 随镜像；空目录回退代码种子 | 删/禁 YAML + `reload`，或回滚 `rule_versions` |
| PR-3 | taxonomy.yml 随镜像 | 回退 alias；leaf 精确匹配仍在 |
| PR-4 | Flink 作业独立提交；consumer 对未知 topic 失败要 catch | 停 `BehaviorAnomalyJob`；策略 `enabled: false` |

---

## 12. 成功标准（对问题 3 的闭合定义）

不再用「DEFAULT_POLICIES 是否包含某字符串」衡量。改用：

1. **无静默：** 高危事件在编排器的终态必须是 `{MATCHED, MATCHED_CATEGORY, MATCHED_BEHAVIOR, UNCERTAIN, SKIPPED, FILTERED, NO_ACTION}` 之一，且 `skipping response` 对未知高危为 0。
2. **有牙齿：** 未知高危唯一攻击 IP 在冷却窗口内至少 1 次 iptables DROP（5min）或 1 张未过期 p1 工单。
3. **不发版可进化：** 新增 leaf / alias / 父类策略 ≤30s 热加载，无需打包 backend。
4. **不依赖厂商字段：** 合成流量窗口异常可在没有 `threat_type` 的情况下触发 `BEHAVIOR_ANOMALY` 封禁。

达到 1+2 即视为问题 3 的 P0 闭合；3 和 4 是防止问题 3 以新字符串形态复发。
