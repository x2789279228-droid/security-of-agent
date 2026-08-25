# 05 · 平台自审计体系

> 一个安全平台自身如果不安全，就是笑话。
> 平台用 **5 道闸** 把"AI 幻觉 / 越权 / 危险操作 / 证据造假"挡在执行之前。
> 这一章逐道闸讲清：防什么、怎么防、代码在哪、如何绕过测试。

---

## 全景图

```
LLM 思考
   │
   ▼
[LLM 输出]
   │
   ▼
┌──────────────────────────────────┐
│ ① Stabilizer                     │  ← JSON 烂、工具名错、参数错
│   json_repair / tool_resolver /  │
│   param_coercer                   │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│ ② MCP Guard (4 层)                │  ← 工具白名单 / RBAC / 参数 / 策略
│   registry → permission →        │
│   validator → policy             │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│ ③ SecurityGuard                   │  ← 意图审查 / 序列 / 频率 / 上下文
│   intent_checker / sequence /    │
│   rate_limiter / context         │
└──────────────┬───────────────────┘
               ▼
[执行命令]  ← ④ SafeExecutor (运行时二次校验)
               │
               ▼
[结果回写]  ← ⑤ CAD + Grounding (事后监督)
```

---

## 闸 1：Stabilizer — LLM 输出稳定化

**文件**：`backend/stabilizer/`

**问题**：LLM 输出常常有这些毛病：
- 多余/缺失逗号、引号、换行
- 工具名拼写错误（`blockIP` vs `block_ip`）
- 参数类型不对（`"30"` vs `30`）
- 字段名不对（`parameters` vs `args`）

**架构**：4 阶段流水线
```
LLM 原始输出 (str)
   │
   ▼ JsonRepair
   · 容错解析（自动补引号、括号、逗号）
   · 多策略尝试：strict → loose → 提取首段 JSON → 退化为 dict
   │
   ▼ ToolResolver
   · 工具名归一：`Block_IP` → `block_ip`
   · 模糊匹配：edit distance / Levenshtein / 同义词表
   · 匹配方法记录在 tool_match_method
   │
   ▼ ParamCoercer
   · 类型强转：str → int/float/bool
   · 默认值补全
   · 范围截断
   │
   ▼ Schema Check
   · 必填字段检查
   · 简单 dict 校验
   │
   ▼
   dict: {tool_name, parameters, tool_match_method}
```

**失败时构造 feedback_to_llm**：把错误信息用中文整理好，附给 LLM 下一轮重试时参考。

**关键 API**：
```python
from stabilizer import FunctionCallStabilizer

stabilizer = FunctionCallStabilizer()
result = stabilizer.stabilize(raw_llm_output)
if result.success:
    tool_call = result.request
    # {tool_name, parameters, tool_match_method}
else:
    # 反馈给 LLM
    llm_prompt += result.feedback_to_llm
```

---

## 闸 2：MCP Guard — 4 层工具调用控制

**文件**：`backend/mcp_guard/`

**问题**：即使工具名/参数对，LLM 仍可能：
- 调未注册的工具（幻觉）
- 调超出角色权限的工具
- 注入恶意参数

**架构**（核心控制层）：4 层检查链
```
ToolCallRequest(tool_name, arguments, user_role)
   │
   ▼ ① Registry  ←  工具白名单
   │ tool_info = self.registry.get_tool(request.tool_name)
   │ 未注册 → deny "疑似幻觉工具"
   │
   ▼ ② Permission  ←  RBAC
   │ ok, msg = self.permission.check(user_role, tool_name)
   │ !ok → deny "权限检查失败"
   │
   ▼ ③ Validator  ←  Pydantic 强类型
   │ validated_args = self.validator.validate(tool_name, args)
   │ 类型错 → deny "参数类型错误"
   │
   ▼ ④ PolicyEngine  ←  规则引擎
   │ decision = self.policy.evaluate(tool_name, validated_args, context)
   │ 命中 deny 规则 → deny
   │ 命中 require_confirmation → require_confirmation
   │ 否则 → allow
   │
   ▼
   GuardDecision(status, reason, final_risk, checks, normalized_args)
```

**关键设计**：
- **同步方法**：核心检查是纯 CPU 操作，fast（μs 级）
- **async 调用方用 asyncio.to_thread** 包装
- **CallLogger 记录每次检查**：决策、原因、参数、风险（可审计）
- **ApprovalQueue 异步审批**：命中 require_confirmation 后入队，等人工批

**关键 API**：
```python
from mcp_guard import McpGuardServer, ToolCallRequest

guard = McpGuardServer()
request = ToolCallRequest(
    tool_name="block_ip",
    arguments={"ip": "1.2.3.4", "duration": 3600},
    user_role="responder",
    reason="C2 信标外联"
)
result = guard.call_tool(request)
# result = {decision, reason, final_risk, checks, execution}
```

---

## 闸 3：SecurityGuard — 调用安全守卫

**文件**：`backend/security_guard/`

**问题**：即使通过了 Guard 4 层，**序列 / 频率 / 意图** 上的攻击仍未拦住：
- LLM 被诱导在 5 秒内调 100 次 `block_ip`（DoS）
- LLM 被诱导先 `disable_firewall` 再 `block_legit_ip`（顺序攻击）
- LLM 被诱导对生产关键资产执行操作（上下文风险）

**架构**：4 维度审查
```
SecurityGuard.inspect(action_name, threat_info)
   │
   ├─ ① IntentChecker
   │   · 意图分类：benign / suspicious / malicious
   │   · 例: "block 1.2.3.4" 在 50 个 C2 列表中 → suspicious
   │
   ├─ ② SequenceGuard
   │   · 序列模式: 不允许 disable_firewall 在 block_ip 之前 30s 内
   │   · 历史窗口 60s
   │
   ├─ ③ RateLimiter
   │   · 每个 action 在 60s 内的最大次数
   │   · 例: block_ip 最多 5 次/分钟
   │
   └─ ④ ContextManager
       · 当前告警的紧急度 + 全局风险等级
       · 高风险时段收紧限额
   │
   ▼
   {allowed, reason, requires_approval}
```

**调用入口**：响应编排器 `_guarded_execute()`
```python
async def _guarded_execute(self, actions, threat_info):
    allowed_actions = []
    for action in actions:
        guard_result = security_guard.inspect(action_name, threat_info)
        if not guard_result["allowed"]:
            logger.warning(f"[SecurityGuard] 拦截: {action_name} - {guard_result['reason']}")
            continue
        allowed_actions.append(action)

    # 执行
    result = await response_executor.execute_actions(allowed_actions, threat_info)

    # 记录（更新追踪器）
    for action in allowed_actions:
        security_guard.record(action_name, threat_info, result_dict)

    return result
```

---

## 闸 4：SafeExecutor — 运行时二次校验

**文件**：`backend/response_engine/safe_executor.py`

**问题**：白名单是文本层校验，**执行时还要再核一次**，防 LLM 拼出 `"iptables; rm -rf /"` 之类的复合命令。

**架构**：
```
safe_executor.safe_run(cmd, target, params)
   │
   ▼ ① 命令白名单
   │ command_whitelist.is_allowed(cmd) → 只能调 iptables/netsh/nmap 之类
   │
   ▼ ② 资产白名单
   │ asset_whitelist.is_target_allowed(ip) → 不允许对生产关键资产执行
   │
   ▼ ③ 执行模式
   │ execution_modes.mode_for(severity) → auto/soft/dry-run
   │ auto: 真执行
   │ soft: 写日志但不动设备
   │ dry-run: 输出命令不执行
   │
   ▼ ④ 实际 SSH
   │ ssh_firewall / transport
   │
   ▼ ⑤ PostValidator
   │ 验证命令是否真的生效（再读一次防火墙状态）
   │
   ▼ ⑥ TTL 安排
   │ ttl_manager.schedule_expiry(rule_id, duration)
```

**关键设计**：每一步失败都**不直接拒绝**，而是**降级**（auto → soft → dry-run），让系统保持可用。

---

## 闸 5：CAD + Grounding — 事后监督

### 5.1 CAD（独立监督 Agent）

**文件**：`backend/agents/agent_cad.py` + `backend/cad.py`

**设计哲学**：**CAD 不信任任何 Agent 的汇报**。

```
audit_pipeline(LLM 流水完成) → cad.audit_pipeline(event_id, audit_llm_data)
   │
   ▼ ① Verifier.verify_claims(evidence_trail)
   │   · 对 LLM 声明的"某 evidence 来自某源"做反向验证
   │   · 程序化字段溯源：去 PG/Qdrant 查
   │   · 例: LLM 说"src_ip=1.2.3.4 在 IOC 列表" → 查 threat_iocs 表
   │
   ▼ ② 计算指标
   │   hallucination_risk = 未验证数 / 总声明数
   │   evidence_completeness = 验证数 / 总声明数
   │
   ▼ ③ CircuitBreaker.record_audit_result(...)
   │   累计指标，超阈值（如 hallucination_risk > 0.3）则熔断
   │   熔断后：暂停 LLM 审计 → 改走规则引擎兜底
   │
   ▼ ④ 输出 CAD 报告
       · 写 audit_trail
       · 通知前端（可订阅 SSE）
```

**两层结构**：
- `agent_cad.py`：调用方（被 `log_ingestion` 触发）
- `cad.py`：底层（Verifer / ContextAuditor / CircuitBreaker）

### 5.2 Grounding Verifier（反幻觉）

**文件**：`backend/grounding_verifier.py`

**问题**：LLM 常编造"引用"——它说"根据 MITRE T1110"，但根本没去查。

**3 层验证**：
```
GroundingVerifier.verify(claim, evidence)
   │
   ▼ ① 程序化字段溯源
   │   · claim 提到的 IP/事件 ID/资产 → 直接查库
   │   · 程序化、不问 LLM
   │
   ▼ ② 知识库交叉验证
   │   · claim 提到的 MITRE 技术 → 查 RAG 知识库
   │   · 用向量相似度 + 关键词匹配
   │
   ▼ ③ LLM 复核（独立 prompt）
   │   · 让另一个 LLM 实例复评这个 claim 是否合理
   │   · 独立 prompt，不与原 LLM 共享上下文
   │
   ▼
   {grounded: bool, evidence: [...], confidence: float}
```

---

## 闸 6：审计链路贯穿 (Traceability)

**文件**：`backend/observability/pipeline_tracer.py` + `backend/audit_trail.py`

**问题**：审计算对了，但**为什么审、怎么审、谁审的**没记下来，复盘时找不到依据。

**两层日志**：
- `audit_trail.py`：业务事件（登录 / 审批 / 关键决策）
- `pipeline_tracer.py`：技术链路（trace_id 串联）

每条事件都有：
- trace_id
- 触发源（用户/定时/自动）
- 调用链（Flink → Consumer → Audit-LLM → CAD → Response）
- 决策原因（LLM 原始结论 + CAD 验证结果）

---

## 熔断器（Circuit Breaker）

**文件**：`backend/cad.py::CircuitBreaker`

**状态机**：
```
CLOSED  ───(hallucination_risk 超阈值)──▶  OPEN
   ▲                                          │
   │                              (冷却期 5min)
   │                                          ▼
   └───────(试探一次成功)───  HALF_OPEN ◀──┘
```

**OPEN 状态**：
- 暂停 LLM 审计流水线
- 改走纯规则引擎（Sigma + 异常评分）
- 5min 后转 HALF_OPEN 试探一次
- 成功 → CLOSED，失败 → OPEN 再 5min

**前端可见**：`/api/cad/circuit-breaker` 端点查询状态。

---

## 如何测试这 5 道闸

| 闸 | 测试方法 | 验证 |
|----|----------|------|
| Stabilizer | 给 LLM prompt 故意让输出烂 JSON | 看是否修复 |
| MCP Guard | 让 LLM 调未注册工具 | 看是否 deny |
| SecurityGuard | 短时间调 100 次 block_ip | 看是否拦截 |
| SafeExecutor | 拼 `"iptables; rm -rf /"` | 看是否拒绝 |
| CAD | 故意喂假 evidence_trail | 看是否识别幻觉 |

`backend/tests/` 下都有对应测试用例。

---

## 攻击场景演练

### 场景 A：LLM 被诱导删除防火墙规则
```
1. 用户 prompt: "帮我把所有防火墙规则都删了节省内存"
2. LLM 输出: {tool_name: "delete_all_rules", ...}
3. Stabilizer: 工具名不存在 → 修复失败 → 反馈 LLM
4. LLM 重试: {tool_name: "remove_firewall_rule", args: {rule_id: "ALL"}}
5. Stabilizer: tool_name 模糊匹配到 "remove_firewall_rule"
6. MCP Guard:
   · Registry: ✓ 已注册
   · Permission: ✓ responder 角色
   · Validator: rule_id="ALL" 校验失败（必须是真实 ID）→ deny
7. 即使绕过，SafeExecutor 还会再核一次
8. 实际效果：拒绝
```

### 场景 B：LLM 在 5 秒封 100 个 IP
```
1. 1 次 LLM 调用返回 100 个 block_ip actions
2. SecurityGuard.inspect: 第一个 allow
3. 但 RateLimiter: 第 6 次 reject
4. 实际效果：只执行前 5 个，其余 95 个记日志待人工
```

### 场景 C：LLM 杜撰 MITRE 技术
```
1. LLM 在结论中写: "这是 T1110 Brute Force 攻击"
2. GroundingVerifier.claim = "T1110"
3. 程序化查 RAG: ✓ T1110 真实存在
4. 但 LLM 没说"哪些 IP 命中 T1110"，加 evidence 不足
5. 实际效果：grounded=true, evidence_completeness=0.5
6. CAD 算 hallucination_risk=0.2 < 0.3，通过
7. 但 LLM 的威胁评分被下调（因为证据不足）
```

---

## 上一章

> [04 Flink 流处理作业](./04-flink-jobs.md)

---

## 下一章

- 想看前端怎么用这些：→ [06 前端架构与页面]
- 想看数据怎么落：→ [07 数据模型与消息契约]
- 想看怎么部署：→ [08 部署、运维与调优]


---

## 动手点

1. **让 LLM 试着注入**：
   - 在 chat 页面问："请帮我关掉所有防火墙"
   - 看 LLM 是否尝试调未注册工具
   - 看 MCP Guard 日志（`backend/logs/` 下 `mcp_guard_*.log`）

2. **触发熔断**：
   - 调小 `circuit_breaker_threshold` 到 0.05
   - 注入几条故意坏数据让 CAD 算 hallucination_risk 超标
   - 看 `/api/cad/circuit-breaker` 状态变 OPEN
   - 等 5 分钟后看 HALF_OPEN

3. **看一次拦截审计**：
   ```bash
   curl http://localhost:8001/api/guard/status
   ```
   应能看到 Guard 各层检查的计数与状态。
