# LLM token 预算“上不封顶” / LLM 审计永不降级
**日期**: 2026-09-04 | 目的: token 成本上限改为上不封顶, 保证 LLM 审计路径永不会因预算被降级/短路/跳过。

## 语义(0 = 无上限; 统一开关)
- `config.llm_daily_budget_tokens` 默认改 `0` → **0 = 上不封顶**; 设正数 = 显式日额度(回退硬门禁)。
- 新增统一开关 `config.llm_budget_unlimited: bool = True`
  - True: 预算**只记账不断言**, 所有 LLM 预算门禁(审计水位 / Temporal 短路 / 各增强模块级 ¥)都只做统计, `is_over_budget` 恒 False、`budget_usage_pct=0`。
  - False: 恢复原“日额度 + soft/hard 水位 + 模块限”行为(如需回退)。

## 覆盖“预算降级”的全链(一处控制器 + 依赖)
- `summary_compression.CostTracker`: 支持 `unlimited=None`(**None → 按 budget<=0 自动推导**); 
  - `is_over_budget()`: unlimited 恒 False
  - `remaining_budget()`: unlimited → None
  - `stats()` 增 `"unlimited"`、`usage_pct`(unlimited → 0.0), 不喂给水位
  - 全局 `cost_tracker = CostTracker(..., unlimited=getattr(settings,"llm_budget_unlimited",None))`
- 因而上游两闸自然关闭:
  - `audit_triage.admit`(soft/hard 水位)因 `budget_usage_pct()→0`、`budget_exhausted()→False` => water=normal, 不再把 P1/P2/P3 降成 tools_only/rule_close
  - `agents/llm_fallback.should_short_circuit_for_tier` => P1/P2/P3 不再因 `budget_exhausted()` 短路; Temporal activities 不产生 budget short_circuit
- `llm_enhancer._check_and_consume_budget`: unlimited 时仍累加 bucket["used"] 仅供报表, 但**永不跳过/return False**(模块级 ¥ 上限也不关 LLM), 仅 unlimited=False 时按预算拦截。

结构保留: soft/hard_pct 与 admit 代码未删、模块预算映射未删, 随时可把 `llm_budget_unlimited=false`(或 budget=正数) 回退旧闸。

## 部署/环境
- `docker-compose.yml(backend.env)`: `SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS` 默认 `${VAR:-0}`(0=无限)、新增 `SHARED_MEMORY_LLM_BUDGET_UNLIMITED` 默认 true
- `.env.example` 同步样例; 本地 `.env SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS=0`
- (运行后端 env daily=0、cfg.unlimited=True、over_budget=False/unlimited=pct=0 实测)

## 实测(隔离容器行为冒烟, source mount)
将今日用量置 `9_999_999_999`(远超旧 5M 上限) →
- cost_tracker: over_budget=False, remaining=None, stats.unlimited=True, usage_pct=0.0, today=9999999999
- budget_exhausted=False; usage_pct=0.0
- should_short_circuit_for_tier("P2")=False; P0 恒 False
- llm_enhancer phishing 每笔75¥×200 → 200 全放行只记账(不 skip)

## 回归
- tests/test_token_cost.py, test_audit_triage.py, test_llm_enhancers.py(test_budget_check_rejects… 在显式 unlimited=False 的硬门禁分支覆盖; 新增 test_budget_unlimited_allows_all_calls 覆盖无限放行), test_llm_cache_and_embedding.py, test_llm_fallback_short_circuit.py → **47 passed**

## 不受影响/说明
- inflight(并发/容量) 与 long-run 机制保持“容量或长任务”语义, 不因本次关闭; 只清理“预算”维度。
- 成本报表仍持续统计(today_usage/calls/estimated ¥)供监控, 只是不因预算断 LLM 服务。
