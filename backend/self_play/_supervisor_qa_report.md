# Supervisor QA — Self-Play 训练闭环

日期: 2026-09-06
MiniMax: MCP `run_task` 两次 exit=3；直连 `mcode exec` 要求 `mcode login`。QA 由主管对照仓库与测试完成。

## 测试

```
python -m pytest tests/test_self_play.py tests/test_self_play_lifecycle.py
  tests/test_self_play_scoring.py tests/test_self_play_curriculum.py
  tests/test_self_play_sim_diversity.py tests/test_self_play_wired.py
  tests/test_self_play_review.py tests/test_sigma_selfplay_load.py
  tests/test_prompts_integrity.py -q
→ 104 passed
```

## 验收

| ID | 结论 | 证据 |
|---|---|---|
| P1-A | PASS | `play_round` 先 `score_round` 再 `learn_from_misses`；observer 用 `detect_scoring` |
| P1-B | PASS | `overlay.detect_scoring` 只认 overlay/shadow/promoted/production |
| P1-C | PARTIAL | FPR<0.05 硬门；无独立正样本时 `provisional=True` 仍可升 overlay（为跨回合 compounding） |
| P1-D | PASS | `generalize_rule` 丢 IP/超长/base64 |
| P1-E | PASS | Jaccard≥0.8 或同 mitre+event 去重 |
| P1-F | PASS | version / parent_rule_id / validation |
| P1-G | PASS | `test_three_rounds_learn_evasion` + wired 同构 |
| P2-A | PASS | curriculum=True 时 `select_goal` → `plan_attack(goal=)` |
| P2-B | PASS | `ExecutablePlanner.constrain_steps` 拒非家族 TTP |
| P2-C | PASS | T1059.001 / T1059.006 目录+goal |
| P2-D | PASS | `maybe_advance`：rounds≥3 且 p>0.8；不再用连续 2 次 blue_win |
| P2-E | PASS | rounds≥4 且 p<0.25 降级 |
| P3-A | PASS | 默认 10 主机 |
| P3-B..F | PASS | `generate_topology` / background / 无 payload |
| P4-A/B/D | PASS | fbeta / blue_score / radar / `decide_winner` |
| P4-C | PASS | audit 只写 `audit_detected`，默认 sim 不混 TP |
| P5-A..C | PASS | `observe_gaps`；有 goal 不推翻课程 |
| N-A/B | PASS | `score_layered`；旧 `score()` 保留 |

## 遗留

- 首次见到的 miss 只能 provisional 升级 overlay，独立泛化要等历史正样本。
- `p_level_clear` 用加权公式，与「recall≥0.7 且 ASR≤0.35 且胜率≥0.6」的与门不完全等价。
- LLM goal 挂在 `blue_view.round_goal`，未改 prompt 模板（strict_render）。
- 前端雷达未在浏览器里点选验证（无浏览器工具）。
- MiniMax QA 代理未登录，未能出具独立 QA 文件。
