"""learn_loop 每日学习闭环测试(PR1+PR2+PR3: 收割→统计/聚类/序列→提议→自动应用)。"""
import asyncio
import contextlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

# ── 测试环境前置(必须在 import models 之前注入) ──
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import sqlalchemy.ext.asyncio as _sa_async
_orig_create_async_engine = _sa_async.create_async_engine


def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)


_sa_async.create_async_engine = _patched_create_async_engine


def _run(coro):
    """显式 asyncio 驱动(每个测试独立 event loop, 跑完即关)。"""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()


@contextlib.asynccontextmanager
async def _db():
    """每个测试一个独立内存库引擎(绑定该测试自己的 event loop)。

    :memory: sqlite 默认池每连接一份独立库、跨 loop 复用连接会读到陈旧快照
    (实测偶发 flake)。StaticPool 单连接 + 测试内建/内销, 读写确定一致。
    """
    from sqlalchemy.pool import StaticPool
    from models import Base

    eng = _sa_async.create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    from sqlalchemy.ext.asyncio import async_sessionmaker
    sm = async_sessionmaker(eng, expire_on_commit=False)
    try:
        yield sm
    finally:
        await eng.dispose()


def _now_window(hours: int = 24):
    now = datetime.now(timezone.utc)
    return now - timedelta(hours=hours), now


def _inside() -> datetime:
    """窗口内固定时间点(避免列默认 now 落在窗口边界外)。"""
    return datetime.now(timezone.utc) - timedelta(minutes=30)


class TestLearnLoop:

    # ── harvest ──

    def test_harvest_empty_window(self):
        async def t():
            from learn_loop.harvest import harvest
            ws, we = _now_window()
            async with _db() as sm:
                async with sm() as s:
                    h = await harvest(s, ws, we)
            assert set(h.keys()) == {
                "baseline", "reputation", "feedback", "degrade",
                "tune", "postmortem", "case",
            }
            for key, val in h.items():
                assert isinstance(val, dict), key
                assert "count" in val and val["count"] == 0, key
                assert "error" not in val, key
            assert h["feedback"]["records"] == []
            assert h["case"]["cases"] == []
            assert h["postmortem"]["closed_without_pm"] == []
        _run(t())

    def test_harvest_windows_closed_cases_and_feedback(self):
        async def t():
            from models import SecurityCase, FeedbackRecord
            from learn_loop.harvest import harvest
            ws, we = _now_window()
            inside = _inside()
            async with _db() as sm:
                async with sm() as s:
                    s.add(FeedbackRecord(feedback_type="false_positive", rule_id="SIG-LEARN-1",
                                         original_conclusion="port_scan", status="submitted",
                                         created_at=inside))
                    s.add(SecurityCase(
                        case_number="CASE-LEARN-1", title="x", status="closed",
                        threat_type="PORT_SCAN", event_ids=[], src_ips=["1.2.3.4"],
                        event_count=0, priority="medium", disposition="误报",
                        created_at=inside, updated_at=inside, closed_at=inside,
                    ))
                    await s.commit()
                async with sm() as s:
                    h = await harvest(s, ws, we)
                    assert h["feedback"]["count"] == 1
                    assert h["feedback"]["records"][0]["rule_id"] == "SIG-LEARN-1"
                    assert h["case"]["count"] == 1
                    assert h["case"]["cases"][0]["disposition"] == "误报"
                    # closed 且无复盘 → 进入 closed_without_pm
                    assert len(h["postmortem"]["closed_without_pm"]) == 1
                    assert h["postmortem"]["closed_without_pm"][0]["id"] == \
                        h["case"]["cases"][0]["id"]
        _run(t())

    # ── stats: wilson 门槛 ──

    def test_wilson_small_n_not_shadow(self):
        async def t():
            from models import FeedbackRecord
            from learn_loop.harvest import harvest
            from learn_loop.models_stats import analyze_feedback
            from learn_loop.propose import propose
            ws, we = _now_window()
            inside = _inside()
            async with _db() as sm:
                async with sm() as s:
                    for _ in range(2):
                        s.add(FeedbackRecord(feedback_type="false_positive",
                                             rule_id="SIG-LEARN-2", status="submitted",
                                             created_at=inside))
                    await s.commit()
                async with sm() as s:
                    h = await harvest(s, ws, we)
                    stats = analyze_feedback(h["feedback"]["records"])
                    actions = propose(h, stats, [], {}, existing_keys=set())
                    shadows = [a for a in actions if a["action_type"] == "shadow_rule"]
                    assert shadows == []  # n=2 < 5 → 不许 shadow
        _run(t())

    def test_wilson_high_fp_shadow(self):
        async def t():
            from models import FeedbackRecord
            from learn_loop.harvest import harvest
            from learn_loop.models_stats import analyze_feedback
            from learn_loop.propose import propose
            ws, we = _now_window()
            inside = _inside()
            async with _db() as sm:
                async with sm() as s:
                    for _ in range(6):
                        s.add(FeedbackRecord(feedback_type="false_positive",
                                             rule_id="SIG-LEARN-3", status="submitted",
                                             created_at=inside))
                    s.add(FeedbackRecord(feedback_type="true_positive",
                                         rule_id="SIG-LEARN-3", status="submitted",
                                         created_at=inside))
                    await s.commit()
                async with sm() as s:
                    h = await harvest(s, ws, we)
                    stats = analyze_feedback(h["feedback"]["records"])
                    rule = (stats["by_rule"] or {}).get("SIG-LEARN-3") or {}
                    assert rule["n"] == 7 and rule["fp"] == 6
                    assert rule["lo"] > 0.15  # Wilson 下界显著
                    actions = propose(h, stats, [], {}, existing_keys=set())
                    shadows = [a for a in actions if a["action_type"] == "shadow_rule"
                               and a["target_id"] == "SIG-LEARN-3"]
                    assert len(shadows) == 1
                    assert shadows[0]["auto"] is True
                    assert shadows[0]["mechanism"] == "degrade"
        _run(t())

    # ── cluster ──

    def test_cluster_merges_similar_fp(self):
        from learn_loop.models_cluster import build_clusters
        events = [
            {"id": 101, "event_type": "PORT_SCAN", "src_ip": "10.0.0.7",
             "message": "portscan sweep detected high volume"},
            {"id": 102, "event_type": "PORT_SCAN", "src_ip": "10.0.0.8",
             "message": "portscan sweep detected high volume"},
            {"id": 103, "event_type": "PORT_SCAN", "src_ip": "10.0.0.9",
             "message": "portscan sweep detected massive volume"},
        ]
        clusters = build_clusters(events, min_size=3, threshold=0.5)
        assert len(clusters) == 1
        cl = clusters[0]
        assert cl["size"] == 3
        assert set(cl["event_ids"]) == {101, 102, 103}
        assert cl["net"] == "10.0.0.0/24"

    def test_cluster_keeps_small_clusters_out(self):
        from learn_loop.models_cluster import build_clusters
        events = [
            {"id": 1, "event_type": "PORT_SCAN", "src_ip": "10.1.0.1", "message": "a"},
            {"id": 2, "event_type": "SQL_INJECTION", "src_ip": "10.2.0.2", "message": "b"},
        ]
        assert build_clusters(events, min_size=3, threshold=0.5) == []

    # ── markov / sequence ──

    def test_markov_proposes_known_path(self):
        from learn_loop.models_sequence import build_sequences
        from learn_loop.propose import propose
        path = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"]
        res = build_sequences([path] * 6, patterns={}, min_count=5, min_p=0.4)
        assert res["transitions"]["PORT_SCAN>BRUTE_FORCE"] == 6
        assert res["transitions"]["BRUTE_FORCE>C2_BEACON"] == 6
        sigs = {s["from"] + ">" + s["to"]: s for s in res["signatures"]}
        assert "PORT_SCAN>BRUTE_FORCE" in sigs
        assert sigs["PORT_SCAN>BRUTE_FORCE"]["p"] == 1.0
        assert all(not s["duplicate"] for s in res["signatures"])  # patterns={} 无已知覆盖
        actions = propose({}, {}, [], res, existing_keys=set())
        seq_actions = [a for a in actions if a["action_type"] == "propose_sequence_signature"]
        assert len(seq_actions) >= 2
        assert all(a["auto"] is False for a in seq_actions)
        assert any(a["target_id"] == "PORT_SCAN>BRUTE_FORCE" for a in seq_actions)

    def test_markov_skips_known_pattern_edges(self):
        """既有 CEP 模式覆盖的转移 → duplicate → propose 跳过。"""
        from learn_loop.models_sequence import build_sequences
        from learn_loop.propose import propose
        path = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"]
        res = build_sequences([path] * 6)  # patterns=None → 导入 correlation_engine 模式
        assert any(s["duplicate"] for s in res["signatures"])
        actions = propose({}, {}, [], res, existing_keys=set())
        seq_actions = [a for a in actions if a["action_type"] == "propose_sequence_signature"]
        assert seq_actions == []

    def test_markov_requires_min_count(self):
        from learn_loop.models_sequence import build_sequences
        res = build_sequences([["PORT_SCAN", "BRUTE_FORCE"]] * 2,
                              patterns={}, min_count=5, min_p=0.4)
        assert res["signatures"] == []

    # ── 去重 ──

    def test_duplicate_actions_suppressed(self):
        from learn_loop.models_stats import analyze_feedback
        from learn_loop.propose import propose
        harvest = {
            "reputation": {"ip_counts": {"1.2.3.4": {"tp": 1, "fp": 3}}},
            "postmortem": {"closed_without_pm": []},
            "tune": {"suggestions": []},
            "feedback": {"records": [
                {"rule_id": "SIG-LEARN-4", "feedback_type": "false_positive",
                 "original_conclusion": ""},
            ] * 6},
        }
        stats = analyze_feedback(harvest["feedback"]["records"])
        existing = {
            "shadow_rule:SIG-LEARN-4",          # 24h 内已提议
            "update_reputation_prior:1.2.3.4",  # 24h 内已提议
        }
        actions = propose(harvest, stats, [], {}, existing_keys=existing)
        types = {(a["action_type"], a["target_id"]) for a in actions}
        assert ("shadow_rule", "SIG-LEARN-4") not in types
        assert ("update_reputation_prior", "1.2.3.4") not in types
        # 不同键的同类证据仍可提议(decay 键未被 existing_keys 覆盖)
        assert ("decay_baseline_entity", "1.2.3.4") in types

    # ── ops_loop: shadow + reload ──

    def test_downgrade_reloads_sigma(self):
        from ops_loop import apply_rule_downgrade
        fake_detector = mock.Mock()
        fake_detector.reload = mock.Mock(return_value=None)
        with mock.patch("sigma_engine.store.shadow",
                        return_value={"success": True, "rule_id": "SIG-RELOAD-1"}) as sh, \
             mock.patch("sigma_detector.sigma_detector", fake_detector):
            result = apply_rule_downgrade("SIG-RELOAD-1")
        sh.assert_called_once_with("SIG-RELOAD-1", True)
        fake_detector.reload.assert_called_once()
        assert result["sigma"]["success"] is True
        assert result["sigma"].get("reloaded") is True
        # 未映射响应策略 → 明示 policy_unmapped(不再是 None)
        rp = result.get("response_policy") or {}
        assert rp.get("error") == "policy_unmapped"

    def test_downgrade_policy_unmapped_not_none(self):
        from ops_loop import apply_rule_downgrade
        with mock.patch("sigma_engine.store.shadow",
                        return_value={"success": False, "error": "规则不存在"}):
            result = apply_rule_downgrade("SIG-NO-SUCH-999")
        assert result["sigma"]["success"] is False
        assert result["response_policy"] is not None  # sigma 失败不触发 reload

    # ── apply: llm 门 ──

    def test_llm_suggestion_cannot_auto_apply_sigma(self):
        async def t():
            from learn_loop.models_stats import analyze_feedback
            from learn_loop.propose import propose
            from learn_loop.apply import apply_action
            records = [
                {"rule_id": "SIG-LLM-1", "feedback_type": "false_positive",
                 "original_conclusion": "llm:审计误报"},
                {"rule_id": "SIG-LLM-1", "feedback_type": "false_positive",
                 "original_conclusion": "llm:审计误报"},
                {"rule_id": "SIG-LLM-1", "feedback_type": "false_positive",
                 "original_conclusion": "llm:审计误报"},
                {"rule_id": "SIG-LLM-1", "feedback_type": "false_positive",
                 "original_conclusion": "llm:审计误报"},
                {"rule_id": "SIG-LLM-1", "feedback_type": "false_positive",
                 "original_conclusion": "llm:审计误报"},
                {"rule_id": "SIG-LLM-1", "feedback_type": "false_positive",
                 "original_conclusion": "llm:审计误报"},
                {"rule_id": "SIG-LLM-1", "feedback_type": "true_positive",
                 "original_conclusion": "llm:审计确认"},
            ]
            stats = analyze_feedback(records)
            actions = propose({}, stats, [], {}, existing_keys=set())
            shadows = [a for a in actions if a["action_type"] == "shadow_rule"]
            assert len(shadows) == 1
            assert shadows[0]["auto"] is False  # llm: → 绝不自动 shadow

            async with _db() as sm:
                async with sm() as s:
                    # 即使手工把 llm 来源的 shadow 标成 auto=True 也会被 apply 拒绝
                    action = dict(shadows[0])
                    action["auto"] = True
                    action["target_type"] = "rule"
                    action["target_id"] = "SIG-LLM-1"
                    res = await apply_action(s, action, auto=True)
                    assert res["success"] is False
                    assert "llm" in res.get("error", "")
                    # apply_sigma_change(llm) 同样拒绝
                    res2 = await apply_action(s, {
                        "action_type": "apply_sigma_change", "target_type": "rule",
                        "target_id": "SIG-LLM-1", "mechanism": "degrade",
                        "payload": {"rule_id": "SIG-LLM-1", "original_conclusion": "llm:x"},
                    }, auto=False)
                    assert res2["success"] is False
                    assert "llm" in res2.get("error", "")
        _run(t())

    def test_auto_non_whitelist_skipped(self):
        async def t():
            from learn_loop.apply import apply_action
            async with _db() as sm:
                async with sm() as s:
                    res = await apply_action(s, {
                        "action_type": "label_cluster", "target_type": "cluster",
                        "target_id": "learn_cluster_0", "mechanism": "feedback",
                        "payload": {},
                    }, auto=True)
                    assert res["skipped"] is True
                    assert res["success"] is False
        _run(t())

    # ── apply: 基线衰减 / 信誉先验 ──

    def test_baseline_fp_decay(self):
        async def t():
            from anomaly_detector import anomaly_detector, EntityBaseline
            from learn_loop.apply import apply_action
            # 构造一条实体基线(清理单例, 避免污染其它用例)
            anomaly_detector.baselines["src_ip"]["10.9.9.9"] = EntityBaseline(
                hourly_counts=[10] * 24, daily_count=40, weekly_count=200,
                total_count=100, first_seen=1.0, last_seen=1.0,
                event_types={"PORT_SCAN"},
            )
            action = {
                "action_type": "decay_baseline_entity", "target_type": "ip",
                "target_id": "10.9.9.9", "mechanism": "baseline",
                "payload": {"entity_type": "src_ip", "entity_key": "10.9.9.9",
                            "factor": 0.5},
            }
            async with _db() as sm:
                async with sm() as s:
                    res = await apply_action(s, action, auto=True)
                    assert res["success"] is True
                    assert res["decay_irreversible"] is True
                async with sm() as s:
                    res2 = await apply_action(s, {
                        "action_type": "decay_baseline_entity", "target_type": "ip",
                        "target_id": "203.0.113.99", "mechanism": "baseline",
                        "payload": {"entity_type": "src_ip",
                                    "entity_key": "203.0.113.99"},
                    }, auto=True)
                    assert res2["success"] is False
                    assert res2["error"] == "entity_not_found"
            after = anomaly_detector.baselines["src_ip"]["10.9.9.9"]
            assert after.total_count == 50
            assert after.hourly_counts == [5] * 24
            assert after.daily_count == 20
            # 实体仍在(永不删除)
            assert "10.9.9.9" in anomaly_detector.baselines["src_ip"]
            del anomaly_detector.baselines["src_ip"]["10.9.9.9"]
        _run(t())

    def test_prior_clipped(self):
        async def t():
            from models import ReputationPrior
            from sqlalchemy import select
            from learn_loop.apply import apply_action
            action = {
                "action_type": "update_reputation_prior", "target_type": "ip",
                "target_id": "8.8.8.8", "mechanism": "reputation",
                "payload": {"target": "8.8.8.8", "target_type": "ip",
                            "tp": 100, "fp": 0},
            }
            async with _db() as sm:
                async with sm() as s:
                    res = await apply_action(s, action, auto=True)
                    assert res["success"] is True
                async with sm() as s:
                    row = (await s.execute(
                        select(ReputationPrior).where(
                            ReputationPrior.target == "8.8.8.8",
                            ReputationPrior.target_type == "ip",
                        )
                    )).scalars().first()
                    assert row is not None
                    assert row.tp_count == 100
                    assert abs(row.delta) <= 0.2  # clip: 0.05*100 → ±0.2
                    assert row.delta == 0.2
                # 反方向也 clip(累计 fp 拉低)
                async with sm() as s:
                    res2 = await apply_action(s, {
                        "action_type": "update_reputation_prior", "target_type": "ip",
                        "target_id": "8.8.8.8", "mechanism": "reputation",
                        "payload": {"target": "8.8.8.8", "target_type": "ip",
                                    "tp": 0, "fp": 1000},
                    }, auto=True)
                    assert res2["success"] is True
                    assert res2["delta"] == -0.2

                # 无 session 的信誉查询能读到 apply 同步的缓存先验(缓存 delta=-0.2,
                # 但信誉分有 0 下限 → score 被夹到 0.0, 仍带 learn_prior factor)
                from threat_intel.reputation import reputation_engine, _PRIOR_CACHE
                score = await reputation_engine.score_ip("8.8.8.8")  # session=None → cache
                assert score.score == 0.0
                assert any("learn_prior" in f for f in score.factors)
                assert _PRIOR_CACHE.get(("ip", "8.8.8.8")) == -0.2
        _run(t())

    # ── run_cycle fail-open ──

    def test_run_cycle_fail_open(self):
        async def t():
            from models import LearningRun
            from sqlalchemy import select
            from learn_loop.orchestrator import run_cycle
            async with _db() as sm:
                async with sm() as s:
                    with mock.patch("learn_loop.harvest.harvest",
                                    side_effect=RuntimeError("harvest boom")):
                        result = await run_cycle(s, trigger="daily")
                    assert isinstance(result, dict)
                    assert result["status"] in ("completed", "failed")
                    assert result["id"] is not None
                    assert "harvest" in result.get("error", "")
                async with sm() as s:
                    run = (await s.execute(select(LearningRun))).scalars().first()
                    assert run is not None
                    assert run.trigger == "daily"
                    assert run.status == "completed"  # 子收割失败 → 仍 completed
        _run(t())

    def test_run_cycle_skipped_when_disabled(self):
        async def t():
            from learn_loop.orchestrator import run_cycle
            async with _db() as sm:
                async with sm() as s:
                    with mock.patch("config.settings.learn_loop_enabled", False):
                        result = await run_cycle(s, trigger="daily")
                    assert result == {"skipped": True}
        _run(t())

    def test_run_cycle_harvest_propose_persist(self):
        """端到端: 反馈证据 → run → learning_runs/actions 落库 + shadow 自动应用。"""
        async def t():
            from models import FeedbackRecord, LearningAction, LearningRun, RuleVersion
            from sqlalchemy import select
            # SIG-LEARN-5 是测试假规则: mock apply_rule_downgrade,
            # 保证纯内存路径, 不写任何真实 sigma YAML
            with mock.patch("learn_loop.harvest._harvest_tune",
                            return_value={"count": 0, "suggestions": []}), \
                 mock.patch("ops_loop.apply_rule_downgrade",
                            return_value={"rule_id": "SIG-LEARN-5",
                                         "sigma": {"success": True, "shadow_mode": True},
                                         "response_policy": {"success": False,
                                                             "error": "policy_unmapped"}}):
                async with _db() as sm:
                    async with sm() as s:
                        for _ in range(6):
                            s.add(FeedbackRecord(feedback_type="false_positive",
                                                 rule_id="SIG-LEARN-5", status="submitted"))
                        s.add(FeedbackRecord(feedback_type="true_positive",
                                             rule_id="SIG-LEARN-5", status="submitted"))
                        await s.commit()
                    async with sm() as s:
                        from learn_loop.orchestrator import run_cycle
                        result = await run_cycle(s, trigger="daily")
                    assert result["status"] == "completed", result
                    assert result["actions_proposed"] >= 1, result
                    assert result["actions_auto_applied"] >= 1, result
                    async with sm() as s:
                        actions = (await s.execute(select(LearningAction))).scalars().all()
                        shadow_rows = [a for a in actions if a.action_type == "shadow_rule"]
                        assert shadow_rows, "shadow_rule 动作应已落库"
                        assert shadow_rows[0].status == "auto_applied"
                        assert shadow_rows[0].applied_by == "learn_loop"
                        # shadow_rule 写 RuleVersion 留痕
                        versions = (await s.execute(select(RuleVersion).where(
                            RuleVersion.rule_id == "SIG-LEARN-5"))).scalars().all()
                        assert len(versions) == 1
                        assert versions[0].content.get("shadow_mode") is True
                        runs = (await s.execute(select(LearningRun))).scalars().all()
                        assert len(runs) == 1 and runs[0].status == "completed"
        _run(t())

    # ── 边界 ──

    def test_self_play_untouched(self):
        """learn_loop/*.py 不得 import self_play.reviewer / self_play.orchestrator。"""
        from pathlib import Path
        learn_loop_dir = Path(__file__).resolve().parent.parent / "learn_loop"
        py_files = sorted(learn_loop_dir.glob("*.py"))
        assert py_files
        for fp in py_files:
            text = fp.read_text(encoding="utf-8")
            assert "self_play.reviewer" not in text, fp
            assert "self_play.orchestrator" not in text, fp
            assert "import self_play" not in text.replace("self_play.novelty", ""), fp
        # novelty.tokenize 只读导入被允许(models_cluster)
        cluster_src = (learn_loop_dir / "models_cluster.py").read_text(encoding="utf-8")
        assert "from self_play.novelty import tokenize" in cluster_src

    def test_models_not_rewritten(self):
        """约束复核: learn_loop 包不落在被禁止编辑的 self_play 内。"""
        learn_loop_dir = Path(__file__).resolve().parent.parent / "learn_loop"
        assert (learn_loop_dir / "__init__.py").exists()
        assert not learn_loop_dir.is_relative_to(
            Path(__file__).resolve().parent.parent / "self_play")


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short", "-s"])
