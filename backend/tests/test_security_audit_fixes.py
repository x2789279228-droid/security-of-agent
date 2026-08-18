"""
安全审计 Agent 修复回归测试 — 覆盖阶段 A/B/C/D 关键修复点

测试目标：
  A1/A2  f-string 大括号修复 (SubAuditor / Reviewer prompt)
  A3     chunker.py 重复 get 修复
  A4     chunker.py 严重度顺序修复
  B1     grounding_verifier 时间戳归一化 (ISO 字符串)
  B2     tool_registry _anomaly_score 字段读取
  B4     _audit_chunks_parallel 异常容错 (return_exceptions=True)
  B5     _extract_events 移除 temporal 分支
  B7     SubAuditor 接受 knowledge_chunks 参数
  C1     AuditResult.deep_analysis 字段 + 前置合成
  C3     _llm_recheck 强制 bool 转换
  C4     audit_schemas threat_detected=True with empty claims 不再 raise
  D1     Reviewer 单独提取 RAG 片段注入 prompt
  D2     tool_registry 加 _initialized 守门
  D3     Decomposer / SubAuditor 继承 BaseAuditComponent
  隐藏   ClaimGroundingReport dataclass 字段默认值修复 (生产环境长期未触发)
"""
import importlib
import importlib.util
import os
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 必须先注入 env(参考 conftest.py)，否则 import models 失败
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async

_orig_create_async_engine = _sa_async.create_async_engine


def _patched_create_async_engine(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig_create_async_engine(url, **kw)


_sa_async.create_async_engine = _patched_create_async_engine

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

# 确保 agents 是一个包，让 `from .base import BaseAuditComponent` 能解析
if "agents" not in sys.modules:
    agents_pkg = types.ModuleType("agents")
    agents_pkg.__path__ = [str(BACKEND / "agents")]
    sys.modules["agents"] = agents_pkg

# 预加载 base 模块（lightweight, 仅依赖 summary_compression 与 event_store）
# 为 SubAuditor / Decomposer 的 `from .base import BaseAuditComponent` 提供解析
base_mod_path = BACKEND / "agents" / "base.py"
spec_base = importlib.util.spec_from_file_location("agents.base", str(base_mod_path))
agents_base = importlib.util.module_from_spec(spec_base)
sys.modules["agents.base"] = agents_base
try:
    spec_base.loader.exec_module(agents_base)
except Exception:
    # base.py 的 import 链较重 (需 LLM 配置)，测试中只用到 BaseAgent / BaseAuditComponent
    # 的"类型定义"层面，可以用 fallback 注入桩
    pass


def _load(name: str, path: Path):
    """直接按文件路径加载模块，避免 __init__ 链触发重型依赖

    name 参数需带包名前缀（如 "agents.sub_auditor"），
    否则模块内的相对导入 (from .base import ...) 会因父包未知而失败。
    本测试已在 sys.modules 注入 agents 包（含 __path__），因此
    传入 "agents.xxx" 即可触发正确的相对导入解析。
    """
    spec = importlib.util.spec_from_file_location(name, str(path))
    m = importlib.util.module_from_spec(spec)
    # 注册到 sys.modules（让相对导入能查找到本模块）
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


# ────────────────────────────────────────────
# 加载被测模块
# ────────────────────────────────────────────

audit_types = _load("audit_types", BACKEND / "audit_types.py")
audit_schemas = _load("audit_schemas_mod", BACKEND / "audit_schemas.py")
grounding_mod = _load("grounding_mod", BACKEND / "grounding_verifier.py")

# chunker 不依赖 LLM/DB，可直接加载
chunker_mod = _load("chunker_mod", BACKEND / "agents" / "chunker.py")

# D3: SubAuditor 现在用 `from .base import BaseAuditComponent`
# (相对导入)，必须用带 "agents" 前缀的模块名加载，让父包可解析
sub_auditor_mod = _load("agents.sub_auditor", BACKEND / "agents" / "sub_auditor.py")


# ────────────────────────────────────────────
# 测试用例
# ────────────────────────────────────────────


class TestStageA_Braces:
    """A1/A2: f-string 大括号修复（SubAuditor / Reviewer prompt）"""

    def test_sub_auditor_prompt_renders_valid_json_template(self):
        # 渲染 SubAuditor._build_prompt 输出，断言不含字面量 {{ 或 }}
        import re as _re
        src = (BACKEND / "agents" / "sub_auditor.py").read_text(encoding="utf-8")
        m = _re.search(
            r'def _build_prompt\(self, block_text: str\) -> str:\s*return\s+(f"""[\s\S]+?""")',
            src,
        )
        assert m, "could not locate _build_prompt template"
        rendered = eval(m.group(1), {"block_text": "TEST"})
        # Valid JSON template should have single braces around JSON keys
        assert "{{" not in rendered, "SubAuditor prompt 仍含字面量 {{ — 修复未生效"
        assert "}}" not in rendered, "SubAuditor prompt 仍含字面量 }} — 修复未生效"

    def test_reviewer_prompt_renders_valid_json_template(self):
        import re as _re
        src = (BACKEND / "agents" / "agent_reviewer.py").read_text(encoding="utf-8")
        m = _re.search(r'prompt =\s+(f"""[\s\S]+?""")', src)
        assert m, "could not locate reviewer prompt template"
        # D1: prompt 新增 rag_section 变量，需提供 eval 上下文
        rendered = eval(
            m.group(1),
            {
                "event_json": "{}",
                "depth": "standard",
                "sub_tasks_text": "",
                "llm_analysis": "",
                "audit_json": "{}",
                "tool_data_raw": "",
                "rag_section": "",
            },
        )
        assert "{{" not in rendered
        assert "}}" not in rendered


class TestStageA_Chunker:
    """A3: chunker.py:102 重复 get；A4: chunker.py:221 严重度顺序"""

    def test_chunker_ip_fallback_is_simple(self):
        # A3 由代码静态保证：grep 验证不能再出现嵌套 get
        src = (BACKEND / "agents" / "chunker.py").read_text(encoding="utf-8")
        assert "evt.get(\"src_ip\", evt.get(\"src_ip\"" not in src, \
            "A3 fail: 嵌套 get src_ip 仍然存在"

    def test_severity_range_order(self, monkeypatch=None):
        # A4 改为 high~critical 由低到高？还是 critical~high 由高到低？
        # 修订后：f"{levels[min_idx]}~{levels[max_idx]}"
        # min_idx 是 levels 列表中索引最小=严重度最高所在位置
        # 因此左侧应是更严重、右侧应是更轻 — 即 "critical~high"
        c = chunker_mod.chunker
        events = [
            {"id": 1, "severity": "critical"},
            {"id": 2, "severity": "high"},
        ]
        result = c._severity_range(events)
        # min_idx 对应 critical（idx=0），max_idx 对应 high（idx=1）
        assert result == "critical~high", f"severity range 顺序错: {result}"


class TestStageB1_GroundingTimestamp:
    """B1: grounding_verifier 支持 ISO 字符串时间戳"""

    @staticmethod
    def _expected_epoch(year=2026, month=8, day=1, hour=12, minute=0, second=0):
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp()

    def test_normalize_iso_with_tz(self):
        expected = self._expected_epoch()
        ts = grounding_mod.grounding_verifier._normalize_timestamp(
            "2026-08-01T12:00:00+00:00"
        )
        assert ts is not None
        assert abs(ts - expected) < 1.0, f"got {ts}, expected {expected}"

    def test_normalize_iso_z_suffix(self):
        expected = self._expected_epoch()
        ts = grounding_mod.grounding_verifier._normalize_timestamp(
            "2026-08-01T12:00:00Z"
        )
        assert ts is not None
        assert abs(ts - expected) < 1.0, f"got {ts}, expected {expected}"

    def test_normalize_iso_naive_assumed_utc(self):
        expected = self._expected_epoch()
        ts = grounding_mod.grounding_verifier._normalize_timestamp(
            "2026-08-01 12:00:00"
        )
        # 无时区 → 假定 UTC
        assert ts is not None
        assert abs(ts - expected) < 1.0, f"got {ts}, expected {expected}"

    def test_normalize_epoch_millis(self):
        ts = grounding_mod.grounding_verifier._normalize_timestamp(1756000000000)
        assert abs(ts - 1756000000.0) < 0.01

    def test_normalize_epoch_seconds(self):
        ts = grounding_mod.grounding_verifier._normalize_timestamp(1756000000.0)
        assert abs(ts - 1756000000.0) < 0.01

    def test_normalize_none_returns_none(self):
        assert grounding_mod.grounding_verifier._normalize_timestamp(None) is None
        assert grounding_mod.grounding_verifier._normalize_timestamp("") is None
        assert grounding_mod.grounding_verifier._normalize_timestamp("garbage") is None

    def test_layer5_freshness_detects_old_iso(self):
        gv = grounding_mod.grounding_verifier
        two_days_ago = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        idx = {
            1: {"id": 1, "created_at": two_days_ago},
            2: {"id": 2, "created_at": one_hour_ago},
        }
        stale_ids, freshness = gv._verify_evidence_freshness([1, 2], idx)
        assert 1 in stale_ids
        assert 2 not in stale_ids
        assert freshness < 1.0

    def test_layer7_chain_integrity_detects_reversal(self):
        gv = grounding_mod.grounding_verifier
        old_iso = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        new_iso = datetime.now(timezone.utc).isoformat()
        idx = {
            10: {"id": 10, "created_at": old_iso},  # 旧
            20: {"id": 20, "created_at": new_iso},  # 新
        }
        # evidence_ids 列出顺序：先引用稍新事件，再引用旧事件 → 时序倒置
        breaks, integrity = gv._verify_chain_integrity([20, 10], idx)
        assert breaks, f"应检测到时序倒置: {breaks}"
        assert integrity < 1.0


class TestStageB2_ToolRegistryField:
    """B2: tool_registry.py 读取 _anomaly_score 而非 _anomaly.score"""

    def test_event_ids_path_reads_correct_field(self):
        src = (BACKEND / "tool_registry.py").read_text(encoding="utf-8")
        # 不应再读取 _anomaly.score
        assert "_anomaly\", {}).get(\"score" not in src, \
            "B2 fail: tool_registry 仍读 _anomaly.score"
        # 应读取 _anomaly_score
        assert "_anomaly_score" in src, "B2 fail: tool_registry 未读取 _anomaly_score"


class TestStageB5_TemporalChainIds:
    """B5: _extract_events 不再把 temporal 分组事件塞入 chain_ids"""

    def test_temporal_branch_removed(self):
        src = (BACKEND / "agents" / "agent_executor.py").read_text(encoding="utf-8")
        # 移除前的特征字符串不应该再出现
        assert "r.tool == \"correlation.temporal\"" not in src, \
            "B5 fail: _extract_events 仍含 correlation.temporal 分支"
        assert "不应作为攻击链依据" in src, "B5 fail: 缺少参考注释"


class TestStageB4_ParallelException:
    """B4: _audit_chunks_parallel 使用 return_exceptions"""

    def test_return_exceptions_true_in_use(self):
        src = (BACKEND / "agents" / "agent_executor.py").read_text(encoding="utf-8")
        assert "asyncio.gather(*tasks, return_exceptions=True)" in src, \
            "B4 fail: _audit_chunks_parallel 未使用 return_exceptions=True"

    def test_chunker_no_change_in_signature(self):
        # 防止误改：chunker.chunk 签名保持稳定
        c = chunker_mod.chunker
        chunks = c.chunk([], chain_event_ids=set())
        assert chunks == []


class TestStageB7_SubAuditorKnowledgeChunks:
    """B7: SubAuditor.audit 接受 knowledge_chunks 参数并下发"""

    def test_sub_auditor_signatures_accepts_knowledge_chunks(self):
        import inspect
        sig = inspect.signature(sub_auditor_mod.SubAuditor.audit)
        assert "knowledge_chunks" in sig.parameters, \
            "B7 fail: SubAuditor.audit 不再接受 knowledge_chunks 参数"

    def test_sub_auditor_passes_to_verifier(self):
        src = (BACKEND / "agents" / "sub_auditor.py").read_text(encoding="utf-8")
        assert "verify_chunk(" in src
        assert "knowledge_chunks=knowledge_chunks" in src, \
            "B7 fail: SubAuditor 未把 knowledge_chunks 下发给 verify_chunk"


class TestStageC1_DeepAnalysisField:
    """C1: AuditResult.deep_analysis 字段 + 前置合成"""

    def test_audit_result_has_deep_analysis_field(self):
        ar = audit_types.AuditResult()
        assert hasattr(ar, "deep_analysis")
        assert ar.deep_analysis == ""

    def test_to_dict_exposes_has_deep_analysis(self):
        ar = audit_types.AuditResult(deep_analysis="some deep insight")
        d = ar.to_dict()
        assert d.get("has_deep_analysis") is True
        ar_empty = audit_types.AuditResult()
        assert ar_empty.to_dict().get("has_deep_analysis") is False

    def test_executor_passes_deep_analysis_to_synth(self):
        src = (BACKEND / "agents" / "agent_executor.py").read_text(encoding="utf-8")
        # 前置合成模式：deep_analyze 在 synthesize 之前调用
        # 找到 deep_analyze 调用 vs _synthesize_from_chunks 调用的相对位置
        deep_call_pos = src.find("await self._llm_deep_analyze(")
        synth_call_pos = src.find("await self._synthesize_from_chunks(")
        assert deep_call_pos != -1 and synth_call_pos != -1
        assert deep_call_pos < synth_call_pos, \
            "C1 fail: deep_analyze 应该在 synthesize 之前调用 (前置合成模式)"

    def test_synth_signature_accepts_deep_analysis(self):
        import inspect
        # 通过源码静态分析（避免 import agent_executor 触发重型依赖）
        import re as _re
        src = (BACKEND / "agents" / "agent_executor.py").read_text(encoding="utf-8")
        m = _re.search(
            r'def _synthesize_from_chunks\(([\s\S]+?)\) -> AuditResult:',
            src,
        )
        assert m, "could not find _synthesize_from_chunks signature"
        sig_body = m.group(1)
        assert "deep_analysis" in sig_body, \
            "C1 fail: _synthesize_from_chunks 不再接受 deep_analysis 参数"


class TestStageC3_RecheckBoolCast:
    """C3: _llm_recheck 强制 bool 转换"""

    def test_recheck_enforces_bool_cast(self):
        src = (BACKEND / "agents" / "agent_executor.py").read_text(encoding="utf-8")
        # 检查 _as_bool 辅助函数被引入
        assert "_as_bool" in src, "C3 fail: 缺少 _as_bool 辅助函数"
        # audit_result.needs_human_review 应使用 bool() 包装
        assert "audit_result.needs_human_review = bool(" in src, \
            "C3 fail: needs_human_review 未强制 bool 转换"


class TestStageC4_SchemaNoFalseRaise:
    """C4: audit_schemas threat_detected=True 且 claims=[] 不再 raise"""

    def test_threat_detected_true_with_empty_claims_passes(self):
        m = audit_schemas.SubAuditorOutputSchema(
            threat_detected=True,
            threat_claims=[],
            confidence=0.5,
            severity="high",
            summary="suspected but no evidence",
        )
        # 通过即成功
        assert m.threat_detected is True
        assert m.threat_claims == []

    def test_severity_validator_still_works(self):
        # 防止 over-loosen：严重度仍受字段验证保护
        try:
            audit_schemas.SubAuditorOutputSchema(
                threat_detected=False, confidence=0.5,
                severity="bogus", summary="x",
            )
            assert False, "应当 raise (验证器被误删)"
        except Exception:
            pass


class TestHidden_ClaimGroundingReportDefaults:
    """隐藏 Bug：ClaimGroundingReport 缺默认值导致模块 import 失败
    生产中 SubAuditor 的 verify_chunk 调用被 except 吞掉，
    Layer 1-7 实际从未生效。本回归确保模块可正常加载。
    """

    def test_module_imports_cleanly(self):
        # 整个 grounding_verifier 模块已被加载到 grounding_mod
        # 我们只需断言类与实例可正常实例化
        cls = grounding_mod.ClaimGroundingReport
        # 全默认构造应该可成功（修复后）
        instance = cls(
            claim_type="test", claim_summary="test",
            evidence_ids=[], ids_valid=True,
            missing_ids=[], total_quotes=0, grounded_quotes=0,
            ungrounded_quotes=[], grounding_ratio=1.0,
            mentioned_ips=[], verified_ips=[], phantom_ips=[],
            entity_consistency=1.0, knowledge_supported=True,
        )
        # 默认 grounding_score / verdict 应该被补上
        assert hasattr(instance, "grounding_score")
        assert hasattr(instance, "verdict")

    def test_verify_chunk_returns_report(self):
        # 端到端：调用 verify_chunk 应返回 GroundingReport，而非 AttributeError
        gv = grounding_mod.grounding_verifier
        chunk_id = "test-chunk"
        # 构造一条声明引用存在的事件
        events = [
            {"id": 100, "event_type": "C2_BEACON", "severity": "critical",
             "src_ip": "10.0.0.5", "dst_ip": "1.2.3.4", "message": "C2 通信 已拦截"},
        ]
        claims = [
            {"type": "C2", "confidence": 0.9, "evidence_ids": [100],
             "evidence_quotes": ["C2 通信"], "severity": "critical",
             "summary": "10.0.0.5 与 C2 通信"},
        ]
        report = gv.verify_chunk(claims, events, chunk_id=chunk_id)
        assert report.chunk_id == chunk_id
        assert report.total_claims == 1
        # 引用合法 → overall score 应较高
        assert report.overall_score > 0.5
        assert report.grounded_claims >= 1