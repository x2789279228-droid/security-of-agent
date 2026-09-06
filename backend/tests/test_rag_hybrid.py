"""RAG 混合检索原语与 retrieve 管道。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from rag.lexical import (
    build_search_lex,
    encode_sparse,
    expand_query_text,
    extract_security_terms,
    rrf_fuse,
    tokenize,
)
from rag.query_transform import transform_query
from rag.reranker import feature_rerank, rerank_candidate_urls
from rag.lexical import lexical_needles


class TestLexical:
    def test_extracts_cve_attack_hash(self):
        text = "检测到 CVE-2021-44228 与 T1059.001，hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        terms = extract_security_terms(text)
        joined = " ".join(terms).upper()
        assert "CVE-2021-44228" in joined
        assert "T1059.001" in joined

    def test_expand_marks_lexical_first_for_cve(self):
        st = expand_query_text("CVE-2021-44228 log4j")
        assert st["lexical_first"] is True
        assert "CVE-2021-44228" in st["lexical_query"].upper() or "cve-2021-44228" in st["lexical_query"].lower()

    def test_expand_t1059_adds_aliases(self):
        st = expand_query_text("T1059.001 可疑脚本")
        blob = st["lexical_query"].lower()
        assert "powershell" in blob or "命令执行" in blob
        assert st["lexical_first"] is True

    def test_cjk_bigrams_in_search_lex(self):
        lex = build_search_lex("横向移动检测", "通过 RDP 横向移动")
        assert "横向" in lex or "rdp" in lex.lower()

    def test_sparse_tf_nonempty_and_stable(self):
        a = encode_sparse("CVE-2021-44228 T1059", backend="builtin")
        b = encode_sparse("CVE-2021-44228 T1059", backend="builtin")
        assert a[0] and a[1]
        assert a == b
        assert len(a[0]) == len(a[1])

    def test_tokenize_empty(self):
        assert tokenize("") == []
        idx, val = encode_sparse("", backend="builtin")
        assert idx == [] and val == []


class TestRRF:
    def test_fusion_prefers_consensus(self):
        fused = rrf_fuse({
            "dense": ["a", "b", "c"],
            "bm25": ["c", "a", "d"],
        }, k=60)
        ids = [r["id"] for r in fused]
        assert ids[0] == "a"  # rank1 dense + rank2 bm25
        assert "c" in ids
        a = next(r for r in fused if r["id"] == "a")
        assert a["ranks"]["dense"] == 1
        assert a["ranks"]["bm25"] == 2
        assert a["rrf_score"] > next(r for r in fused if r["id"] == "d")["rrf_score"]

    def test_single_list(self):
        fused = rrf_fuse({"dense": ["x", "y"]}, k=60)
        assert [r["id"] for r in fused] == ["x", "y"]

    def test_dedupes_within_channel(self):
        fused = rrf_fuse({"bm25": ["a", "a", "b"]}, k=60)
        assert [r["id"] for r in fused] == ["a", "b"]


class TestTransform:
    def test_rules_no_llm(self):
        import asyncio
        st = asyncio.run(
            transform_query("T1021.001 rdp", rewrite="rules", hyde="off", skip_llm=True)
        )
        assert st["lexical_first"] is True
        assert not st.get("hyde_text")

    def test_skip_llm_blocks_hyde(self):
        import asyncio
        st = asyncio.run(
            transform_query("如何检测横向移动", rewrite="llm", hyde="always", skip_llm=True)
        )
        assert st["hyde_text"] == ""
        assert st["rewritten"] == st["original"] or st["original"]


class TestFeatureRerank:
    def test_title_hit_bubbles_up(self):
        chunks = [
            {"id": 1, "title": "无关", "content": "hello world", "score": 0.9, "rrf_score": 0.01},
            {"id": 2, "title": "CVE-2021-44228 Log4Shell", "content": "jndi ldap", "score": 0.2, "rrf_score": 0.008},
        ]
        out = feature_rerank("CVE-2021-44228", chunks, top_k=2)
        assert out[0]["id"] == 2
        assert out[0]["rerank_backend"] == "feature"


class TestNeedlesAndUrls:
    def test_cve_query_needles_include_id_and_alias(self):
        needles = [n.lower() for n in lexical_needles("CVE-2021-44228 log4j remote code execution")]
        assert any("cve-2021-44228" in n for n in needles)
        assert any("log4j" in n or "log4shell" in n for n in needles)

    def test_log4j_query_expands_to_cve(self):
        st = expand_query_text("log4j jndi")
        blob = (st["lexical_query"] + " " + " ".join(st["keywords"])).upper()
        assert "CVE-2021-44228" in blob

    def test_rerank_urls_do_not_nest_paths(self):
        urls = rerank_candidate_urls("http://soc-bge-rerank:7997/rerank")
        assert "http://soc-bge-rerank:7997/rerank" in urls
        assert "http://soc-bge-rerank:7997/v1/rerank" in urls
        assert all("/rerank/v1/rerank" not in u for u in urls)

    def test_empty_rerank_url_does_not_fallback_to_llm_gateway(self):
        from rag.reranker import resolve_rerank_url
        class S:
            rag_rerank_url = ""
            llm_base_url = "https://api.minimaxi.com/v1"
        assert resolve_rerank_url(S()) == ""
