"""
安全 RAG 模块 — 减少 Audit-LLM 幻觉

架构:
  KnowledgeBase (知识库管理)
      → SecurityChunker (安全专用分块)
      → Embedder (复用现有 embedding)
      → Retriever (混合检索 + 多维度过滤)
      → ContextBuilder (构建 RAG 上下文注入 LLM)
      → EvidenceVerifier (验证 LLM 断言)
      → Seeder (预置安全知识)
      → MITREImporter (MITRE ATT&CK 导入)
      → CAPECImporter (CAPEC 攻击模式导入)

集成点:
  - SubAuditor: 审核前检索相关知识，减少无依据断言
  - Executor: 汇总阶段用 RAG 上下文做交叉验证
  - Reviewer: 用知识库验证结论准确性
  - CAD Agent: 验证断言是否与知识库一致
"""
from .knowledge_base import kb_manager, KnowledgeBaseManager
from .chunker import security_chunker, SecurityChunker
from .retriever import retriever, Retriever, RetrievalResult
from .context_builder import RAGContextBuilder, rag_context_builder
from .evidence_verifier import evidence_verifier, EvidenceVerifier
from .seeder import seed_knowledge_base
from .mitre_importer import import_enterprise_attack, MITREImportResult
from .capec_importer import import_capec, CAPECImportResult
from .cve_importer import import_cves, CVEImportResult
from .kev_importer import import_kev, KEVImportResult
from .policy_importer import import_policy, PolicyImportResult, POLICY_LIBRARY
from .vuln_seed import import_vuln_seed, VulnImportResult, VULN_SEED
from .import_status import (
    import_lock,
    get_import_status, set_import_status, ImportStatus,
)

__all__ = [
    "kb_manager", "KnowledgeBaseManager",
    "security_chunker", "SecurityChunker",
    "retriever", "Retriever", "RetrievalResult",
    "rag_context_builder", "RAGContextBuilder",
    "evidence_verifier", "EvidenceVerifier",
    "seed_knowledge_base",
    "import_enterprise_attack", "MITREImportResult",
    "import_capec", "CAPECImportResult",
    "import_cves", "CVEImportResult",
    "import_kev", "KEVImportResult",
    "import_policy", "PolicyImportResult", "POLICY_LIBRARY",
    "import_vuln_seed", "VulnImportResult", "VULN_SEED",
    "import_lock",
    "get_import_status", "set_import_status", "ImportStatus",
]
