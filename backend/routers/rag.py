"""
RAG 知识库域路由 — 检索、文档管理、断言验证、MITRE/CAPEC 导入、质量评估
"""
import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from models import get_session
from auth import get_current_user, RequireRole, UserInfo
from summary_compression import embedder
from rag import (
    kb_manager, retriever, security_chunker, seed_knowledge_base,
    evidence_verifier, RAGContextBuilder,
    import_enterprise_attack, import_capec,
    get_import_status, set_import_status, ImportStatus,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["rag"])


# ── RAG 知识库端点 ──

class RAGSearchRequest(BaseModel):
    query: str = ""
    threat_type: str = ""
    severity: str = ""
    source: str = ""
    top_k: int = 5
    min_score: float = 0.0

@router.post("/rag/search")
async def rag_search(
    req: RAGSearchRequest,
    session: AsyncSession = Depends(get_session)
):
    """检索安全知识库"""
    query_embedding = None
    if req.query:
        query_embedding = await embedder.embed(req.query)
    result = await retriever.retrieve(
        session,
        query=req.query,
        query_embedding=query_embedding,
        threat_type=req.threat_type,
        severity=req.severity,
        source=req.source,
        top_k=req.top_k,
        min_score=req.min_score,
    )
    return {
        "total": result.total_found,
        "strategy": result.strategy_used,
        "chunks": result.chunks,
    }

@router.get("/rag/documents")
async def rag_list_documents(
    threat_type: str = Query(""),
    source: str = Query(""),
    limit: int = Query(20),
    offset: int = Query(0),
    session: AsyncSession = Depends(get_session)
):
    """列出知识库文档"""
    docs = await kb_manager.search_documents(
        session,
        threat_type=threat_type,
        source=source,
        limit=limit,
        offset=offset,
    )
    return {"documents": docs, "total": len(docs)}

@router.get("/rag/documents/{doc_id}")
async def rag_get_document(
    doc_id: int,
    session: AsyncSession = Depends(get_session)
):
    """获取单个知识文档"""
    doc = await kb_manager.get_document(session, doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    return doc

@router.delete("/rag/documents/{doc_id}")
async def rag_delete_document(
    doc_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """删除知识文档"""
    ok = await kb_manager.delete_document(session, doc_id)
    if not ok:
        raise HTTPException(404, "Document not found")
    return {"deleted": True}

class RAGAddDocumentRequest(BaseModel):
    title: str = "未命名"
    content: str = ""
    source: str = "internal"
    threat_types: list[str] = []
    severity: str = "medium"
    tags: list[str] = []

@router.post("/rag/documents")
async def rag_add_document(
    req: RAGAddDocumentRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """添加知识文档（自动分块+向量化）"""
    from models import KnowledgeChunk

    title = req.title
    content = req.content
    source = req.source
    threat_types = req.threat_types
    severity = req.severity
    tags = req.tags

    # 添加文档
    doc = await kb_manager.add_document(
        session, title, content, source, threat_types, severity, tags,
    )
    doc_id = doc["id"]

    # 分块
    chunks = security_chunker.chunk_document(
        doc_id, title, content, source, threat_types, severity, tags,
    )

    # 计算向量并写入
    total_chunks = 0
    for chunk_data in chunks:
        vec = await embedder.embed(chunk_data["content"][:1000])
        chunk = KnowledgeChunk(
            doc_id=chunk_data["doc_id"],
            chunk_id=chunk_data["chunk_id"],
            content=chunk_data["content"],
            title=title,
            source=source,
            threat_types=threat_types,
            severity=severity,
            tags=tags,
            embedding=vec,
            token_count=chunk_data["token_count"],
        )
        session.add(chunk)
        total_chunks += 1

    await session.commit()

    return {
        "doc_id": doc_id,
        "title": title,
        "chunks_created": total_chunks,
    }

class RAGVerifyRequest(BaseModel):
    claim: str = ""
    threat_type: str = ""
    severity: str = ""

@router.post("/rag/verify")
async def rag_verify_claim(
    req: RAGVerifyRequest,
    session: AsyncSession = Depends(get_session)
):
    """验证断言是否被知识库支撑（减少幻觉的核心功能）"""
    claim = req.claim
    threat_type = req.threat_type
    severity = req.severity

    query_embedding = None
    if claim:
        query_embedding = await embedder.embed(claim)

    report = await evidence_verifier.verify_claim(
        session, claim, threat_type, severity, query_embedding,
    )
    return {
        "claim": claim,
        "verdict": report.verdict,
        "confidence": report.confidence,
        "supporting_evidence": report.supporting_evidence,
        "suggestion": report.suggestion,
    }

@router.get("/rag/stats")
async def rag_stats(
    session: AsyncSession = Depends(get_session)
):
    """知识库统计"""
    stats = await kb_manager.get_stats(session)
    return stats

@router.post("/rag/reseed")
async def rag_reseed(
    session: AsyncSession = Depends(get_session)
):
    """重新播种知识库"""
    await seed_knowledge_base(session)
    return {"status": "reseeded"}

@router.get("/rag/import/status")
async def rag_import_status():
    """查询当前导入进度"""
    status = get_import_status()
    if not status:
        return {"running": False, "message": "No import in progress"}
    return status.to_dict()

@router.post("/rag/import/mitre")
async def rag_import_mitre(
    limit: int = Query(0, description="最大导入数(0=全部)"),
    session: AsyncSession = Depends(get_session),
):
    """从 MITRE ATT&CK 官方数据源导入完整攻击技术库"""
    s = ImportStatus()
    s.start("mitre-attack")
    set_import_status(s)
    try:
        result = await import_enterprise_attack(session, limit=limit)
        s.finish(result.imported, result.skipped, result.errors, result.error_details)
        return {"status": "ok" if result.errors == 0 else "partial", "source": "mitre-attack", **result.to_dict()}
    except Exception as e:
        s.fail(str(e))
        raise

@router.post("/rag/import/capec")
async def rag_import_capec(
    limit: int = Query(0, description="最大导入数(0=全部)"),
    session: AsyncSession = Depends(get_session),
):
    """从 MITRE CAPEC 官方数据源导入完整攻击模式库"""
    s = ImportStatus()
    s.start("capec")
    set_import_status(s)
    try:
        result = await import_capec(session, limit=limit)
        s.finish(result.imported, result.skipped, result.errors, result.error_details)
        return {"status": "ok" if result.errors == 0 else "partial", "source": "capec", **result.to_dict()}
    except Exception as e:
        s.fail(str(e))
        raise

@router.post("/rag/import/all")
async def rag_import_all(
    session: AsyncSession = Depends(get_session),
):
    """导入所有 MITRE 知识库 (ATT&CK + CAPEC + 预置知识)"""
    s = ImportStatus()
    s.start("all")
    set_import_status(s)
    try:
        await seed_knowledge_base(session)
        mitre = await import_enterprise_attack(session)
        capec = await import_capec(session)
        total = mitre.imported + capec.imported
        s.finish(total, mitre.skipped + capec.skipped, mitre.errors + capec.errors)
        return {"status": "ok", "seed": {"status": "done"}, "mitre_attack": mitre.to_dict(), "capec": capec.to_dict()}
    except Exception as e:
        s.fail(str(e))
        raise

# ── 质量评估端点 ──

async def _embed_contexts(contexts: list[dict]) -> list[list[float]]:
    """为评估上下文批量计算 embedding（并发，失败返回空列表）"""
    if not contexts:
        return []
    sem = asyncio.Semaphore(5)

    async def embed_one(ctx: dict):
        async with sem:
            try:
                return await embedder.embed(str(ctx.get("content", ""))[:2000])
            except Exception:
                return None

    vectors = await asyncio.gather(*[embed_one(c) for c in contexts])
    return [v for v in vectors if v]

class RAGEvalRequest(BaseModel):
    query: str
    contexts: list[dict] = []
    ground_truth: str = ""
    retrieval_strategy: str = ""

class RAGEvalAutoRequest(BaseModel):
    query: str
    threat_type: str = ""
    severity: str = ""
    top_k: int = 5
    ground_truth: str = ""

class FaithfulnessEvalRequest(BaseModel):
    answer: str
    contexts: list[dict] = []
    query: str = ""
    prompt_version: str = ""

@router.post("/eval/rag")
async def eval_rag(
    req: RAGEvalRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """评估一次 RAG 检索质量（传入查询与检索上下文）"""
    from eval_service import evaluate_rag_retrieval
    return await evaluate_rag_retrieval(
        query=req.query,
        contexts=req.contexts,
        ground_truth=req.ground_truth,
        retrieval_strategy=req.retrieval_strategy,
    )

@router.post("/eval/rag/auto")
async def eval_rag_auto(
    req: RAGEvalAutoRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """对真实知识库检索做自动质量评估（检索 + 评估一体化）"""
    from rag.retriever import retriever
    from eval_service import evaluate_rag_retrieval

    query_embedding = None
    try:
        query_embedding = await embedder.embed(req.query)
    except Exception:
        pass
    result = await retriever.retrieve(
        session,
        query=req.query,
        query_embedding=query_embedding,
        threat_type=req.threat_type,
        severity=req.severity,
        top_k=req.top_k,
    )
    contexts = [
        {"title": c["title"], "content": c["content"], "source": c["source"], "score": c.get("score", 0)}
        for c in result.chunks
    ]
    context_embeddings = await _embed_contexts(contexts)
    run = await evaluate_rag_retrieval(
        query=req.query,
        contexts=contexts,
        ground_truth=req.ground_truth,
        retrieval_strategy=f"{result.strategy_used}:top{req.top_k}",
        answer_embedding=query_embedding,
        context_embeddings=context_embeddings,
    )
    return {"search": {"total": result.total_found, "strategy": result.strategy_used, "chunks": result.chunks}, "eval": run}

@router.post("/eval/faithfulness")
async def eval_faithfulness(
    req: FaithfulnessEvalRequest,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """评估回答对上下文的忠实度（防幻觉）"""
    from eval_service import evaluate_faithfulness
    context_embeddings = await _embed_contexts(req.contexts)
    return await evaluate_faithfulness(
        answer=req.answer,
        contexts=req.contexts,
        query=req.query,
        prompt_version=req.prompt_version,
        context_embeddings=context_embeddings,
    )

@router.get("/eval/runs")
async def eval_runs(
    run_type: str = Query("", description="rag | faithfulness"),
    limit: int = Query(50, ge=1, le=200),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """列出评估运行记录"""
    from eval_repository import list_evaluation_runs
    return await list_evaluation_runs(run_type=run_type, limit=limit)

@router.get("/eval/runs/{run_id}")
async def eval_run_detail(
    run_id: str,
    user: UserInfo = Depends(RequireRole("admin")),
):
    """评估运行详情"""
    from eval_repository import get_evaluation_run
    run = await get_evaluation_run(run_id)
    if not run:
        raise HTTPException(404, "Evaluation run not found")
    return run

@router.get("/eval/report")
async def eval_report(
    run_type: str = Query("", description="rag | faithfulness"),
    limit: int = Query(200, ge=1, le=1000),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """质量评估聚合报告（指标均值/通过率）"""
    from eval_repository import evaluation_report
    return await evaluation_report(run_type=run_type, limit=limit)
