"""
CVE 漏洞库导入器（聚焦导入）

数据源: NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)

聚焦策略（用户确认）:
  - 近 1 年发布的 CVE + CVSS≥7（HIGH/CRITICAL 各发一次请求）
  - 历史高危缺口由 CISA KEV 全量（kev_importer）+ 手工精选（vuln_seed）补足
  - 支持 lastMod 增量 upsert（调度器每日刷新用）

关键技术约束:
  - 日期跨度 ≤120 天 → 按 110 天窗口切分
  - cvssV3Severity 是单值 → HIGH / CRITICAL 分别请求，按 cve_id 合并去重
  - 分页: resultsPerPage=2000, startIndex 递增直到 ≥ totalResults
  - 无 key 限流约 5 请求/30s → 请求间 sleep nvd_rate_limit_sleep
  - _parse_cve_item 为纯函数（不碰 DB），可离线单测
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from sqlalchemy import delete as sa_delete, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from .knowledge_base import kb_manager
from .chunker import security_chunker
from .kb_types import (
    SOURCE_CVE, SOURCE_KEV, SOURCE_VULN,
    build_content_prefix, cwe_to_threat_types,
)

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 常见误判为 CVE 的特殊状态
_SKIP_STATUS = {"Rejected", "Received", "Awaiting Analysis"}


class CVEImportResult:
    def __init__(self):
        self.total_found = 0
        self.imported = 0          # 新建文档数
        self.updated = 0           # 刷新已有文档数
        self.skipped = 0
        self.errors = 0
        self.error_details: list[str] = []
        self.days = 0
        self.cvss_min = 0.0
        self.incremental_days = 0

    def to_dict(self):
        return {
            "source": "cve",
            "total_found": self.total_found,
            "imported": self.imported,
            "updated": self.updated,
            "skipped": self.skipped,
            "errors": self.errors,
            "error_details": self.error_details[:5],
            "days": self.days,
            "cvss_min": self.cvss_min,
            "incremental_days": self.incremental_days,
        }


def _parse_cve_item(cve_obj: dict) -> dict:
    """
    纯函数：从 NVD API 2.0 的单个 CVE 对象提取结构化字段。

    入参兼容两种形状：
      {"cve": {...}}   —— API 响应 vulnerabilities[] 的元素
      {...}            —— 直接传入 cve 对象

    返回的 dict 供 upsert 使用，不含任何 DB 依赖。
    """
    cve = cve_obj.get("cve", cve_obj) if isinstance(cve_obj, dict) else {}
    cve_id = cve.get("id", "")

    # 描述（优先英文）
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = (d.get("value") or "").strip()
            break
    if not desc:
        for d in cve.get("descriptions", []):
            v = (d.get("value") or "").strip()
            if v:
                desc = v
                break

    # CVSS（优先 v3.1，其次 v3.0，兜底 v2）
    cvss = {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metrics = cve.get("metrics", {}).get(key, [])
        if metrics:
            data = metrics[0].get("cvssData", {}) or {}
            if data.get("baseScore") is not None:
                cvss = {
                    "cvss_score": data.get("baseScore"),
                    "cvss_severity": (data.get("baseSeverity") or "").upper(),
                    "cvss_vector": data.get("vectorString", ""),
                    "cvss_version": "3.1" if key.endswith("31") else "3.0",
                }
                break
    if not cvss:
        for m in cve.get("metrics", {}).get("cvssMetricV2", []):
            data = m.get("cvssData", {}) or {}
            if data.get("baseScore") is not None:
                cvss = {
                    "cvss_score": data.get("baseScore"),
                    "cvss_severity": (m.get("baseSeverity") or "").upper(),
                    "cvss_vector": data.get("vectorString", ""),
                    "cvss_version": "2.0",
                }
                break

    # CWE 编号
    cwe_ids = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and len(v) > 4 and v[4:].isdigit():
                if v not in cwe_ids:
                    cwe_ids.append(v)

    # 受影响产品: CPE 2.3 字符串 → vendor:product（小写）
    products: list[str] = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable"):
                    continue
                criteria = cm.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                    vendor, product = parts[3].lower(), parts[4].lower()
                    if vendor and product and vendor != "*" and product != "*":
                        p = f"{vendor}:{product}"
                        if p not in products:
                            products.append(p)

    # 参考链接
    references = [
        r.get("url", "") for r in cve.get("references", [])
        if r.get("url")
    ]

    return {
        "cve_id": cve_id,
        "description": desc,
        "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""),
        "cvss_score": cvss.get("cvss_score"),
        "cvss_severity": cvss.get("cvss_severity", ""),
        "cvss_vector": cvss.get("cvss_vector", ""),
        "cvss_version": cvss.get("cvss_version", ""),
        "cwe_ids": cwe_ids,
        "products": products,
        "references": references,
        "status": cve.get("vulnStatus", ""),
    }


def _derive_severity(parsed: dict, existing: Optional[dict]) -> str:
    """派生文档严重度：KEV 联动文档最低 high"""
    sev = (parsed.get("cvss_severity") or "").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    existing_sev = (existing or {}).get("severity", "")
    if existing_sev == "critical" or sev == "critical":
        return "critical"
    if sev == "high" or existing_sev == "high":
        return "high"
    if existing and existing.get("metadata", {}).get("exploit_available"):
        return "high"
    return sev


async def _fetch_nvd_pages(client: httpx.AsyncClient, source_url: str, params: dict) -> list[dict]:
    """分页拉取一个 NVD 查询窗口的全部 CVE 对象（处理 429 限流）"""
    items: list[dict] = []
    start_index = 0
    data = {}
    while True:
        p = {**params, "startIndex": start_index, "resultsPerPage": 2000}
        for attempt in range(4):
            try:
                resp = await client.get(source_url, params=p)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "30") or 30)
                    logger.warning(f"NVD rate limited, retry after {retry_after}s")
                    await asyncio.sleep(min(retry_after, 120))
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except (httpx.HTTPError, ValueError) as e:
                if attempt == 3:
                    raise
                logger.warning(f"NVD fetch attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(2 * (attempt + 1))
        batch = data.get("vulnerabilities", [])
        items.extend(batch)
        total = data.get("totalResults", 0)
        start_index += len(batch)
        if not batch or start_index >= total:
            break
    return items


async def _fetch_nvd(
    source_url: str,
    days: int,
    incremental_days: int,
) -> list[dict]:
    """按聚焦/增量策略从 NVD 拉取 CVE 对象列表"""
    # httpx: 无代理直连（避免容器 HTTP_PROXY 拦截本地流量）；需要代理时设 SHARED_MEMORY_NVD_PROXY
    proxy = settings.nvd_proxy or None
    timeout = httpx.Timeout(60.0, connect=15.0)
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    now = datetime.now(timezone.utc)
    items: list[dict] = []

    async with httpx.AsyncClient(timeout=timeout, headers=headers, trust_env=not proxy, proxy=proxy) as client:
        if incremental_days > 0:
            # 增量刷新：最近 incremental_days 天被修改的 CVE（跨度 < 120 天，无需切窗）
            start = now - timedelta(days=incremental_days)
            for sev in ("HIGH", "CRITICAL"):
                params = {
                    "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "cvssV3Severity": sev,
                }
                items.extend(await _fetch_nvd_pages(client, source_url, params))
                if settings.nvd_rate_limit_sleep:
                    await asyncio.sleep(settings.nvd_rate_limit_sleep)
        else:
            # 聚焦：近 days 天按 ≤110 天窗口切分（NVD 单次跨度上限 120 天）
            window_days = 110
            window_start = now - timedelta(days=days)
            while window_start < now:
                window_end = min(window_start + timedelta(days=window_days), now)
                for sev in ("HIGH", "CRITICAL"):
                    params = {
                        "pubStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "pubEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "cvssV3Severity": sev,
                    }
                    items.extend(await _fetch_nvd_pages(client, source_url, params))
                    if settings.nvd_rate_limit_sleep:
                        await asyncio.sleep(settings.nvd_rate_limit_sleep)
                window_start = window_end

    return items


async def _upsert_cve_doc(session: AsyncSession, parsed: dict) -> Optional[tuple[int, bool]]:
    """写入/刷新一条 CVE 文档（含分块）。embedding 占位 [0.0]，留待后台回填。

    Returns: (doc_id, is_new)；既有 source=vulnerability（手工精选）时返回 None（跳过，
    避免 NVD 覆盖人工维护的检测/修复细节）。
    """
    from models import KnowledgeDoc, KnowledgeChunk

    cve_id = parsed["cve_id"]
    existing = await kb_manager.find_doc_by_metadata(
        session, {"cve_id": cve_id}, sources=[SOURCE_CVE, SOURCE_KEV, SOURCE_VULN]
    )
    # 手工精选漏洞文档视为权威条目，NVD 导入不覆盖（source=cve/kev 仍正常 upsert）
    if existing and existing.get("source") == SOURCE_VULN:
        return None

    threat_types = cwe_to_threat_types(parsed["cwe_ids"])
    severity = _derive_severity(parsed, existing)

    meta = {
        "cve_id": cve_id,
        "cvss_score": parsed["cvss_score"],
        "cvss_severity": parsed["cvss_severity"],
        "cvss_vector": parsed["cvss_vector"],
        "published": parsed["published"],
        "modified": parsed["modified"],
        "products": parsed["products"],
        "cwe_ids": parsed["cwe_ids"],
        "references": parsed["references"],
        "status": parsed["status"],
    }
    # 已被 KEV 标记在野利用的 CVE，联动标记不能被 NVD 刷新覆盖
    if existing and existing.get("metadata", {}).get("exploit_available"):
        meta["exploit_available"] = True

    content = build_content_prefix(meta) + parsed["description"]
    if parsed["products"]:
        content += "\n\n## 受影响产品\n" + "\n".join(parsed["products"])
    if parsed["references"]:
        content += "\n\n## 参考链接\n" + "\n".join(parsed["references"][:10])
    content = content[:10000]

    title = f"{cve_id} - {parsed['description'][:80]}"
    tags = [cve_id, "cve"] + [p for p in parsed["products"][:5]]

    if existing:
        doc_id = existing["id"]
        await session.execute(
            sa_delete(KnowledgeChunk).where(KnowledgeChunk.doc_id == doc_id)
        )
        await session.execute(
            sa_update(KnowledgeDoc).where(KnowledgeDoc.id == doc_id).values(
                title=title, content=content,
                threat_types=threat_types, severity=severity, tags=tags,
                metadata_=meta,
            )
        )
        is_new = False
    else:
        doc = KnowledgeDoc(
            title=title, content=content, source=SOURCE_CVE,
            threat_types=threat_types, severity=severity, tags=tags, metadata_=meta,
        )
        session.add(doc)
        await session.flush()
        doc_id = doc.id
        is_new = True

    # 分块（新文档建块；刷新文档先删旧块再建，见上面 sa_delete）
    chunks = security_chunker.chunk_document(
        doc_id=doc_id, title=title, content=content, source=SOURCE_CVE,
        threat_types=threat_types, severity=severity, tags=tags,
    )
    for cd in chunks:
        session.add(KnowledgeChunk(
            doc_id=cd["doc_id"], chunk_id=cd["chunk_id"], content=cd["content"],
            title=title, source=SOURCE_CVE, threat_types=threat_types,
            severity=severity, tags=tags, embedding=None, token_count=cd["token_count"],
        ))

    return doc_id, is_new


async def import_cves(
    session: AsyncSession,
    limit: int = 0,
    days: int = 365,
    cvss_min: float = 7.0,
    source_url: str = "",
    fixture_path: str = "",
    incremental_days: int = 0,
) -> CVEImportResult:
    """
    从 NVD 聚焦导入 CVE（近 days 天 + CVSS≥cvss_min）。

    Args:
        session: 数据库会话
        limit: 最大导入数 (0=全部)
        days: 时间窗口天数（聚焦模式）
        cvss_min: 最低 CVSS 分值
        source_url: NVD API 地址（默认取 config）
        fixture_path: 本地 JSON fixture（离线测试用，格式同 NVD 响应）
        incremental_days: >0 时按 lastModified 增量 upsert（调度器用）

    Returns:
        CVEImportResult
    """
    result = CVEImportResult()
    result.days = days
    result.cvss_min = cvss_min
    result.incremental_days = incremental_days

    source_url = source_url or settings.nvd_url

    if fixture_path:
        with open(fixture_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = [v.get("cve", v) for v in data.get("vulnerabilities", [])]
        result.total_found = len(items)
        logger.info(f"[cve] offline fixture: {len(items)} items from {fixture_path}")
    else:
        try:
            items = await _fetch_nvd(source_url, days, incremental_days)
        except Exception as e:
            result.errors = 1
            result.error_details.append(f"NVD fetch failed: {e}")
            logger.error(f"NVD fetch failed: {e}")
            return result
        result.total_found = len(items)
        logger.info(f"[cve] NVD fetched {len(items)} candidate CVEs")

    # 解析 + 过滤 + 去重（纯函数，离线可测）
    parsed_list: list[dict] = []
    seen: set[str] = set()
    for cve_obj in items:
        try:
            parsed = _parse_cve_item(cve_obj)
        except Exception as e:
            result.errors += 1
            result.error_details.append(f"parse error: {e}")
            continue
        cve_id = parsed["cve_id"]
        if not cve_id or cve_id in seen:
            continue
        if parsed["status"] in _SKIP_STATUS:
            result.skipped += 1
            continue
        score = parsed["cvss_score"]
        if score is None or float(score) < cvss_min:
            result.skipped += 1
            continue
        if not parsed["description"]:
            result.skipped += 1
            continue
        seen.add(cve_id)
        parsed_list.append(parsed)

    if limit > 0:
        parsed_list = parsed_list[:limit]

    # upsert 写入（每 500 条一提交，避免逐条 ORM 开销）
    for i, parsed in enumerate(parsed_list):
        upsert = await _upsert_cve_doc(session, parsed)
        if upsert is None:
            result.skipped += 1
            continue
        _, is_new = upsert
        if is_new:
            result.imported += 1
        else:
            result.updated += 1
        if (i + 1) % 500 == 0:
            await session.commit()

    await session.commit()
    logger.info(
        f"CVE import complete: {result.imported} new, {result.updated} updated, "
        f"{result.skipped} skipped, {result.errors} errors"
    )

    # 异步回填 embedding（后台任务自建 session，独立于请求生命周期）
    if result.imported + result.updated > 0:
        from .seeder import _compute_missing_embeddings
        asyncio.create_task(_compute_missing_embeddings(None))

    return result
