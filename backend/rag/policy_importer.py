"""
安全监管政策库导入器

内嵌结构化政策数据（Python 常量），覆盖：
  - 中国：《网络安全法》《数据安全法》《个人信息保护法》《等保2.0 GB/T 22239-2019》
    《关键信息基础设施安全保护条例》《数据出境安全评估办法》
  - 国际：ISO/IEC 27001、GDPR、PCI-DSS、NIST SP 800-53、SOC 2

按 regulation_id 幂等导入（已存在则跳过，除非 force=True）。
数据随代码版本管理，检索走 RAG（source="policy"）。
"""
import asyncio
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .knowledge_base import kb_manager
from .chunker import security_chunker
from .kb_types import SOURCE_POLICY

logger = logging.getLogger(__name__)

# 每条政策一条记录：regulation_id 唯一，作为幂等键
POLICY_LIBRARY: list[dict] = [
    {
        "regulation_id": "cn-csl-2016",
        "name": "中华人民共和国网络安全法",
        "short_name": "网络安全法",
        "jurisdiction": "中国",
        "category": "基础法律",
        "effective_date": "2017-06-01",
        "overview": (
            "我国网络安全领域的基础性法律，确立网络运行安全与网络信息安全两条主线，"
            "明确网络运营者、关键信息基础设施运营者、网络用户的义务，是安全审计与应急处置的最高位阶依据。"
        ),
        "scope": "境内建设、运营、维护和使用网络，以及网络安全的监督管理。",
        "key_requirements": [
            "网络运营者应当履行网络安全保护义务，落实网络安全等级保护制度（第二十一条）",
            "关键信息基础设施在等保基础上实行重点保护，境内存储个人信息和重要数据（第三十一至三十七条）",
            "制定网络安全事件应急预案，及时处置安全风险并按规定报告（第二十五条）",
            "留存网络日志不少于六个月（第二十一条）",
            "开展安全检测评估，每年至少一次（关键信息基础设施）",
        ],
        "penalty": (
            "网络运营者未履行保护义务：警告、责令改正、罚款（单位最高一百万元）；"
            "造成严重后果的责令停业整顿、吊销相关业务许可证；对直接负责人员罚款。"
        ),
        "compliance_points": [
            "安全审计 Agent 检测到未落实等保/日志留存不足时，可援引本法第二十一条、第二十五条",
            "数据泄露等事件按第三十一条、第四十二条要求报告",
        ],
        "related_standards": ["GB/T 22239-2019", "GB/T 28448-2019"],
        "reference_url": "https://www.gov.cn/xinwen/2016-11/07/content_5129771.htm",
    },
    {
        "regulation_id": "cn-dsl-2021",
        "name": "中华人民共和国数据安全法",
        "short_name": "数据安全法",
        "jurisdiction": "中国",
        "category": "基础法律",
        "effective_date": "2021-09-01",
        "overview": (
            "以数据为保护对象的基础性法律，建立数据分类分级、数据安全审查、数据出境管理等制度，"
            "要求数据处理活动依法合规、采取必要措施保障数据安全。"
        ),
        "scope": "在境内开展数据收集、存储、使用、加工、传输、提供、公开等数据处理活动。",
        "key_requirements": [
            "建立数据分类分级制度，对重要数据实行重点保护（第二十一条）",
            "开展数据安全风险评估，发现风险及时处置并报告（第二十七条、第二十九条）",
            "重要数据出境实行安全评估（第三十一条）",
            "建立全流程数据安全管理制度，明确责任人和管理措施（第二十七条）",
        ],
        "penalty": (
            "不履行数据安全保护义务：警告、责令改正、罚款；情节严重的最高罚款一千万元，"
            "并可责令暂停业务、停业整顿、吊销许可证。"
        ),
        "compliance_points": [
            "审计 Agent 识别到敏感数据（凭据/个人信息）异常访问，可援引本法第二十七条、第二十九条",
            "检测到疑似数据外传（DATA_EXFIL）时，评估报告义务与处置流程",
        ],
        "related_standards": ["GB/T 22239-2019", "GB/T 35273-2020"],
        "reference_url": "https://www.gov.cn/xinwen/2021-06/11/content_5616919.htm",
    },
    {
        "regulation_id": "cn-pipl-2021",
        "name": "中华人民共和国个人信息保护法",
        "short_name": "个人信息保护法",
        "jurisdiction": "中国",
        "category": "基础法律",
        "effective_date": "2021-11-01",
        "overview": (
            "规范个人信息处理活动、保护个人信息权益的法律，确立告知-同意、最小必要、"
            "目的限制等核心原则，对敏感个人信息处理提出更高要求。"
        ),
        "scope": "在境内处理自然人个人信息的活动；境外处理境内个人信息的特定情形亦适用。",
        "key_requirements": [
            "处理个人信息需取得个人同意，且遵循告知-同意、最小必要原则（第十三条至十六条）",
            "敏感个人信息需单独同意并告知必要性、对个人的影响（第二十九、三十条）",
            "个人信息处理者采取加密、去标识化等安全技术措施（第五十一条）",
            "发生或可能发生个人信息泄露时，立即补救并通知监管与个人（第五十七条）",
        ],
        "penalty": (
            "情节严重的最高罚款五千万元或上一年度营业额百分之五，并可责令暂停业务、吊销许可证；"
            "直接责任人员禁业。"
        ),
        "compliance_points": [
            "审计 Agent 检测到个人信息明文泄露/越权访问，援引第五十一条、第五十七条（通知义务）",
            "处置建议需平衡安全调查与个人信息保护：最小必要收集、保留期限限制",
        ],
        "related_standards": ["GB/T 35273-2020", "GB/T 41391-2022"],
        "reference_url": "https://www.gov.cn/xinwen/2021-08/20/content_5632486.htm",
    },
    {
        "regulation_id": "cn-gb22239-2019",
        "name": "网络安全等级保护基本要求 GB/T 22239-2019（等保2.0）",
        "short_name": "等保2.0",
        "jurisdiction": "中国",
        "category": "国家标准",
        "effective_date": "2019-12-01",
        "overview": (
            "等级保护制度的核心测评标准，按定级对象的安全保护等级（一至五级）规定安全通用要求"
            "及云计算、移动互联、物联网、工业控制、大数据等扩展要求，是安全建设与测评的直接依据。"
        ),
        "scope": "已定级的等级保护对象，含信息系统、云计算平台、大数据平台等。",
        "key_requirements": [
            "安全物理环境、安全通信网络、安全区域边界、安全计算环境、安全管理中心五大层面要求",
            "第二级起要求入侵防范、安全审计、恶意代码防范；第三级要求审计记录覆盖全过程并留存六个月以上",
            "安全管理中心要求集中管控、审计记录保护（第三级）",
            "定期开展等级测评：三级及以上每年一次",
        ],
        "penalty": (
            "依据网络安全法：未落实等保义务的按第二十一条、第五十九条处罚。"
        ),
        "compliance_points": [
            "审计 Agent 输出可对照等保2.0 安全计算环境/安全审计控制项给出差距项",
            "审计记录留存要求（≥6个月）与平台 response_logs / llm_traces 设计吻合",
        ],
        "related_standards": ["GB/T 22240-2020", "GB/T 25070-2019", "GB/T 28448-2019"],
        "reference_url": "https://std.samr.gov.cn/gb/search/gbDetailed?id=71F772D7F5D3D7A7E05397BE0A0AB82A",
    },
    {
        "regulation_id": "cn-citi-reg-2021",
        "name": "关键信息基础设施安全保护条例",
        "short_name": "关基保护条例",
        "jurisdiction": "中国",
        "category": "行政法规",
        "effective_date": "2021-09-01",
        "overview": (
            "细化网络安全法关于关键信息基础设施（CII）的安全保护要求，规定运营者的专门安全管理机构、"
            "安全检测评估频率、应急处置与报告义务。"
        ),
        "scope": "公共通信和信息服务、能源、交通、水利、金融、公共服务、电子政务、国防科技工业等重要行业领域的 CII。",
        "key_requirements": [
            "设置专门安全管理机构和安全管理负责人，对关键岗位人员进行安全背景审查",
            "每年至少进行一次安全检测评估（可委托第三方机构）",
            "存储境内收集的重要数据和个人信息，境内存储、出境评估",
            "制定网络安全事件应急预案，定期开展应急演练",
        ],
        "penalty": "未履行保护义务的责令改正、警告、罚款；情节严重对主管人员、直接责任人员依法处分。",
        "compliance_points": [
            "对关基行业的审计发现应关联该条例的专门机构、定期测评、应急演练要求",
        ],
        "related_standards": ["GB/T 22239-2019", "GB/T 25070-2019"],
        "reference_url": "https://www.gov.cn/zhengce/content/2021-08/17/content_5631668.htm",
    },
    {
        "regulation_id": "cn-data-exit-2022",
        "name": "数据出境安全评估办法",
        "short_name": "数据出境评估办法",
        "jurisdiction": "中国",
        "category": "部门规章",
        "effective_date": "2022-09-01",
        "overview": (
            "规定数据出境安全评估的适用情形、申报流程与评估内容，是数据处理者向境外提供重要数据"
            "和个人信息的合规门槛。"
        ),
        "scope": "向境外提供重要数据、关键信息基础设施运营者向境外提供个人信息、处理100万人以上个人信息的个人信息处理者向境外提供个人信息等情形。",
        "key_requirements": [
            "属于应评估情形的，须事前向网信部门申报数据出境安全评估",
            "订立数据出境相关合同，明确数据安全责任",
            "评估通过后方可出境，评估结果有效期两年",
        ],
        "penalty": "未按规定出境评估的按数据安全法、个人信息保护法处罚。",
        "compliance_points": [
            "审计 Agent 检测到数据外传至境外 IP/域（DATA_EXFIL），提示核验是否履行出境评估",
        ],
        "related_standards": ["GB/T 35273-2020", "个人信息出境标准合同办法"],
        "reference_url": "https://www.cac.gov.cn/2022-07/07/c_1658811536398873.htm",
    },
    {
        "regulation_id": "iso-27001-2022",
        "name": "ISO/IEC 27001:2022 信息安全管理体系",
        "short_name": "ISO 27001",
        "jurisdiction": "国际",
        "category": "国际标准",
        "effective_date": "2022-10-25",
        "overview": (
            "国际通行的信息安全管理体系（ISMS）认证标准，采用 PDCA 持续改进模型，"
            "通过 93 项 Annex A 控制措施管理信息安全风险。"
        ),
        "scope": "适用于所有行业的信息安全管理体系建设与认证。",
        "key_requirements": [
            "建立 ISMS 范围、信息安全方针与风险评估程序（Clause 4-6）",
            "A.8 资产/访问控制、A.5 组织控制、A.12 运维安全等控制措施",
            "信息安全事件管理流程：分类、报告、响应、教训总结（A.5.24-A.5.28）",
            "定期内部审核与管理评审，持续改进（Clause 9-10）",
        ],
        "penalty": "非法规性标准，不设处罚；不满足则无法通过认证/监督审核。",
        "compliance_points": [
            "安全审计 Agent 可作为 A.8.9 脆弱性管理、A.5.25 事件评估的落地工具",
            "审计记录留存与证据链符合 A.5.26 响应/证据要求",
        ],
        "related_standards": ["ISO/IEC 27002:2022", "ISO/IEC 27005:2022"],
        "reference_url": "https://www.iso.org/standard/27001",
    },
    {
        "regulation_id": "eu-gdpr-2016",
        "name": "欧盟通用数据保护条例 (GDPR)",
        "short_name": "GDPR",
        "jurisdiction": "欧盟",
        "category": "法律",
        "effective_date": "2018-05-25",
        "overview": (
            "欧盟个人数据保护的核心法律，确立数据控制者/处理者义务、数据主体权利，"
            "对个人数据泄露事件设置 72 小时报告义务，跨境数据传输有严格限制。"
        ),
        "scope": "在欧盟境内处理个人数据的活动，及向欧盟境内主体提供商品/服务或监测其行为的境外处理者。",
        "key_requirements": [
            "数据最小化、目的限制、存储限制（Art.5）",
            "个人数据泄露事件 72 小时内向监管机构报告，高风险情形通知数据主体（Art.33/34）",
            "设计与默认的数据保护（Privacy by Design, Art.25）",
            "高风险处理活动需开展数据保护影响评估（DPIA, Art.35）",
            "向境外（非充分性认定地区）转移数据需标准合同条款等保障措施（Art.44-49）",
        ],
        "penalty": "行政罚款最高 2000 万欧元或全球年营业额的 4%（取较高者）。",
        "compliance_points": [
            "安全审计 Agent 检测到个人数据泄露事件时，输出需包含 GDPR Art.33 的 72 小时报告时限提示",
            "审计日志中的个人数据处置需符合数据最小化（Art.5(1)(c)）",
        ],
        "related_standards": ["EDPB Guidelines", "ISO/IEC 27701"],
        "reference_url": "https://gdpr-info.eu/",
    },
    {
        "regulation_id": "pci-dss-4.0",
        "name": "支付卡行业数据安全标准 (PCI DSS 4.0)",
        "short_name": "PCI DSS",
        "jurisdiction": "国际",
        "category": "行业标准",
        "effective_date": "2022-03-31",
        "overview": (
            "持卡人数据环境（CDE）的安全标准，由 PCI SSC 制定。4.0 版引入定制化方法、"
            "多因素认证扩展、安全编码要求，通过 12 项要求管理持卡人数据安全。"
        ),
        "scope": "所有存储、处理、传输持卡人数据（CHD）或敏感认证数据（SAD）的实体及服务提供商。",
        "key_requirements": [
            "构建并维护安全的网络与系统：防火墙配置、不使用厂商默认口令（Req.1-2）",
            "保护账户数据：加密传输、存储不可读（Req.3-4）",
            "维护漏洞管理计划：防病毒、补丁与系统更新、安全编码（Req.5-6）",
            "实施强访问控制：最小权限、账号认证（Req.7-8）",
            "定期监控与测试：日志与监控所有 CDE 访问、漏洞扫描与渗透测试（Req.10-11）",
            "维护信息安全方针（Req.12）",
        ],
        "penalty": "违反 Visa/Mastercard 规则可能被罚款（每事件最高数十万美元）或取消受理资格；非政府处罚。",
        "compliance_points": [
            "审计 Agent 检测 CDE 内异常访问时，对应 PCI DSS Req.10 的日志与监控要求",
            "凭证泄露处置建议对齐 Req.8（MFA、最小权限）与 Req.3（加密存储）",
        ],
        "related_standards": ["PCI DSS 4.0 Self-Assessment", "PCI SSC Information Supplement"],
        "reference_url": "https://www.pcisecuritystandards.org/standards/pci-dss/",
    },
    {
        "regulation_id": "nist-sp800-53-r5",
        "name": "NIST SP 800-53 Rev.5 安全与隐私控制",
        "short_name": "NIST 800-53",
        "jurisdiction": "美国",
        "category": "标准/指南",
        "effective_date": "2020-09-23",
        "overview": (
            "美国联邦信息系统与组织的安全与隐私控制目录，20 个控制族（AC访问控制、AU审计与问责、"
            "IR事件响应、SI系统与信息完整性等）约千项控制，是 FedRAMP、CMMC 的基础。"
        ),
        "scope": "美国联邦机构及其信息系统（FISMA 适用）；广泛被私有云与合规体系借鉴。",
        "key_requirements": [
            "AU-2/3 事件日志记录与内容、AU-6 审计记录评审分析与报告",
            "IR-4 事件处理、IR-6 事件报告、IR-8 事件响应计划",
            "AC-2 账户管理、AC-3 访问强制、AC-6 最小特权",
            "SI-2 漏洞与缺陷修复、SI-4 系统监控、SI-5 安全警报",
        ],
        "penalty": "美国联邦：FISMA 合规性审查；非联邦实体无直接罚款但为 FedRAMP/CMMC 门槛。",
        "compliance_points": [
            "审计 Agent 的告警/响应能力可直接映射 IR-4/IR-6（事件处理与报告）",
            "日志留存映射 AU-6（评审分析与报告），弥补 SI-4 监控盲区",
        ],
        "related_standards": ["NIST SP 800-53B", "FedRAMP", "CMMC"],
        "reference_url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    {
        "regulation_id": "aicpa-soc2",
        "name": "SOC 2 信任服务准则",
        "short_name": "SOC 2",
        "jurisdiction": "美国",
        "category": "鉴证准则",
        "effective_date": "2017-05-01",
        "overview": (
            "AICPA 发布的服务组织控制报告准则，基于五项信任服务标准（安全性、可用性、处理完整性、"
            "保密性、隐私），第三方审计师出具 SOC 2 Type I/II 报告。"
        ),
        "scope": "SaaS 及云服务提供商向客户提供的信任服务控制（TSC）范围。",
        "key_requirements": [
            "CC6 逻辑与物理访问控制、CC7 系统操作与监控（入侵检测、安全事件响应）",
            "CC8 变更管理、CC9 风险缓解",
            "Type II 要求在一段时期（通常 6-12 个月）内控制措施持续有效运行的证据",
            "A1 可用性：容量、灾备、监控告警",
        ],
        "penalty": "非法规性鉴证；无法取得审计师无保留意见将影响客户信任与采购准入。",
        "compliance_points": [
            "安全审计 Agent 的监控与响应能力支撑 CC7.3/CC7.4（入侵检测与安全事件响应）",
            "告警处置闭环（工单/复盘）作为 Type II 运行有效性的证据来源",
        ],
        "related_standards": ["TSC 2017", "ISO/IEC 27001"],
        "reference_url": "https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2program",
    },
]


class PolicyImportResult:
    def __init__(self):
        self.total_found = len(POLICY_LIBRARY)
        self.imported = 0
        self.updated = 0
        self.skipped = 0
        self.errors = 0
        self.error_details: list[str] = []

    def to_dict(self):
        return {
            "source": "policy",
            "total_found": self.total_found,
            "imported": self.imported,
            "updated": self.updated,
            "skipped": self.skipped,
            "errors": self.errors,
            "error_details": self.error_details[:5],
        }


def _build_policy_content(p: dict) -> str:
    """纯函数：政策记录 → 文档正文"""
    parts = []
    parts.append("## 概述\n" + p["overview"])
    if p.get("scope"):
        parts.append("## 适用范围\n" + p["scope"])
    if p.get("key_requirements"):
        parts.append("## 核心要求\n" + "\n".join(f"- {r}" for r in p["key_requirements"]))
    if p.get("penalty"):
        parts.append("## 违规处罚\n" + p["penalty"])
    if p.get("compliance_points"):
        parts.append("## 合规落地要点\n" + "\n".join(f"- {c}" for c in p["compliance_points"]))
    return "\n\n".join(parts)


async def import_policy(
    session: AsyncSession,
    policy_data: Optional[list[dict]] = None,
    force: bool = False,
) -> PolicyImportResult:
    """
    导入安全监管政策库（内嵌数据，按 regulation_id 幂等）。

    Args:
        session: 数据库会话
        policy_data: 政策列表（默认 POLICY_LIBRARY，测试可注入）
        force: True 时覆盖已有同名政策文档（重建正文）

    Returns:
        PolicyImportResult
    """
    result = PolicyImportResult()
    library = policy_data if policy_data is not None else POLICY_LIBRARY
    result.total_found = len(library)

    from models import KnowledgeDoc, KnowledgeChunk
    from sqlalchemy import delete as sa_delete

    for p in library:
        reg_id = p.get("regulation_id", "")
        if not reg_id:
            result.skipped += 1
            continue

        try:
            existing = await kb_manager.find_doc_by_metadata(
                session, {"regulation_id": reg_id}, sources=[SOURCE_POLICY]
            )
            if existing and not force:
                result.skipped += 1
                continue

            title = f"{p.get('name', reg_id)}"
            content = _build_policy_content(p)
            tags = [reg_id, p.get("short_name", ""), p.get("jurisdiction", "")]
            meta = {
                "regulation_id": reg_id,
                "regulation_name": p.get("name", ""),
                "jurisdiction": p.get("jurisdiction", ""),
                "category": p.get("category", ""),
                "effective_date": p.get("effective_date", ""),
                "related_standards": p.get("related_standards", []),
                "reference_url": p.get("reference_url", ""),
            }
            threat_types = ["ANY"]

            if existing:
                doc_id = existing["id"]
                await session.execute(
                    sa_delete(KnowledgeChunk).where(KnowledgeChunk.doc_id == doc_id)
                )
                await session.execute(
                    KnowledgeDoc.__table__.update().where(KnowledgeDoc.id == doc_id).values(
                        title=title, content=content[:10000],
                        threat_types=threat_types, severity="medium",
                        tags=tags, metadata_=meta,
                    )
                )
                result.updated += 1
            else:
                doc = KnowledgeDoc(
                    title=title, content=content[:10000], source=SOURCE_POLICY,
                    threat_types=threat_types, severity="medium",
                    tags=tags, metadata_=meta,
                )
                session.add(doc)
                await session.flush()
                doc_id = doc.id
                result.imported += 1

            chunks = security_chunker.chunk_document(
                doc_id=doc_id, title=title, content=content[:10000], source=SOURCE_POLICY,
                threat_types=threat_types, severity="medium", tags=tags,
            )
            for cd in chunks:
                session.add(KnowledgeChunk(
                    doc_id=cd["doc_id"], chunk_id=cd["chunk_id"], content=cd["content"],
                    title=title, source=SOURCE_POLICY, threat_types=threat_types,
                    severity="medium", tags=tags, embedding=None, token_count=cd["token_count"],
                ))
        except Exception as e:
            result.errors += 1
            result.error_details.append(f"import {reg_id}: {e}")
            logger.warning(f"Policy import failed for {reg_id}: {e}")

    await session.commit()
    logger.info(
        f"Policy import complete: {result.imported} new, {result.updated} updated, "
        f"{result.skipped} skipped, {result.errors} errors"
    )

    if result.imported + result.updated > 0:
        from .seeder import _compute_missing_embeddings
        asyncio.create_task(_compute_missing_embeddings(None))

    return result
