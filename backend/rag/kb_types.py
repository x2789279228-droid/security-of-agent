"""
知识库类型（KB Taxonomy）— 常量 + 中文标签 + 元数据过滤辅助

沿用 KnowledgeDoc.source 字段作为知识库类型标识，结构化字段存 metadata_ JSONB。
前端展示与后端过滤共用此处定义，避免字符串散落。
"""
import logging

logger = logging.getLogger(__name__)

# ═══ 知识库类型（source 取值） ═══

SOURCE_MITRE = "mitre-attack"        # MITRE ATT&CK 攻击技术库
SOURCE_CAPEC = "capec"               # CAPEC 攻击模式库
SOURCE_CVE = "cve"                   # CVE 漏洞库（NVD 聚焦导入）
SOURCE_KEV = "kev"                   # 0day/已知被利用漏洞库（CISA KEV）
SOURCE_VULN = "vulnerability"        # 漏洞知识库（手工精选高危漏洞）
SOURCE_POLICY = "policy"             # 安全监管政策库
SOURCE_PLAYBOOK = "playbook"         # 应急响应 Playbook
SOURCE_INTERNAL = "internal"         # 内部知识/预置知识

# 知识库类型 → 中文标签（前端分布卡片 / 下拉框用）
KB_LABELS: dict[str, str] = {
    SOURCE_MITRE: "MITRE ATT&CK",
    SOURCE_CAPEC: "CAPEC 攻击模式",
    SOURCE_CVE: "CVE 漏洞库",
    SOURCE_KEV: "0day/已知被利用",
    SOURCE_VULN: "漏洞知识库",
    SOURCE_POLICY: "监管政策库",
    SOURCE_PLAYBOOK: "应急 Playbook",
    SOURCE_INTERNAL: "内部知识",
}

# 所有知识库类型（用于遍历/统计）
ALL_KB_SOURCES = list(KB_LABELS.keys())

# 大批量源：文档管理列表默认排除，避免被淹没
BULK_SOURCES = {SOURCE_CVE, SOURCE_KEV}

# ═══ CWE → 威胁类型映射（CVE 导入时用于 threat_types 关联） ═══

CWE_THREAT_MAP: dict[str, list[str]] = {
    "CWE-79": ["WEB_ATTACK"],                # XSS
    "CWE-89": ["WEB_ATTACK"],                # SQL 注入
    "CWE-20": ["WEB_ATTACK"],                # 输入验证不当
    "CWE-22": ["WEB_ATTACK"],                # 路径遍历
    "CWE-502": ["MALWARE_DETECT", "WEB_ATTACK"],  # 反序列化
    "CWE-78": ["MALWARE_DETECT", "WEB_ATTACK"],   # OS 命令注入
    "CWE-77": ["MALWARE_DETECT", "WEB_ATTACK"],   # 命令注入
    "CWE-94": ["MALWARE_DETECT", "WEB_ATTACK"],   # 代码注入
    "CWE-95": ["MALWARE_DETECT", "WEB_ATTACK"],
    "CWE-287": ["CREDENTIAL_ACCESS", "BRUTE_FORCE"],  # 认证绕过
    "CWE-288": ["CREDENTIAL_ACCESS"],
    "CWE-306": ["CREDENTIAL_ACCESS"],        # 缺失认证
    "CWE-307": ["BRUTE_FORCE"],              # 暴力破解防护缺失
    "CWE-798": ["CREDENTIAL_ACCESS"],        # 硬编码凭据
    "CWE-611": ["DATA_EXFIL"],               # XXE
    "CWE-918": ["WEB_ATTACK", "DATA_EXFIL"], # SSRF
    "CWE-200": ["DATA_EXFIL", "DISCOVERY"],  # 信息泄露
    "CWE-787": ["MALWARE_DETECT"],           # 越界写
    "CWE-125": ["MALWARE_DETECT"],           # 越界读
    "CWE-119": ["MALWARE_DETECT"],           # 内存破坏
    "CWE-120": ["MALWARE_DETECT"],
    "CWE-416": ["MALWARE_DETECT"],           # use-after-free
    "CWE-269": ["PRIVILEGE_ESCALATION"],     # 权限管理不当
    "CWE-276": ["PRIVILEGE_ESCALATION"],
    "CWE-732": ["PRIVILEGE_ESCALATION"],     # 权限控制不当
    "CWE-862": ["PRIVILEGE_ESCALATION"],     # 缺失授权
    "CWE-863": ["PRIVILEGE_ESCALATION"],
    "CWE-400": ["DDoS_TRAFFIC"],             # 资源耗尽
    "CWE-770": ["DDoS_TRAFFIC"],
    "CWE-404": ["DDoS_TRAFFIC"],
    "CWE-352": ["WEB_ATTACK"],               # CSRF
    "CWE-434": ["MALWARE_DETECT", "WEB_ATTACK"],  # 危险文件上传
    "CWE-1321": ["SUPPLY_CHAIN", "WEB_ATTACK"],   # 原型污染
}

# CWE 未命中时的兜底威胁类型
CWE_FALLBACK_THREAT = ["ANY", "VULNERABILITY"]


def cwe_to_threat_types(cwe_ids: list[str]) -> list[str]:
    """将 CWE 编号列表映射为系统威胁类型列表（去重保序）"""
    result: list[str] = []
    for cwe in cwe_ids:
        for t in CWE_THREAT_MAP.get(cwe, []):
            if t not in result:
                result.append(t)
    if not result:
        result = list(CWE_FALLBACK_THREAT)
    return result


# ═══ 导入内容前缀辅助（结构化字段 → chunk content 前缀） ═══

def build_content_prefix(meta: dict) -> str:
    """
    把 CVE/KEV/漏洞知识的结构化元数据编译成 content 前缀。

    前缀随 content 一起 embed（提升向量质量），检索上下文天然携带
    CVE-ID/CVSS/产品/发布时间/利用状态，供 LLM 精确引用，减少幻觉。
    返回空字符串表示无结构化字段。
    """
    parts: list[str] = []
    cve_id = meta.get("cve_id") or meta.get("cveId") or meta.get("CVEID")
    if cve_id:
        parts.append(f"CVE-ID: {cve_id}")

    cvss = meta.get("cvss_score")
    if cvss is not None:
        sev = meta.get("cvss_severity", "")
        parts.append(f"CVSS: {cvss}" + (f" ({sev})" if sev else ""))

    products = meta.get("products") or meta.get("affected_products") or []
    if products:
        shown = ", ".join(str(p) for p in products[:5])
        parts.append(f"受影响产品: {shown}")

    published = meta.get("published") or meta.get("date_added") or ""
    if published:
        parts.append(f"发布时间: {str(published)[:10]}")

    if meta.get("exploit_available") or meta.get("known_exploited"):
        parts.append("利用状态: 已在野外利用(KEV)")

    patch = meta.get("fix_version")
    if patch:
        parts.append(f"修复版本: {patch}")

    if not parts:
        return ""
    return "[" + " | ".join(parts) + "]\n"
