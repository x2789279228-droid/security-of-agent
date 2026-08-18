"""
behavior_analyzer.py — 沙箱报告行为分析

解析 CAPE/Cuckoo 报告，提取:
  - 行为摘要（进程树、文件操作、注册表修改、网络活动）
  - MITRE ATT&CK 技术映射
  - 网络 IOC（C2 地址、下载 URL、DNS 查询）
  - 文件 IOC（释放文件、修改文件）
  - 综合恶意度评分

用法:
    from zeroday_detect.behavior_analyzer import behavior_analyzer
    analysis = behavior_analyzer.analyze(report_dict)
"""
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# CAPE 签名 → MITRE ATT&CK 映射
_SIGNATURE_MITRE = {
    "creates_exe": ("T1105", "Ingress Tool Transfer"),
    "injection_runpe": ("T1055", "Process Injection"),
    "injection_resumethread": ("T1055.003", "Thread Execution Hijacking"),
    "persistence_autorun": ("T1547.001", "Registry Run Keys"),
    "persistence_service": ("T1543.003", "Windows Service"),
    "disables_security": ("T1562.001", "Disable or Modify Tools"),
    "antivm": ("T1497", "Virtualization/Sandbox Evasion"),
    "antisandbox": ("T1497.003", "Time Based Evasion"),
    "network_cnc": ("T1071", "Application Layer Protocol"),
    "ransomware_files": ("T1486", "Data Encrypted for Impact"),
    "credential_dumping": ("T1003", "OS Credential Dumping"),
    "keylogger": ("T1056.001", "Keylogging"),
    "banker": ("T1555", "Credentials from Password Stores"),
    "rat": ("T1219", "Remote Access Software"),
}


@dataclass
class BehaviorAnalysis:
    """行为分析结果"""
    verdict: str = "clean"          # clean | suspicious | malicious
    score: float = 0.0
    behavior_summary: str = ""
    mitre_techniques: list = field(default_factory=list)
    network_iocs: list = field(default_factory=list)
    file_iocs: list = field(default_factory=list)
    process_tree: list = field(default_factory=list)
    signatures: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "behavior_summary": self.behavior_summary,
            "mitre_techniques": self.mitre_techniques,
            "network_iocs": self.network_iocs,
            "file_iocs": self.file_iocs,
            "process_tree": self.process_tree,
            "signatures": self.signatures,
        }


class BehaviorAnalyzer:
    """沙箱报告行为分析器"""

    def analyze(self, report: dict) -> BehaviorAnalysis:
        """分析 CAPE/Cuckoo 报告"""
        result = BehaviorAnalysis()
        score = 0.0
        techniques = []
        sigs = []

        if not report:
            return result

        # 1. 签名分析
        signatures = report.get("signatures", [])
        for sig in signatures:
            sig_name = sig.get("name", "")
            sig_severity = sig.get("severity", 1)
            sigs.append(sig_name)

            # 严重度加权
            score += min(sig_severity * 0.1, 0.4)

            # MITRE 映射
            if sig_name in _SIGNATURE_MITRE:
                tid, tname = _SIGNATURE_MITRE[sig_name]
                techniques.append({"id": tid, "name": tname, "signature": sig_name})

        # 2. 网络 IOC 提取
        network = report.get("network", {})

        for host in network.get("hosts", []):
            ip = host.get("ip", "")
            if ip and not ip.startswith(("10.", "192.168.", "172.")):
                result.network_iocs.append({"type": "ip", "value": ip})
                score += 0.1

        for domain in network.get("domains", []):
            d = domain.get("domain", "")
            if d:
                result.network_iocs.append({"type": "domain", "value": d})

        for http_req in network.get("http", []):
            uri = http_req.get("uri", "")
            if uri:
                result.network_iocs.append({"type": "url", "value": uri})
                score += 0.05

        for dns in network.get("dns", []):
            request = dns.get("request", "")
            if request:
                result.network_iocs.append({"type": "dns", "value": request})

        # 3. 文件 IOC
        behavior = report.get("behavior", {})
        for f in behavior.get("summary", {}).get("files", [])[:20]:
            result.file_iocs.append({"path": f, "action": "accessed"})
        for f in behavior.get("summary", {}).get("files_written", [])[:20]:
            result.file_iocs.append({"path": f, "action": "written"})
            score += 0.02
        for f in behavior.get("summary", {}).get("files_deleted", [])[:10]:
            result.file_iocs.append({"path": f, "action": "deleted"})
            score += 0.03

        # 4. 注册表
        for reg in behavior.get("summary", {}).get("keys", [])[:10]:
            result.file_iocs.append({"path": reg, "action": "registry"})

        # 5. 进程树
        proctree = report.get("behavior", {}).get("processtree", [])
        for proc in proctree[:10]:
            result.process_tree.append({
                "name": proc.get("name", ""),
                "pid": proc.get("pid", 0),
                "command_line": proc.get("command_line", "")[:200],
                "children": len(proc.get("children", [])),
            })

        # 6. malfamily（如果 CAPE 识别了家族）
        malfamily = report.get("malfamily", "")
        if malfamily:
            sigs.append(f"family:{malfamily}")
            score += 0.3

        # 7. 综合评分
        info = report.get("info", {})
        cape_score = info.get("score", 0)
        if isinstance(cape_score, (int, float)):
            score = max(score, cape_score / 10)  # CAPE 0-10 → 0-1

        result.score = min(score, 1.0)
        result.signatures = sigs[:20]
        result.mitre_techniques = techniques[:15]

        # 判定
        if result.score >= 0.7:
            result.verdict = "malicious"
        elif result.score >= 0.3:
            result.verdict = "suspicious"
        else:
            result.verdict = "clean"

        # 行为摘要
        summary_parts = []
        if sigs:
            summary_parts.append(f"触发 {len(sigs)} 条签名")
        if result.network_iocs:
            summary_parts.append(f"{len(result.network_iocs)} 个网络 IOC")
        if result.file_iocs:
            summary_parts.append(f"{len(result.file_iocs)} 个文件操作")
        if techniques:
            summary_parts.append(f"映射 {len(techniques)} 个 ATT&CK 技术")
        if malfamily:
            summary_parts.append(f"家族: {malfamily}")
        result.behavior_summary = "; ".join(summary_parts) or "无显著恶意行为"

        return result


# ── 全局单例 ──
behavior_analyzer = BehaviorAnalyzer()
