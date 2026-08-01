"""附件钓鱼检测器 — 6 维度深度分析

维度:
  1. 扩展名伪装 (extension)
  2. Magic bytes 不匹配 (magic)
  3. 宏/脚本风险 (macro)
  4. 加密规避 (encryption)
  5. 文件大小异常 (size)
  6. 嵌入 URL (embedded_url)
"""
import re
import logging

from .models import AttachmentPhishingRequest, PhishingIndicator

logger = logging.getLogger(__name__)

# 高危可执行扩展名
EXECUTABLE_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp",
    ".hta", ".cpl", ".jar", ".reg", ".dll", ".ocx", ".ade", ".adp",
}

# 宏/脚本扩展名
MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm"}

# 常见文档扩展名（用于双扩展名检测）
DOCUMENT_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".rtf", ".odt", ".ods", ".jpg", ".png", ".gif",
}

# 压缩包扩展名
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso"}

# Magic bytes 签名 → 真实类型
MAGIC_SIGNATURES: dict[str, str] = {
    "4d5a": "PE_EXE",           # MZ → Windows 可执行文件
    "7f454c46": "ELF",          # ELF → Linux 可执行文件
    "cafebabe": "JAVA_CLASS",   # Java class
    "504b0304": "ZIP",          # ZIP/DOCX/XLSX/PPTX/JAR
    "25504446": "PDF",          # %PDF
    "d0cf11e0": "OLE2",         # OLE2 (旧版 Office / 宏载体)
    "52617221": "RAR",          # RAR
    "377abcaf": "7Z",           # 7z
    "1f8b": "GZIP",             # gzip
}

# 扩展名 → 期望的 magic 类型
EXT_EXPECTED_MAGIC: dict[str, set[str]] = {
    ".pdf": {"PDF"},
    ".doc": {"OLE2"},
    ".docx": {"ZIP"},
    ".xls": {"OLE2"},
    ".xlsx": {"ZIP"},
    ".ppt": {"OLE2"},
    ".pptx": {"ZIP"},
    ".jpg": {"JPEG"},
    ".png": {"PNG"},
    ".gif": {"GIF"},
    ".zip": {"ZIP"},
    ".rar": {"RAR"},
    ".7z": {"7Z"},
}


def _get_ext(filename: str) -> str:
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return ""


def _get_all_exts(filename: str) -> list[str]:
    parts = filename.lower().split(".")
    if len(parts) <= 1:
        return []
    return ["." + p for p in parts[1:]]


def _match_magic(magic_hex: str) -> str:
    magic_hex = magic_hex.lower().strip()
    for sig, ftype in MAGIC_SIGNATURES.items():
        if magic_hex.startswith(sig):
            return ftype
    return ""


def _check_extension(req: AttachmentPhishingRequest) -> list[PhishingIndicator]:
    """维度 1: 扩展名伪装"""
    indicators: list[PhishingIndicator] = []
    filename = req.filename.strip()
    ext = _get_ext(filename)
    all_exts = _get_all_exts(filename)

    # 双扩展名：.pdf.exe / .docx.vbs
    if len(all_exts) >= 2:
        inner = all_exts[-2]
        outer = all_exts[-1]
        if inner in DOCUMENT_EXTS and outer in EXECUTABLE_EXTS:
            indicators.append(PhishingIndicator(
                name="双扩展名伪装",
                category="extension",
                severity="critical",
                detail=f"文件名 \"{filename}\" 使用双扩展名 {inner}{outer}，伪装为文档实为可执行文件",
            ))
        elif inner in DOCUMENT_EXTS and outer in MACRO_EXTS:
            indicators.append(PhishingIndicator(
                name="双扩展名宏文件",
                category="extension",
                severity="high",
                detail=f"文件名 \"{filename}\" 使用双扩展名 {inner}{outer}",
            ))

    # 单一可执行扩展名
    if ext in EXECUTABLE_EXTS and len(all_exts) == 1:
        indicators.append(PhishingIndicator(
            name="可执行文件附件",
            category="extension",
            severity="high",
            detail=f"附件 \"{filename}\" 为可执行文件类型 ({ext})",
        ))

    # 宏文件扩展名
    if ext in MACRO_EXTS:
        indicators.append(PhishingIndicator(
            name="宏文件附件",
            category="extension",
            severity="high",
            detail=f"附件 \"{filename}\" 支持 VBA 宏执行 ({ext})",
        ))

    return indicators


def _check_magic(req: AttachmentPhishingRequest) -> list[PhishingIndicator]:
    """维度 2: Magic bytes 不匹配"""
    indicators: list[PhishingIndicator] = []
    if not req.magic_bytes:
        return indicators

    ext = _get_ext(req.filename)
    actual_type = _match_magic(req.magic_bytes)
    if not actual_type:
        return indicators

    expected = EXT_EXPECTED_MAGIC.get(ext)
    if expected and actual_type not in expected:
        # 文档扩展名但实际是 PE
        if actual_type in ("PE_EXE", "ELF"):
            indicators.append(PhishingIndicator(
                name="文件头与扩展名严重不匹配",
                category="magic",
                severity="critical",
                detail=f"扩展名 {ext} 期望 {expected}，但文件头为 {actual_type}（可执行文件）",
            ))
        else:
            indicators.append(PhishingIndicator(
                name="文件头与扩展名不匹配",
                category="magic",
                severity="high",
                detail=f"扩展名 {ext} 期望 {expected}，实际文件头为 {actual_type}",
            ))

    # OLE2 容器 + 非旧版 Office 扩展名 → 可能藏宏
    if actual_type == "OLE2" and ext not in (".doc", ".xls", ".ppt", ".msg"):
        indicators.append(PhishingIndicator(
            name="OLE2 容器异常扩展名",
            category="magic",
            severity="medium",
            detail=f"文件为 OLE2 容器但扩展名为 {ext}，可能隐藏宏/脚本",
        ))

    return indicators


def _check_macros(req: AttachmentPhishingRequest) -> list[PhishingIndicator]:
    """维度 3: 宏/脚本风险"""
    indicators: list[PhishingIndicator] = []

    if req.has_macros:
        ext = _get_ext(req.filename)
        if ext in MACRO_EXTS:
            indicators.append(PhishingIndicator(
                name="宏文件含宏",
                category="macro",
                severity="high",
                detail=f"文件 \"{req.filename}\" 含 VBA 宏，可能执行恶意代码",
            ))
        else:
            indicators.append(PhishingIndicator(
                name="非宏文件含宏",
                category="macro",
                severity="critical",
                detail=f"文件 \"{req.filename}\" 扩展名为 {ext} 但含宏/脚本，高度可疑",
            ))

    return indicators


def _check_encryption(req: AttachmentPhishingRequest) -> list[PhishingIndicator]:
    """维度 4: 加密规避"""
    indicators: list[PhishingIndicator] = []

    if req.is_encrypted:
        ext = _get_ext(req.filename)
        if ext in ARCHIVE_EXTS:
            indicators.append(PhishingIndicator(
                name="加密压缩包",
                category="encryption",
                severity="high",
                detail=f"加密压缩包 \"{req.filename}\" 可绕过杀毒扫描，常见于钓鱼附件",
            ))
        else:
            indicators.append(PhishingIndicator(
                name="加密文件",
                category="encryption",
                severity="medium",
                detail=f"文件 \"{req.filename}\" 已加密，无法进行内容安全检查",
            ))

    return indicators


def _check_size(req: AttachmentPhishingRequest) -> list[PhishingIndicator]:
    """维度 5: 文件大小异常"""
    indicators: list[PhishingIndicator] = []
    if req.file_size <= 0:
        return indicators

    ext = _get_ext(req.filename)

    # 极小的文档文件（< 1KB 的 .docx/.xlsx 几乎不可能）
    if ext in (".docx", ".xlsx", ".pptx") and req.file_size < 1024:
        indicators.append(PhishingIndicator(
            name="文档文件异常过小",
            category="size",
            severity="medium",
            detail=f"文件 \"{req.filename}\" 仅 {req.file_size} 字节，正常 Office 文档至少数 KB",
        ))

    # 极大的可执行文件（> 500MB 可能是填充规避沙箱）
    if ext in EXECUTABLE_EXTS and req.file_size > 500 * 1024 * 1024:
        indicators.append(PhishingIndicator(
            name="可执行文件异常过大",
            category="size",
            severity="medium",
            detail=f"文件 \"{req.filename}\" 达 {req.file_size // (1024*1024)}MB，可能用填充数据规避沙箱",
        ))

    return indicators


def _check_embedded_urls(req: AttachmentPhishingRequest) -> list[PhishingIndicator]:
    """维度 6: 嵌入 URL"""
    indicators: list[PhishingIndicator] = []

    suspicious_tlds = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw")
    for url in req.embedded_urls[:10]:
        url_lower = url.lower()
        # IP 直连
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            indicators.append(PhishingIndicator(
                name="文件内嵌 IP 链接",
                category="embedded_url",
                severity="high",
                detail=f"文件内嵌 IP 直连链接: {url[:80]}",
            ))
        # 可疑 TLD
        for tld in suspicious_tlds:
            if tld in url_lower:
                indicators.append(PhishingIndicator(
                    name="文件内嵌高风险链接",
                    category="embedded_url",
                    severity="medium",
                    detail=f"文件内嵌链接使用高风险 TLD {tld}: {url[:80]}",
                ))
                break

    return indicators


def detect(req: AttachmentPhishingRequest) -> list[PhishingIndicator]:
    """执行附件钓鱼全维度检测。"""
    indicators: list[PhishingIndicator] = []
    indicators.extend(_check_extension(req))
    indicators.extend(_check_magic(req))
    indicators.extend(_check_macros(req))
    indicators.extend(_check_encryption(req))
    indicators.extend(_check_size(req))
    indicators.extend(_check_embedded_urls(req))
    return indicators
