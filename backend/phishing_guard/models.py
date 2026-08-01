"""钓鱼检测模块 — 数据模型定义

请求/响应模型:
  - EmailPhishingRequest:   邮件钓鱼检测输入
  - WebPhishingRequest:     网页钓鱼检测输入
  - DomainPhishingRequest:  域名访问钓鱼检测输入
  - PhishingIndicator:      单条检测指标
  - PhishingVerdict:        统一检测裁决输出
"""
from pydantic import BaseModel, Field


# ── 请求模型 ──

class EmailPhishingRequest(BaseModel):
    """邮件钓鱼检测输入"""
    headers: str = ""                          # 原始邮件头（Received/SPF/DKIM 等）
    sender: str = ""                           # 发件人地址，如 "IT Support <it@paypa1.com>"
    subject: str = ""                          # 邮件主题
    body: str = ""                             # 邮件正文（纯文本或 HTML）
    attachments: list[str] = Field(default_factory=list)  # 附件文件名列表
    urls: list[str] = Field(default_factory=list)         # 正文中提取的 URL（可选，留空则自动提取）


class WebPhishingRequest(BaseModel):
    """网页钓鱼检测输入"""
    url: str                                   # 待检测 URL
    page_title: str = ""                       # 页面标题（可选）
    page_content: str = ""                     # 页面文本内容（可选，用于 LLM 分析）


class DomainPhishingRequest(BaseModel):
    """域名访问钓鱼检测输入"""
    domain: str                                # 待检测域名，如 "paypa1.com"
    access_context: str = ""                   # 访问上下文描述（可选）


class AttachmentPhishingRequest(BaseModel):
    """附件钓鱼检测输入"""
    filename: str                              # 文件名，如 "发票.pdf.exe"
    file_size: int = 0                         # 文件大小（字节）
    mime_type: str = ""                        # MIME 类型，如 "application/pdf"
    magic_bytes: str = ""                      # 文件头 hex，如 "4d5a9000" (MZ/PE)
    is_encrypted: bool = False                 # 是否加密/密码保护
    has_macros: bool = False                   # 是否含宏/脚本
    embedded_urls: list[str] = Field(default_factory=list)  # 文件内嵌 URL


class SmsPhishingRequest(BaseModel):
    """短信钓鱼检测输入"""
    sender_number: str = ""                    # 发送号码，如 "10086" 或 "+8613800138000"
    message_body: str = ""                     # 短信正文
    urls: list[str] = Field(default_factory=list)  # 短信中的 URL（可选，留空自动提取）


class QrCodePhishingRequest(BaseModel):
    """二维码钓鱼检测输入"""
    decoded_url: str                           # 二维码解码后的 URL/内容
    source_context: str = ""                   # 来源场景：email / poster / webpage / payment
    brand_hint: str = ""                       # 声称的品牌，如 "支付宝"


class BecPhishingRequest(BaseModel):
    """商务诈骗 (BEC) 检测输入"""
    sender: str = ""                           # 发件人，如 "CEO 张总 <zhang@gmail.com>"
    reply_to: str = ""                         # 回复地址
    subject: str = ""                          # 邮件主题
    body: str = ""                             # 邮件正文
    has_attachment: bool = False               # 是否含附件


# ── 输出模型 ──

class PhishingIndicator(BaseModel):
    """单条检测指标"""
    name: str                                  # 指标名称，如 "发件人伪造"
    category: str                              # 维度分类，如 "sender" / "url" / "content"
    severity: str = "info"                     # info / low / medium / high / critical
    detail: str = ""                           # 详细说明
    score: float = 0.0                         # 该指标贡献分 (0-100)


class PhishingVerdict(BaseModel):
    """统一检测裁决"""
    detection_type: str                        # "email" / "web" / "domain"
    target: str                                # 检测对象摘要
    risk_level: str = "safe"                   # safe / suspicious / phishing
    confidence: float = 0.0                    # 置信度 0-1
    score: float = 0.0                         # 综合风险分 0-100
    indicators: list[PhishingIndicator] = Field(default_factory=list)
    summary: str = ""                          # 一句话结论
    suggested_actions: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detection_type": self.detection_type,
            "target": self.target,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "score": self.score,
            "indicators": [i.model_dump() for i in self.indicators],
            "summary": self.summary,
            "suggested_actions": self.suggested_actions,
        }
