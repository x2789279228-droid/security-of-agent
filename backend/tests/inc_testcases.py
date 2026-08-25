"""
inc_testcases — 五项能力(NDR/EDR/威胁情报/0day/反钓鱼)单元测试的样本数据。

所有样本为纯 Python dict/字符串, 不依赖外部服务; 驱动 mock 服务器与本地方法。
"""
import json

__all__ = [
    "SYSMON_XML_PROCESS", "SYSMON_XML_NETWORK",
    "EDR_INGEST_EVENT", "SAMBOX_REPORT",
    "TAXII_OBJECTS_RESP", "MISP_ATTRIBUTES_RESP",
    "JA3_FIELDS", "TLS_METADATA",
    "PHISH_EMAIL_REQ", "PHISH_WEB_REQ", "PHISH_DOMAIN_REQ", "PHISH_ATTACHMENT_REQ",
    "PHISH_SMS_REQ", "PHISH_QR_REQ", "PHISH_BEC_REQ",
]

# ── EDR: Sysmon Event (Windows XML) ──
SYSMON_XML_PROCESS = """<Event>
<System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
  <EventID>1</EventID>
  <EventRecordID>1234</EventRecordID>
</System>
<EventData>
  <Data Name="UtcTime">2024-01-01 00:00:00.000</Data>
  <Data Name="ProcessGuid">{a1} - {b2}</Data>
  <Data Name="Image">C:\\Windows\\Temp\\evil.exe</Data>
  <Data Name="CommandLine">evil.exe -c http://c2.example.com</Data>
  <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
</EventData>
</Event>"""

SYSMON_XML_NETWORK = """<Event>
<System>
  <Provider Name="Microsoft-Windows-Sysmon"/>
  <EventID>3</EventID>
</System>
<EventData>
  <Data Name="Image">C:\\Windows\\Temp\\evil.exe</Data>
  <Data Name="DestinationIp">5.6.7.8</Data>
  <Data Name="DestinationPort">443</Data>
  <Data Name="Protocol">tcp</Data>
</EventData>
</Event>"""

EDR_INGEST_EVENT = {
    "event_id": 2,
    "event_data": {
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c powershell.exe -enc YWJj",
        "User": "DOMAIN\\admin",
    },
    "source": "sysmon",
}

# ── 0day: sandbox 报告 ──
SAMBOX_REPORT = {
    "task_id": "task-mock-1",
    "info": {"score": 8.0},
    "signatures": [{"name": "network:http_request", "description": "HTTP 请求到已知 C2"}],
    "network": {"hosts": [{"ip": "5.6.7.8", "hostname": "c2.example.com"}]},
    "behavior": {"summary": {"files": ["malware.exe"], "registry": []}},
}

# ── 威胁情报: TAXII/MISP 响应 ──
TAXII_OBJECTS_RESP = {
    "objects": [
        {"type": "indicator", "id": "indicator--1", "name": "c2",
         "pattern": "[ipv4-addr:value = '5.6.7.8' or domain-name:value = 'evil.com']"},
        {"type": "indicator", "id": "indicator--2", "name": "hash",
         "pattern": "[file:hashes.'SHA-256' = 'deadbeef00']"},
    ]
}

MISP_ATTRIBUTES_RESP = {
    "response": {"Attribute": [
        {"type": "ip-src", "value": "5.6.7.8", "category": "Network activity",
         "Event": {"info": "apt campaign"}},
        {"type": "domain", "value": "evil.com", "category": "Network activity"},
    ]}
}

# ── NDR: JA3/TLS ──
JA3_FIELDS = {
    "tls_version": "0x0303",
    "cipher_suites": [0x1301, 0x1302, 0x1303],
    "extensions": [0x002b, 0x000d],
    "elliptic_curves": [0x001d, 0x0017],
    "ec_point_formats": [0x00],
}
TLS_METADATA = {
    "sni": "www.example.com",
    "server_name": "www.example.com",
    "tls_version": "TLS1.3",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "ja3_hash": "acd97f1e0da26c4f4a8efafcc0edc80e",
    "cert_subject": "CN=*.example.com",
}

# ── 反钓鱼: Request 样本 ──
PHISH_EMAIL_REQ = {
    "sender": "IT Support <it@paypa1-security.com>",
    "subject": "紧急: 您的账户将被停用",
    "body": "请点击链接登录验证您的账户: http://secure-paypa1.com/login",
    "urls": ["http://secure-paypa1.com/login"],
    "html": "<a href='http://secure-paypa1.com/login'>验证</a>",
}
PHISH_WEB_REQ = {"url": "http://secure-login-paypa1.xyz/account"}
PHISH_DOMAIN_REQ = {"domain": "secure-login-paypa1.xyz"}
PHISH_ATTACHMENT_REQ = {
    "filename": "invoice.scr", "filetype": "exe",
    "embedded_urls": ["http://5.6.7.8/evil"],
}
PHISH_SMS_REQ = {"sender_number": "+8613800138000", "content": "您的中奖奖品已到账, 点击 http://fake-prize.xyz 领取"}
PHISH_QR_REQ = {"decoded_url": "http://qr-evil.example/scan"}
PHISH_BEC_REQ = {
    "sender": "CEO 张总 <ceo@company-email.com>",
    "display_name": "张总",
    "subject": "紧急转账",
    "urgent": True,
    "requesting_transfer": True,
}


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)
