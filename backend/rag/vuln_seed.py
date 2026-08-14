"""
漏洞知识库 — 手工精选高影响漏洞（source="vulnerability"）

用途:
  - 补充 NVD 聚焦窗口（近 1 年）之外的历史高危漏洞，覆盖 Log4Shell、EternalBlue、
    Heartbleed 等依然活跃在真实攻击中的漏洞
  - 每条含描述、受影响版本、利用条件、检测特征、修复/缓解，供 RAG 精确检索与 LLM 引用

字段约定（均为结构化 metadata，写入 content 前缀 + metadata JSONB）:
  cve_id / name / severity / cvss_score / cvss_severity / published
  affected_products / fix_version / products (vendor:product 列表, 可选)
  description / exploit_condition / detection / fix
  cwe_ids / references / cnvd_id (可选) / known_exploited (是否在 CISA KEV)
"""
import asyncio
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .knowledge_base import kb_manager
from .chunker import security_chunker
from .kb_types import (
    SOURCE_KEV, SOURCE_VULN, SOURCE_CVE,
    build_content_prefix, cwe_to_threat_types,
)

logger = logging.getLogger(__name__)

# cve_id 唯一，作为幂等键；known_exploited=True 表示该漏洞在 CISA KEV 目录
VULN_SEED: list[dict] = [
    {
        "cve_id": "CVE-2021-44228",
        "name": "Apache Log4j2 远程代码执行漏洞（Log4Shell）",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2021-12-10", "known_exploited": True,
        "affected_products": "Apache Log4j 2.x（2.0-beta9 至 2.14.1）",
        "fix_version": "2.15.0（最佳） / 2.12.2 / 2.3.1",
        "products": ["apache:log4j"],
        "description": (
            "Apache Log4j2 的 JNDI 查找功能在解析日志消息时未对 `${jndi:ldap://...}` 形式的输入做限制，"
            "攻击者通过构造恶意日志内容可触发 JNDI 注入，加载远程恶意类，实现远程代码执行。"
            "影响面覆盖大量使用 Java 生态的中间件与应用。"
        ),
        "exploit_condition": "目标组件记录攻击者可控输入到日志且 Log4j2 版本在受影响范围内；无需认证即可利用。",
        "detection": (
            "日志中出现 `${jndi:` 前缀（含大小写/编码变体如 ${${lower:j}}）；"
            "LDAP/RMI 出站请求到非预期地址；WAF/IDS 规则命中 jndi 特征；进程异常反弹 Shell 行为。"
        ),
        "fix": (
            "升级 Log4j2 ≥2.17.1（2.15.0 存在绕过）；无法升级时设置 log4j2.formatMsgNoLookups=true、"
            "移除 JndiLookup 类或部署 WAF 拦截。"
        ),
        "cwe_ids": ["CWE-502"],
        "cnvd_id": "CNVD-2021-95914",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"],
    },
    {
        "cve_id": "CVE-2017-0144",
        "name": "Microsoft SMBv1 远程代码执行漏洞（EternalBlue）",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2017-04-14", "known_exploited": True,
        "affected_products": "Windows Vista/7/8.1/10、Server 2008/2012/2016（开启 SMBv1）",
        "fix_version": "MS17-010 补丁（KB4012212 等）",
        "products": ["microsoft:windows"],
        "description": (
            "SMBv1 服务在处理特制 SMB 报文时存在内存破坏，攻击者无需认证即可在目标上执行任意代码。"
            "该漏洞被 NSA 泄露的漏洞利用工具利用，成为 WannaCry、NotPetya 等勒索软件大规模传播的载体。"
        ),
        "exploit_condition": "目标开放 445 端口且未安装 MS17-010 补丁、未禁用 SMBv1；防火墙常为外部利用的主要屏障。",
        "detection": (
            "SMB 445 端口异常扫描与连接频率；MS17-010 相关 exploit 特征（EternalBlue 报文）；"
            "勒索软件释放的 dropper 行为。"
        ),
        "fix": "安装 MS17-010 补丁、禁用 SMBv1、关闭不必要共享，限制 445 端口入站访问。",
        "cwe_ids": ["CWE-119"],
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"],
    },
    {
        "cve_id": "CVE-2023-34362",
        "name": "MOVEit Transfer SQL 注入远程代码执行漏洞",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2023-05-31", "known_exploited": True,
        "affected_products": "Progress MOVEit Transfer < 2023.0.1",
        "fix_version": "2023.0.1 / 2023.0.2（Cl0p 系列利用）",
        "products": ["progress:moveit_transfer"],
        "description": (
            "MOVEit Transfer 存在 SQL 注入漏洞，攻击者可通过 web 接口执行任意 SQL，"
            "并利用存储过程向目标植入 webshell 实现远程代码执行，被 Cl0p 勒索团伙大规模利用。"
        ),
        "exploit_condition": "Web 管理接口可达且版本未修复；利用链无需已知凭据。",
        "detection": (
            "对 /moveitisapi 等接口的异常请求；webshell 文件（如 human2.aspx）落地；"
            "数据库连接异常与 webserver 进程异常。"
        ),
        "fix": "升级到修复版本，排查被植入的 webshell，重置受影响的数据库凭据。",
        "cwe_ids": ["CWE-89"],
        "cnvd_id": "CNVD-2023-591",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-34362"],
    },
    {
        "cve_id": "CVE-2014-0160",
        "name": "OpenSSL Heartbleed 信息泄露漏洞",
        "severity": "high", "cvss_score": 7.5, "cvss_severity": "HIGH",
        "published": "2014-04-07", "known_exploited": True,
        "affected_products": "OpenSSL 1.0.1 - 1.0.1f",
        "fix_version": "1.0.1g",
        "products": ["openssl:openssl"],
        "description": (
            "OpenSSL TLS 心跳扩展（Heartbeat）存在边界检查缺失，攻击者可向服务端发送特制心跳请求，"
            "每次读取最多 64KB 服务端内存，泄露私钥、会话密钥、用户凭据等敏感数据。"
        ),
        "exploit_condition": "目标使用受影响 OpenSSL 版本且启用 TLS 心跳；无需认证，可远程重复利用。",
        "detection": (
            "检测 TLS 心跳扩展响应长度与请求不一致（发送 1 字节请求、收到 >1 字节响应）；"
            "异常心跳报文大小；泄露数据导致的凭据滥用。"
        ),
        "fix": "升级 OpenSSL ≥1.0.1g 或应用补丁，之后必须轮换全部服务端证书私钥与会话凭据。",
        "cwe_ids": ["CWE-119"],
        "cnvd_id": "CNVD-2014-02425",
        "references": ["https://heartbleed.com/", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
    },
    {
        "cve_id": "CVE-2014-6271",
        "name": "Bash 环境变量代码执行漏洞（Shellshock）",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2014-09-24", "known_exploited": True,
        "affected_products": "GNU Bash ≤ 4.3",
        "fix_version": "Bash 4.3 后续补丁（bash44-001 起）",
        "products": ["gnu:bash"],
        "description": (
            "Bash 在处理以函数定义开头的环境变量时，会在函数体结束后继续解析并执行后续命令。"
            "CGI、DHCP、SSH 等将攻击者可控数据传入环境变量的场景均可触发远程代码执行。"
        ),
        "exploit_condition": "任何将用户输入放入环境变量并由 Bash 解释的场景（如 CGI 脚本）；可利用面广。",
        "detection": (
            "HTTP 请求携带包含 `(){` 特征的 User-Agent 等头；bash 子进程异常执行命令；"
            "对 `/cgi-bin` 的畸形请求。"
        ),
        "fix": "升级 Bash 至修复版本；临时措施如设置 shellshock 缓解、加固 CGI 环境清理。",
        "cwe_ids": ["CWE-78"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
    },
    {
        "cve_id": "CVE-2022-0847",
        "name": "Linux 内核 Dirty Pipe 本地提权漏洞",
        "severity": "high", "cvss_score": 7.8, "cvss_severity": "HIGH",
        "published": "2022-03-07", "known_exploited": True,
        "affected_products": "Linux 内核 5.8+（直至修复）",
        "fix_version": "内核 5.16.11 / 5.15.25 / 5.10.102 等",
        "products": ["linux:linux_kernel"],
        "description": (
            "Linux 内核管道（pipe）实现中，写操作可绕过只读文件映射的权限检查，"
            "攻击者可修改任意只读文件内容（如 /etc/passwd、suid 二进制），实现本地提权。"
            "利用方式简单可靠，2022 年大量真实攻击中用于提权。"
        ),
        "exploit_condition": "攻击者已获得低权限本地 shell；漏洞利用无需交互，几秒内完成提权。",
        "detection": (
            "检测 /etc/passwd、sshd 配置等敏感只读文件的异常篡改（文件哈希变化）；"
            "内核版本低于修复版本且存在可疑提权行为的进程。"
        ),
        "fix": "升级内核或应用厂商补丁；结合文件完整性监控（FIM）发现被篡改的只读文件。",
        "cwe_ids": ["CWE-787"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"],
    },
    {
        "cve_id": "CVE-2022-22965",
        "name": "Spring Framework 远程代码执行漏洞（Spring4Shell）",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2022-03-31", "known_exploited": True,
        "affected_products": "Spring Framework 5.3.x < 5.3.18、5.2.x < 5.2.20（JDK9+ 且部署为 WAR）",
        "fix_version": "5.3.18 / 5.2.20",
        "products": ["springsource:spring_framework", "vmware:spring"],
        "description": (
            "Spring MVC 通过 ClassLoader 的 data binding 特性，可访问并修改 ClassLoader 属性，"
            "攻击者利用 `class.module.classLoader` 路径写 webshell 实现远程代码执行。"
            "利用依赖 JDK9+ 且以 WAR 方式部署，被称为 Spring4Shell。"
        ),
        "exploit_condition": "JDK 9+、WAR 部署、未修复版本；常见于使用 Spring Boot 内嵌容器的场景（不直接受影响）。",
        "detection": (
            "HTTP 请求参数或路径含 `class.module.classLoader` 特征；Tomcat 目录异常写入 .jsp 文件；"
            "应用日志中的异常 URL 参数。"
        ),
        "fix": "升级 Spring Framework/Spring Boot 至修复版本；临时禁用 data binding 危险属性或加 WAF 规则拦截特征参数。",
        "cwe_ids": ["CWE-94"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    },
    {
        "cve_id": "CVE-2021-34527",
        "name": "Windows Print Spooler 远程代码执行漏洞（PrintNightmare）",
        "severity": "critical", "cvss_score": 8.8, "cvss_severity": "HIGH",
        "published": "2021-07-01", "known_exploited": True,
        "affected_products": "Windows Server 全版本（Print Spooler 服务）",
        "fix_version": "KB5004945 等 2021 年 7 月补丁",
        "products": ["microsoft:windows"],
        "description": (
            "Windows Print Spooler 服务对打印驱动安装的权限校验存在缺陷，"
            "攻击者可利用 `PrintNightmare` 将恶意 DLL 以 SYSTEM 权限加载，实现远程代码执行或本地提权。"
        ),
        "exploit_condition": "目标开放 445/139 且 Print Spooler 服务运行、未打补丁；域环境下攻击面更大。",
        "detection": (
            "Spoolsv.exe 进程异常加载 DLL；对新安装打印机驱动的异常行为；445 端口的异常 SMB 会话。"
        ),
        "fix": "安装补丁；紧急缓解可停止并禁用 Print Spooler 服务（非必需场景）、限制远程打印访问。",
        "cwe_ids": ["CWE-269"],
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
    },
    {
        "cve_id": "CVE-2021-26855",
        "name": "Microsoft Exchange Server SSRF 远程代码执行（ProxyLogon）",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2021-03-02", "known_exploited": True,
        "affected_products": "Exchange Server 2013/2016/2019",
        "fix_version": "2021 年 3 月安全更新",
        "products": ["microsoft:exchange_server"],
        "description": (
            "Exchange Server 的 EWS 端点存在服务端请求伪造（SSRF），攻击者可通过绕过认证的请求链"
            "（配合 CVE-2021-27065 等）写入 webshell，实现远程代码执行，2021 年遭多国 APT 大规模利用。"
        ),
        "exploit_condition": "Exchange 服务器 web 可达、未打 2021 年 3 月补丁；利用无需已知凭据。",
        "detection": (
            "Exchange 后端 OWA 目录出现可疑 .aspx 文件（如 aspnet_client 下）；异常 autodiscover/EWS 请求；"
            "新建立的 PowerShell 远程会话。"
        ),
        "fix": "应用 3 月安全更新；排查被植入的 webshell（重点目录：c:\\inetpub\\wwwroot\\aspnet_client）；重置相关账户。",
        "cwe_ids": ["CWE-918"],
        "references": ["https://msrc.microsoft.com/blog/2021/03/analysis-of-the-proxylogon-exploit-chain/"],
    },
    {
        "cve_id": "CVE-2021-34473",
        "name": "Microsoft Exchange Server 远程代码执行（ProxyShell）",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2021-08-10", "known_exploited": True,
        "affected_products": "Exchange Server 2013/2016/2019",
        "fix_version": "2021 年 5 月/8 月安全更新",
        "products": ["microsoft:exchange_server"],
        "description": (
            "ProxyShell 是由三个漏洞（CVE-2021-34473 SSRF、CVE-2021-34523 权限提升、"
            "CVE-2021-31207 写入权限）组成的利用链，攻击者可无凭据获得 Exchange 的任意代码执行权限，"
            "常被用于投放勒索软件与 webshell。"
        ),
        "exploit_condition": "Exchange web 接口可达且未打相关补丁；利用链相对稳定，广泛用于攻击。",
        "detection": (
            "autodiscover 接口异常请求；新落地 .aspx webshell；Exchange 相关进程异常命令执行；"
            "新建的额外 Exchange 管理员账户。"
        ),
        "fix": "安装 2021 年 5 月、7 月、8 月安全更新；排查 webshell 与异常管理员账户。",
        "cwe_ids": ["CWE-918"],
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473"],
    },
    {
        "cve_id": "CVE-2023-4966",
        "name": "Citrix NetScaler ADC/网关敏感信息泄露（CitrixBleed）",
        "severity": "critical", "cvss_score": 9.4, "cvss_severity": "CRITICAL",
        "published": "2023-10-10", "known_exploited": True,
        "affected_products": "Citrix NetScaler ADC/Gateway（13.1 < 49.13、14.1 < 4.29 等）",
        "fix_version": "13.1-49.13 / 14.1-4.29",
        "products": ["citrix:netscaler"],
        "description": (
            "Citrix NetScaler ADC 与 Gateway 存在内存越界读，攻击者通过构造的 HTTP 请求可读取内存中的"
            "会话令牌，进而绕过认证接管现有会话，被用于窃取会话以获取 VPN 内部访问权限。"
        ),
        "exploit_condition": "设备管理接口或登录接口可达、未修复；利用后配合会话劫持进入内网。",
        "detection": (
            "对 NetScaler 设备的异常 GET 请求（长 URL 探测）；新建立的 VPN 会话与已知会话异常重合；"
            "会话令牌泄露导致的异常访问行为。"
        ),
        "fix": "升级至修复版本；轮换受影响设备的全部会话/凭据，排查异常会话。",
        "cwe_ids": ["CWE-125"],
        "references": ["https://support.citrix.com/article/CTX579459"],
    },
    {
        "cve_id": "CVE-2023-46604",
        "name": "Apache ActiveMQ OpenWire 远程代码执行漏洞",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2023-10-27", "known_exploited": True,
        "affected_products": "Apache ActiveMQ 5.x / Artemis",
        "fix_version": "5.15.16 / 5.16.7 / 5.17.6 / 5.18.3",
        "products": ["apache:activemq"],
        "description": (
            "Apache ActiveMQ 的 OpenWire 协议反序列化处理存在缺陷，攻击者可构造恶意报文触发任意类加载，"
            "实现远程代码执行。2023 年 10 月起被 HelloKitty 等勒索团伙大规模利用。"
        ),
        "exploit_condition": "OpenWire 端口（默认 61616）对外可达且未修复；无需认证即可利用。",
        "detection": (
            "对 61616 端口的畸形 OpenWire 报文；ActiveMQ 进程外连异常地址；落地 webshell 或挖矿程序。"
        ),
        "fix": "升级至修复版本；限制 OpenWire 端口仅内网可达、开启认证。",
        "cwe_ids": ["CWE-502"],
        "references": ["https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt"],
    },
    {
        "cve_id": "CVE-2024-3400",
        "name": "Palo Alto PAN-OS GlobalProtect 远程代码执行漏洞",
        "severity": "critical", "cvss_score": 10.0, "cvss_severity": "CRITICAL",
        "published": "2024-04-12", "known_exploited": True,
        "affected_products": "PAN-OS 10.2 < 10.2.9-h1、11.0 < 11.0.4-h1、11.1 < 11.1.2-h3",
        "fix_version": "10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3",
        "products": ["paloaltonetworks:pan-os"],
        "description": (
            "PAN-OS GlobalProtect 的 Cookie 解析存在路径穿越导致任意文件写入，配合命令注入实现"
            "未认证远程代码执行。攻击者可在防火墙设备上获得 root 权限，被广泛用于接管边界设备。"
        ),
        "exploit_condition": "GlobalProtect 接口对公网可达且版本未修复；无需认证即可利用。",
        "detection": (
            "设备上异常文件写入（/var/appweb/sslvpndocs/ 等）；GlobalProtect 会话异常；"
            "边界设备外连非预期 C2 地址。"
        ),
        "fix": "升级 PAN-OS 至修复版本；排查设备上的恶意文件与异常会话，必要时重置管理凭据。",
        "cwe_ids": ["CWE-78", "CWE-22"],
        "references": ["https://security.paloaltonetworks.com/CVE-2024-3400"],
    },
    {
        "cve_id": "CVE-2023-27350",
        "name": "PaperCut MF/NG 远程代码执行漏洞",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2023-04-26", "known_exploited": True,
        "affected_products": "PaperCut MF/NG < 22.0.9、< 20.1.7",
        "fix_version": "22.0.9 / 20.1.7",
        "products": ["papercut:papercut_mf", "papercut:papercut_ng"],
        "description": (
            "PaperCut 打印管理软件存在认证绕过（CVE-2023-27350）与命令注入（CVE-2023-27351），"
            "组合可实现在内置 admin 账户上远程代码执行，2023 年 4 月起遭勒索团伙利用。"
        ),
        "exploit_condition": "PaperCut 管理端口（默认 9191）可达且未修复。",
        "detection": "对管理端口的异常 POST 请求；PaperCut 进程外连 C2；落地 webshell。",
        "fix": "升级至修复版本；将管理端口限制在内网并加认证。",
        "cwe_ids": ["CWE-306"],
        "references": ["https://www.papercut.com/kb/Main/PO-1216"],
    },
    {
        "cve_id": "CVE-2023-20198",
        "name": "Cisco IOS XE Web UI 权限提升漏洞",
        "severity": "critical", "cvss_score": 10.0, "cvss_severity": "CRITICAL",
        "published": "2023-10-16", "known_exploited": True,
        "affected_products": "Cisco IOS XE（启用 Web UI 的版本）",
        "fix_version": "各版本对应修复（禁用 webui 为临时缓解）",
        "products": ["cisco:ios_xe"],
        "description": (
            "Cisco IOS XE 的 Web UI 特性存在权限提升漏洞，攻击者可创建本地用户并提权至 level 15，"
            "被用于植入 Lua 植入程序以长期控制边界路由器/交换机。"
        ),
        "exploit_condition": "设备启用 Web UI 特性且暴露管理接口。",
        "detection": (
            "设备上新增未知本地用户；异常配置变更；对管理端口的扫描；边界设备外连可疑地址。"
        ),
        "fix": "升级到修复版本或禁用 http server/webui；排查新增用户与恶意配置。",
        "cwe_ids": ["CWE-269"],
        "references": ["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"],
    },
    {
        "cve_id": "CVE-2021-26084",
        "name": "Atlassian Confluence OGNL 注入远程代码执行",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2021-08-25", "known_exploited": True,
        "affected_products": "Confluence Server/Data Center 受影响版本",
        "fix_version": "7.4.10 / 7.11.6 / 7.12.5 / 7.13.0",
        "products": ["atlassian:confluence_server", "atlassian:confluence_data_center"],
        "description": (
            "Confluence 对 Webwork OGNL 表达式的过滤不完整，未认证攻击者可通过特制请求触发 OGNL 注入"
            "执行任意命令，2021 年 8 月起被用于挖矿与 webshell 投放。"
        ),
        "exploit_condition": "Confluence 公网可达且未修复；无需认证即可利用。",
        "detection": "含 OGNL 特征（如 ${、%24、add）的异常请求；Confluence 进程异常命令执行；落地文件。",
        "fix": "升级至修复版本；排查 webshell（webapps/confluence 目录）与异常账户。",
        "cwe_ids": ["CWE-94"],
        "references": ["https://confluence.atlassian.com/doc/confluence-security-advisory-2021-08-25-1073066216.html"],
    },
    {
        "cve_id": "CVE-2022-30190",
        "name": "Microsoft 支持诊断工具远程代码执行（Follina）",
        "severity": "high", "cvss_score": 7.8, "cvss_severity": "HIGH",
        "published": "2022-05-30", "known_exploited": True,
        "affected_products": "Windows 全版本（MSDT 组件）",
        "fix_version": "2022 年 6 月补丁（KB5014697 等）",
        "products": ["microsoft:windows"],
        "description": (
            "Windows 支持诊断工具（MSDT）通过 URL 协议 ms-msdt 被 Office 文档调用时，"
            "可执行攻击者指定的 PowerShell 命令，构造恶意 Word 文档即可实现远程代码执行。"
        ),
        "exploit_condition": "受害者打开恶意 Office 文档；需用户交互但利用隐蔽。",
        "detection": "文档中 `ms-msdt:` 协议特征；MSDT 进程异常启动 PowerShell；Office 外连可疑地址。",
        "fix": "安装补丁；禁用 ms-msdt 协议（注册表），加强邮件网关对恶意 Office 文档的检测。",
        "cwe_ids": ["CWE-94"],
        "references": ["https://msrc.microsoft.com/blog/2022/05/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/"],
    },
    {
        "cve_id": "CVE-2020-1472",
        "name": "Netlogon 权限提升漏洞（Zerologon）",
        "severity": "critical", "cvss_score": 10.0, "cvss_severity": "CRITICAL",
        "published": "2020-08-11", "known_exploited": True,
        "affected_products": "Windows Server 2008 R2 - 2019（域控）",
        "fix_version": "2020 年 8 月补丁（KB4565349）",
        "products": ["microsoft:windows_server"],
        "description": (
            "Netlogon 协议的 AES-CFB8 加密初始化向量恒为零，攻击者可伪造域控身份的登录请求，"
            "在几分钟内将域控机器账户密码置空，进而取得域管理员权限，接管整个域。"
        ),
        "exploit_condition": "域控未打补丁且攻击者可从内网访问 445 端口；攻击无需认证。",
        "detection": "对域控 445 端口的异常 Netlogon 会话；DC 机器账户密码异常重置；异常 DCSync 行为。",
        "fix": "安装补丁并启用强制防护（域控需在补丁后进入强制模式）；立即重置域内高风险账户密码。",
        "cwe_ids": ["CWE-330"],
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"],
    },
    {
        "cve_id": "CVE-2019-19781",
        "name": "Citrix Application Delivery Controller 目录遍历远程代码执行",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2019-12-17", "known_exploited": True,
        "affected_products": "Citrix ADC/Gateway 13.0 < 13.0-82.46、12.1 < 12.1-63.18 等",
        "fix_version": "13.0-82.46 / 12.1-63.18",
        "products": ["citrix:netscaler"],
        "description": (
            "Citrix ADC 与 Gateway 存在目录遍历，未认证攻击者可通过构造路径访问管理脚本，"
            "写入恶意文件实现远程代码执行，被广泛用于边界设备接管。"
        ),
        "exploit_condition": "设备管理接口或 VPN 接口可达且未修复。",
        "detection": "对 /vpn/../ 等路径的异常请求；设备上的恶意 XML/文件写入；边界设备外连 C2。",
        "fix": "升级至修复版本；排查设备文件系统与异常配置。",
        "cwe_ids": ["CWE-22"],
        "references": ["https://support.citrix.com/article/CTX267027"],
    },
    {
        "cve_id": "CVE-2024-3094",
        "name": "XZ Utils liblzma 供应链后门",
        "severity": "critical", "cvss_score": 10.0, "cvss_severity": "CRITICAL",
        "published": "2024-03-29", "known_exploited": False,
        "affected_products": "xz/liblzma 5.6.0 / 5.6.1",
        "fix_version": "5.4.6 / 5.6.1+（后门已移除）",
        "products": ["tukaani:xz"],
        "description": (
            "XZ Utils 5.6.0/5.6.1 在构建产物中被注入后门代码，通过混淆的二进制脚本劫持 sshd 认证"
            "流程实现远程代码执行，是一次针对开源软件供应链的高隐蔽性攻击，影响广泛的 Linux 发行版。"
        ),
        "exploit_condition": "系统安装带后门的 liblzma 且 sshd 受影响（主要影响 systemd 集成的发行版）。",
        "detection": (
            "检测 xz 版本为 5.6.0/5.6.1；sshd 进程加载异常符号（如 RSA_public_decrypt 被劫持）；"
            "ldd sshd 输出异常；包管理器告警。"
        ),
        "fix": "降级/升级 xz 至无后门版本；排查受影响的二进制与 SSH 配置；轮换可能泄露的凭据。",
        "cwe_ids": ["CWE-1321"],
        "references": ["https://www.openwall.com/lists/oss-security/2024/03/29/4"],
    },
    {
        "cve_id": "CVE-2024-21887",
        "name": "Ivanti Connect Secure 命令注入漏洞",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2024-01-10", "known_exploited": True,
        "affected_products": "Ivanti Connect Secure < 9.1R14.4 / < 22.5R2.5 等",
        "fix_version": "9.1R14.4 / 22.5R2.5",
        "products": ["ivanti:connect_secure"],
        "description": (
            "Ivanti Connect Secure（原 Pulse Secure）存在命令注入漏洞，攻击者可通过特制请求"
            "以 root 权限执行任意命令，常与 CVE-2023-46805 认证绕过组合使用，被多国 APT 利用。"
        ),
        "exploit_condition": "VPN 接口公网可达且未修复；无需认证即可触发命令注入。",
        "detection": "设备上异常文件写入（/home/webserver/htdocs/ 等）；VPN 会话异常；边界设备外连 C2。",
        "fix": "升级至修复版本；按厂商指引排查后门与配置篡改，必要时重置设备。",
        "cwe_ids": ["CWE-78"],
        "references": ["https://forums.ivanti.com/s/article/CVE-2024-21887-Policy-Secure-Connect-Secure-RCE"],
    },
    {
        "cve_id": "CVE-2021-4034",
        "name": "polkit pkexec 本地提权漏洞（PwnKit）",
        "severity": "high", "cvss_score": 7.8, "cvss_severity": "HIGH",
        "published": "2022-01-25", "known_exploited": True,
        "affected_products": "polkit < 0.120（各主流 Linux 发行版）",
        "fix_version": "polkit 0.120 / 各发行版安全更新",
        "products": ["freedesktop:polkit"],
        "description": (
            "polkit 的 pkexec 存在 CVE-2017-1000366 修复不完整的越界写，任何本地用户无需凭据即可"
            "通过构造环境变量在默认配置下提权至 root，利用代码仅数行，2022 年遭大规模利用。"
        ),
        "exploit_condition": "目标运行受影响 polkit 且攻击者已有普通用户权限。",
        "detection": "pkexec 相关异常行为；低权限进程提权后的异常命令执行；文件哈希核对版本。",
        "fix": "升级 polkit 至修复版本；临时可用 chmod 0755 /usr/bin/pkexec 缓解。",
        "cwe_ids": ["CWE-787"],
        "references": ["https://www.openwall.com/lists/oss-security/2022/01/25/14"],
    },
    {
        "cve_id": "CVE-2018-13379",
        "name": "Fortinet FortiOS SSL VPN 路径遍历漏洞",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2019-06-06", "known_exploited": True,
        "affected_products": "FortiOS 6.0.0-6.0.4、5.6.3-5.6.7、5.4.6-5.4.12",
        "fix_version": "6.0.5 / 5.6.8 / 5.4.13",
        "products": ["fortinet:fortios"],
        "description": (
            "FortiOS SSL VPN 的 portal 存在路径遍历，未认证攻击者可读取任意系统文件，"
            "泄露 VPN 会话明文凭据，被多国政府与企业的边界设备漏洞利用，2020-2021 年遭大规模攻击。"
        ),
        "exploit_condition": "SSL VPN 接口公网可达且版本受影响；利用可读取 /dev/cmdb/sslvpn_websession 获取会话。",
        "detection": "对 SSL VPN 端口的异常路径请求；疑似凭据泄露后的 VPN 账号异常登录。",
        "fix": "升级 FortiOS 至修复版本；强制 VPN 用户轮换密码，排查异常会话。",
        "cwe_ids": ["CWE-22"],
        "cnvd_id": "CNVD-2021-03056",
        "references": ["https://www.fortiguard.com/psirt/FG-IR-18-384"],
    },
    {
        "cve_id": "CVE-2020-10148",
        "name": "SolarWinds Orion 平台认证绕过漏洞",
        "severity": "critical", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "published": "2020-12-14", "known_exploited": True,
        "affected_products": "SolarWinds Orion Platform < 2020.2.1",
        "fix_version": "2020.2.1 HF2",
        "products": ["solarwinds:orion_platform"],
        "description": (
            "SolarWinds Orion 平台存在硬编码/可预测密钥导致的认证绕过，攻击者可未认证调用管理 API。"
            "2020 年曝出的 SUNBURST 供应链攻击正是通过污染 Orion 更新构建链完成，影响上万组织。"
        ),
        "exploit_condition": "Orion 平台 web 接口可达且未修复。",
        "detection": "Orion 进程（SolarWinds.BusinessLayerHost.exe）异常外连与进程行为；对管理 API 的未认证调用。",
        "fix": "升级至修复版本并应用补丁；排查 SUNBURST 相关 IOC、轮换全部关联凭据。",
        "cwe_ids": ["CWE-306"],
        "references": ["https://www.solarwinds.com/securityadvisory"],
    },
    {
        "cve_id": "CVE-2024-6387",
        "name": "OpenSSH sshd 远程代码执行漏洞（regreSSHion）",
        "severity": "high", "cvss_score": 8.1, "cvss_severity": "HIGH",
        "published": "2024-07-01", "known_exploited": False,
        "affected_products": "OpenSSH 8.5p1 - 9.7p1（受影响版本，信号处理竞态）",
        "fix_version": "9.8p1",
        "products": ["openssh:openssh"],
        "description": (
            "OpenSSH sshd 在 OpenSSH 8.5p1-9.7p1 版本中，因 2020 年移除对 SIGALRM 处理的重置逻辑，"
            "存在可利用的信号竞态，攻击者可在 SSH 登录前并发连接触发，最终实现远程代码执行（利用难度高）。"
        ),
        "exploit_condition": "目标运行受影响版本且开放 SSH；利用需要较长时间竞争窗口（数小时级），实际攻击门槛高。",
        "detection": "对 sshd 的异常大量并发连接尝试；sshd 进程崩溃/异常退出；日志中的认证异常模式。",
        "fix": "升级 OpenSSH ≥9.8p1；临时缓解可配置 LoginGraceTime=0、连接数限制、网络层限制 SSH 来源。",
        "cwe_ids": ["CWE-362"],
        "references": ["https://www.qualys.com/2024/07/01/cve-2024-6387/openssh-server-remote-code-execution-regresshion/"],
    },
    {
        "cve_id": "CVE-2023-44487",
        "name": "HTTP/2 流重置拒绝服务（Rapid Reset）",
        "severity": "high", "cvss_score": 7.5, "cvss_severity": "HIGH",
        "published": "2023-10-10", "known_exploited": True,
        "affected_products": "支持 HTTP/2 的 Web 服务器/反向代理/负载均衡",
        "fix_version": "各组件对应修复（nginx/Node.js/Envoy 等 2023-10 更新）",
        "products": [],
        "description": (
            "攻击者利用 HTTP/2 流可以大量创建并立即 RST 的特性，绕过单连接并发限制，"
            "以极低带宽对目标发起超大规模 DDoS。2023 年 8-10 月 Cloudflare/AWS/Google 等被用于最大规模攻击。"
        ),
        "exploit_condition": "目标开放 HTTP/2；攻击者需能保持多个连接（通常通过分布式僵尸网络）。",
        "detection": "单连接内异常高的 RST_STREAM 频率；连接生命周期极短；流量体积-请求数比值异常。",
        "fix": "应用组件更新；部署 HTTP/2 流重置速率限制、启用 RST_STREAM 限流与连接池监控。",
        "cwe_ids": ["CWE-400", "CWE-770"],
        "references": ["https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack"],
    },
]


class VulnImportResult:
    def __init__(self):
        self.total_found = len(VULN_SEED)
        self.imported = 0
        self.updated = 0
        self.skipped = 0
        self.errors = 0
        self.error_details: list[str] = []

    def to_dict(self):
        return {
            "source": "vulnerability",
            "total_found": self.total_found,
            "imported": self.imported,
            "updated": self.updated,
            "skipped": self.skipped,
            "errors": self.errors,
            "error_details": self.error_details[:5],
        }


def _build_vuln_content(v: dict) -> str:
    """纯函数：精选漏洞记录 → 文档正文"""
    parts = []
    parts.append("## 漏洞描述\n" + v.get("description", ""))
    if v.get("affected_products"):
        parts.append("## 受影响版本\n" + v["affected_products"])
    if v.get("exploit_condition"):
        parts.append("## 利用条件\n" + v["exploit_condition"])
    if v.get("detection"):
        parts.append("## 检测特征\n" + v["detection"])
    if v.get("fix"):
        parts.append("## 修复/缓解\n" + v["fix"])
    return "\n\n".join(parts)


def _vuln_meta(v: dict) -> dict:
    """精选漏洞 → metadata JSONB（与内容前缀共用）"""
    return {
        "cve_id": v["cve_id"],
        "cvss_score": v.get("cvss_score"),
        "cvss_severity": (v.get("cvss_severity") or "").upper(),
        "published": v.get("published", ""),
        "products": v.get("products", []),
        "cwe_ids": v.get("cwe_ids", []),
        "references": v.get("references", []),
        "cnvd_id": v.get("cnvd_id", ""),
        "fix_version": v.get("fix_version", ""),
        "affected_products": v.get("affected_products", ""),
        "exploit_available": bool(v.get("known_exploited")),
    }


async def import_vuln_seed(
    session: AsyncSession,
    vuln_data: Optional[list[dict]] = None,
    force: bool = False,
) -> VulnImportResult:
    """
    导入手工精选漏洞知识库（source="vulnerability"，按 cve_id 幂等）。

    Args:
        session: 数据库会话
        vuln_data: 漏洞列表（默认 VULN_SEED，测试可注入）
        force: True 时覆盖 source="vulnerability" 的已有同名文档

    Returns:
        VulnImportResult
    """
    result = VulnImportResult()
    library = vuln_data if vuln_data is not None else VULN_SEED
    result.total_found = len(library)

    from models import KnowledgeDoc, KnowledgeChunk
    from sqlalchemy import delete as sa_delete, update as sa_update

    for v in library:
        cve_id = v.get("cve_id", "")
        if not cve_id:
            result.skipped += 1
            continue

        try:
            # 幂等：仅对 source="vulnerability" 去重（cve/kev 文档不阻止精选漏洞补细节）
            existing = await kb_manager.find_doc_by_metadata(
                session, {"cve_id": cve_id}, sources=[SOURCE_VULN]
            )
            if existing and not force:
                result.skipped += 1
                continue

            severity = v.get("severity", "high")
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "high"
            meta = _vuln_meta(v)
            threat_types = cwe_to_threat_types(v.get("cwe_ids", []))
            title = f"{cve_id} - {v.get('name', '')}"
            content = build_content_prefix(meta) + _build_vuln_content(v)
            tags = [cve_id, "vulnerability"] + (
                ["kev-exploited"] if v.get("known_exploited") else []
            )

            if existing:
                doc_id = existing["id"]
                await session.execute(
                    sa_delete(KnowledgeChunk).where(KnowledgeChunk.doc_id == doc_id)
                )
                await session.execute(
                    sa_update(KnowledgeDoc).where(KnowledgeDoc.id == doc_id).values(
                        title=title, content=content[:10000],
                        threat_types=threat_types, severity=severity,
                        tags=tags, metadata_=meta,
                    )
                )
                result.updated += 1
            else:
                doc = KnowledgeDoc(
                    title=title, content=content[:10000], source=SOURCE_VULN,
                    threat_types=threat_types, severity=severity,
                    tags=tags, metadata_=meta,
                )
                session.add(doc)
                await session.flush()
                doc_id = doc.id
                result.imported += 1

            chunks = security_chunker.chunk_document(
                doc_id=doc_id, title=title, content=content[:10000], source=SOURCE_VULN,
                threat_types=threat_types, severity=severity, tags=tags,
            )
            for cd in chunks:
                session.add(KnowledgeChunk(
                    doc_id=cd["doc_id"], chunk_id=cd["chunk_id"], content=cd["content"],
                    title=title, source=SOURCE_VULN, threat_types=threat_types,
                    severity=severity, tags=tags, embedding=None, token_count=cd["token_count"],
                ))
        except Exception as e:
            result.errors += 1
            result.error_details.append(f"import {cve_id}: {e}")
            logger.warning(f"Vuln seed import failed for {cve_id}: {e}")

    await session.commit()
    logger.info(
        f"Vuln seed import complete: {result.imported} new, {result.updated} updated, "
        f"{result.skipped} skipped, {result.errors} errors"
    )

    if result.imported + result.updated > 0:
        from .seeder import _compute_missing_embeddings
        asyncio.create_task(_compute_missing_embeddings(None))

    return result
