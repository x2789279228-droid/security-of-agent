<#
.SYNOPSIS
  Windows 安全日志采集器 — 将真实主机事件转发到 SOC 平台 /api/logs/ingest

.DESCRIPTION
  持续轮询 Windows 安全/系统事件日志（登录失败、防火墙拦截、Defender 告警等），
  并采集 netstat 活动连接，转换为平台 JSON 后批量 POST 到 SOC 平台。
  建议以管理员身份运行（读取安全事件日志需要权限）。
  事件按主机统一 session_id 上报，便于平台做攻击链关联。

用法:
  .\windows-log-collector.ps1 -SocUrl http://192.168.1.50:8001 -Interval 10
  注册为计划任务:
  schtasks /create /tn "WinLogCollector" /sc minute /mo 1 /ru SYSTEM /rl HIGHEST ^
    /tr "powershell -ExecutionPolicy Bypass -File C:\tools\windows-log-collector.ps1 -SocUrl http://192.168.1.50:8001"
#>
param(
    [string]$SocUrl = "http://localhost:8001",
    [int]$Interval = 15,
    [int]$NetstatInterval = 60
)

$ErrorActionPreference = "Continue"
$stateDir = "$env:LOCALAPPDATA\SecurityEngine"
$stateFile = Join-Path $stateDir "winlog-state.json"
if (!(Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }

$hostId = "win-" + $env:COMPUTERNAME
$state = @{}
if (Test-Path $stateFile) {
    try { $state = Get-Content $stateFile -Raw | ConvertFrom-Json -AsHashtable } catch { $state = @{} }
}

function Write-State {
    $state | ConvertTo-Json | Set-Content $stateFile -Encoding utf8
}

function New-Event([string]$type, [string]$sev, [string]$src, [string]$dst, [string]$msg, [int]$conf) {
    return @{
        event = $type; severity = $sev
        src_ip = $src; dst_ip = $dst
        message = $msg; confidence = $conf
        protocol = "winlog"; source_host = $env:COMPUTERNAME
    }
}

function Get-EventLogEvents {
    $events = @()
    $logs = @("Security", "System", "Microsoft-Windows-Defender/Operational")
    $idMap = @{
        4625 = @("LOGON_FAILED", "high", "登录失败 (暴力破解/凭据攻击)", 80)
        4624 = @("USER_LOGIN", "info", "用户登录成功", 90)
        4634 = @("USER_LOGOUT", "info", "用户注销", 90)
        5152 = @("FIREWALL_BLOCK", "medium", "Windows 防火墙拦截入站连接", 75)
        5157 = @("FIREWALL_BLOCK", "medium", "Windows 防火墙拦截出站连接", 75)
        1102 = @("AUDIT_LOG_CLEAR", "critical", "安全日志被清除", 95)
        7045 = @("SERVICE_INSTALL", "high", "系统安装新服务", 70)
        4720 = @("ACCOUNT_CREATED", "medium", "创建新用户账号", 75)
        4740 = @("ACCOUNT_LOCKED", "medium", "账号被锁定", 80)
        1116 = @("MALWARE_DETECT", "critical", "Defender 检测到恶意软件", 90)
        1117 = @("MALWARE_REMEDIATED", "high", "Defender 已处置威胁", 90)
        4648 = @("EXPLICIT_LOGON", "medium", "显式凭据登录 (横向移动特征)", 65)
    }

    foreach ($log in $logs) {
        if ($log -eq "Security" -and $state[$log] -eq $null) { $state[$log] = 0 }
        $lastId = if ($state.ContainsKey($log)) { [long]$state[$log] } else { 0 }
        $hashtable = @{ LogName = $log }
        if ($lastId -gt 0) { $hashtable["Provider"] = "Microsoft-Windows-Security-Auditing" }
        try {
            $query = "*[System/EventID=4625 or System/EventID=4624 or System/EventID=4634 or System/EventID=5152 or System/EventID=5157 or System/EventID=1102 or System/EventID=7045 or System/EventID=4720 or System/EventID=4740 or System/EventID=4648 or System/EventID=1116 or System/EventID=1117]"
            $xe = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $query)
            if ($lastId -gt 0) {
                $xe.SelectionTicks = [long]($lastId + 1)
            }
        } catch {
            continue
        }
        try {
            $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($xe)
            while (($rec = $reader.ReadEvent()) -ne $null) {
                if ($rec.Id -and $idMap.ContainsKey([int]$rec.Id)) {
                    $meta = $idMap[[int]$rec.Id]
                    $msg = $rec.FormatDescription()
                    if (!$msg) { $msg = ($rec.Properties | ForEach-Object { $_.Value }) -join " " }
                    $src = ""; $dst = ""
                    if ($msg -match "Source Network Address:\s*(\S+)") { $src = $Matches[1] }
                    elseif ($msg -match "源网络地址:\s*(\S+)") { $src = $Matches[1] }
                    if ($msg -match "Destination Network Address:\s*(\S+)") { $dst = $Matches[1] }
                    elseif ($msg -match "目标网络地址:\s*(\S+)") { $dst = $Matches[1] }
                    if ($src -eq "-") { $src = "" }
                    if ($dst -eq "-") { $dst = "" }
                    $events += New-Event $meta[0] $meta[1] $src $dst ($meta[2] + " | " + $msg.Substring(0, [Math]::Min(120, $msg.Length))) $meta[3]
                }
                if ($rec.RecordId -gt $lastId) { $lastId = $rec.RecordId }
            }
            $reader.Dispose()
            $state[$log] = $lastId
        } catch {
            Write-Host "[$log] 读取失败: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    return $events
}

function Get-NetstatConnections {
    $events = @()
    $out = & netstat -ano
    $stateKey = "netstat"
    $last = if ($state.ContainsKey($stateKey)) { [long]$state[$stateKey] } else { 0 }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $rows = $out | Where-Object { $_ -match "ESTABLISHED" -and $_ -match "TCP" }
    foreach ($row in $rows) {
        $parts = ($row -split "\s+") | Where-Object { $_ }
        if ($parts.Count -lt 4) { continue }
        $local = $parts[1]; $remote = $parts[2]
        if ($remote -eq "0.0.0.0:0" -or $remote -match "127\.0\.0\.1|\[::1\]|^\*") { continue }
        if ($local -match "^192\.168\.|^10\.|^172\.(1[6-9]|2\d|3[01])\." -and $remote -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2\d|3[01])\.") {
            $events += New-Event "OUTBOUND_CONN" "low" $local $remote "主机主动建立外部连接 (外联行为)" 55
        }
    }
    $state[$stateKey] = $now
    return $events
}

function Post-Events($events) {
    if ($events.Count -eq 0) { return }
    $body = @{ logs = @($events); session_id = $hostId } | ConvertTo-Json -Depth 6 -Compress
    try {
        $resp = Invoke-RestMethod -Uri "$SocUrl/api/logs/ingest/batch" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 10
        Write-Host "[$(Get-Date -Format HH:mm:ss)] 上报 $($events.Count) 条成功" -ForegroundColor Green
    } catch {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] 上报失败: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Windows 日志采集器启动 — SOC: $SocUrl  主机ID: $hostId  间隔: ${Interval}s" -ForegroundColor Cyan
$lastNetstat = 0
while ($true) {
    $all = @(Get-EventLogEvents)
    if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $lastNetstat -ge $NetstatInterval) {
        $all += @(Get-NetstatConnections)
        $lastNetstat = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
    if ($all.Count -gt 0) {
        Post-Events $all
        Write-State
    }
    Start-Sleep -Seconds $Interval
}
