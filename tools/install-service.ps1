<#
 .SYNOPSIS
  安全响应引擎 — 一键安装工具
  配置开机自启 + 系统托盘 + 桌面通知

 .DESCRIPTION
  执行本脚本将:
  1. 检查 Docker 环境
  2. 启动 Docker 容器 (docker-compose up -d)
  3. 设置开机自动启动 (注册为计划任务)
  4. 启动系统托盘 (隐藏 PowerShell 窗口)
  5. 验证所有服务正常运行

  用法:
    PowerShell (管理员) > .\install-service.ps1
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path "$scriptPath\.."
$trayScript = "$scriptPath\security-tray.ps1"
$logPath = "$env:LOCALAPPDATA\SecurityEngine"
$taskName = "SecurityEngineTray"
$ps1Path = Join-Path $logPath "run-tray.ps1"
$vbsPath = Join-Path $logPath "run-tray.vbs"

# ── 颜色输出 ──
function Write-Success($msg) { Write-Host "  ✅ $msg" -ForegroundColor Green }
function Write-Info($msg)    { Write-Host "  ℹ️  $msg" -ForegroundColor Cyan }
function Write-Warn($msg)    { Write-Host "  ⚠️  $msg" -ForegroundColor Yellow }
function Write-Step($msg)    { Write-Host "`n==> $msg" -ForegroundColor White -BackgroundColor DarkBlue }

Clear-Host
Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║    安全响应引擎 — 一键安装工具      ║" -ForegroundColor Cyan
Write-Host "║    Security Response Engine Setup    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan

# ── 1. 检查 Docker ──
Write-Step "步骤 1/5: 检查 Docker 环境"
try {
    $dockerVer = docker --version 2>&1
    Write-Success "Docker: $dockerVer"
} catch {
    Write-Warn "Docker 未安装！请先安装 Docker Desktop"
    Write-Info "下载地址: https://www.docker.com/products/docker-desktop/"
    exit 1
}

# 检查 Docker Compose
try {
    $composeVer = docker-compose --version 2>&1
    Write-Success "Docker Compose: $composeVer"
} catch {
    Write-Warn "Docker Compose 不可用，请更新 Docker Desktop"
    exit 1
}

# ── 2. 启动 Docker 服务 ──
Write-Step "步骤 2/5: 启动容器服务"
Set-Location $projectRoot
Write-Info "执行: docker-compose up -d"
$result = docker-compose up -d 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Success "容器已启动"
} else {
    Write-Warn "启动过程中可能有警告，继续检查..."
}

# 等待服务就绪
Write-Info "等待后端就绪..."
Start-Sleep 10

# ── 3. 验证服务 ──
Write-Step "步骤 3/5: 验证服务状态"

try {
    $health = Invoke-RestMethod -Uri "http://localhost:8001/api/health" -TimeoutSec 5
    if ($health.status -eq "ok") {
        Write-Success "后端服务: 运行中 (端口 8001)"
        Write-Info "  PostgreSQL: $($health.services.postgres)"
        Write-Info "  Redis:      $($health.services.redis)"
        Write-Info "  LLM:        $($health.services.llm)"
    }
} catch {
    Write-Warn "后端服务未响应，请稍后检查: localhost:8001"
}

try {
    $null = Invoke-WebRequest -Uri "http://localhost:3001" -UseBasicParsing -TimeoutSec 5
    Write-Success "前端服务: 运行中 (端口 3001)"
} catch {
    Write-Warn "前端服务未响应，请稍后检查: localhost:3001"
}

# 显示容器状态
Write-Info "容器状态:"
docker ps --filter "name=shared-memory" --format "table {{.Names}}`t{{.Status}}"

# ── 4. 设置开机自启 ──
Write-Step "步骤 4/5: 设置开机自动启动"

# 创建日志目录
if (!(Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
}

# 复制托盘脚本
Copy-Item $trayScript (Join-Path $logPath "security-tray.ps1") -Force

# 创建隐藏运行脚本 (VBS 隐藏 PowerShell 窗口)
$vbsContent = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ps1Path`"", 0, False
"@
Set-Content -Path $vbsPath -Value $vbsContent -Encoding ASCII

# 创建 PowerShell 启动脚本
$runScript = @"
`$projectRoot = "$projectRoot"
Set-Location `$projectRoot
& "$(Join-Path `$logPath 'security-tray.ps1')"
"@
Set-Content -Path $ps1Path -Value $runScript -Encoding UTF8

# 创建计划任务（开机启动 + 登录时启动）
try {
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($taskExists) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Info "旧计划任务已删除"
    }

    $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited

    Register-ScheduledTask -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "安全响应引擎 — 系统托盘 + 桌面通知" | Out-Null

    Write-Success "开机自启已设置 (计划任务: $taskName)"
    Write-Info "  触发器: 用户登录时启动"
    Write-Info "  脚本: $ps1Path"
} catch {
    Write-Warn "设置计划任务失败: $_"
    Write-Info "请手动运行 tray 脚本: powershell -File `"$trayScript`""
}

# ── 5. 启动系统托盘 ──
Write-Step "步骤 5/5: 启动系统托盘"

# 先检查是否已运行
$existing = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "security-tray"
}
if ($existing) {
    Write-Info "系统托盘已在运行"
} else {
    # 通过 VBS 隐藏启动
    try {
        Start-Process wscript.exe -ArgumentList "`"$vbsPath`"" -WindowStyle Hidden
        Write-Success "系统托盘已启动 (右下角查看)"
        Write-Info "  双击托盘图标 = 打开控制台"
        Write-Info "  右键托盘图标 = 菜单操作"
    } catch {
        Write-Warn "启动托盘失败: $_"
        Write-Info "手动启动: powershell -File `"$trayScript`""
    }
}

# ── 完成 ──
Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║         安装完成！                  ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  控制台: http://localhost:3001       ║" -ForegroundColor Green
Write-Host "║  API:    http://localhost:8001       ║" -ForegroundColor Green
Write-Host "║  托盘:   右下角绿色图标              ║" -ForegroundColor Green
Write-Host "║  通知:   自动弹窗告警                ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Green
Write-Host "`n按任意键关闭此窗口..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
