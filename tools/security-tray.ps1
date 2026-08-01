Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$API_BASE = "http://localhost:8001/api"
$LOG_PATH = "$env:LOCALAPPDATA\SecurityEngine\tray.log"
if (!(Test-Path "$env:LOCALAPPDATA\SecurityEngine")) { New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\SecurityEngine" -Force | Out-Null }
function Write-Log($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m" | Out-File $LOG_PATH -Append -Encoding utf8 }
function Api($p) { try { $r = Invoke-WebRequest -Uri "$API_BASE$p" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop; return ($r.Content | ConvertFrom-Json) } catch { return $null } }

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Icon = [System.Drawing.SystemIcons]::Application
$tray.Text = "Security Engine - Starting..."
$tray.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$menu.Items.Add("Dashboard (http://localhost:3001)").add_Click({ Start-Process "http://localhost:3001" })
$menu.Items.Add("Test Notification").add_Click({ $tray.ShowBalloonTip(5000, "Security Engine", "Working OK", [System.Windows.Forms.ToolTipIcon]::Info) })
$menu.Items.Add("-") | Out-Null
$menu.Items.Add("Restart Services").add_Click({
    $tray.ShowBalloonTip(3000, "Security Engine", "Restarting...", [System.Windows.Forms.ToolTipIcon]::Info)
    Start-Process powershell -WindowStyle Hidden -ArgumentList "cd 'D:\JieBangGuaShuai\shared-memory-platform'; docker-compose restart"
})
$menu.Items.Add("Exit").add_Click({ $tray.Visible = $false; [System.Windows.Forms.Application]::Exit() })
$tray.ContextMenuStrip = $menu
$tray.add_MouseDoubleClick({ Start-Process "http://localhost:3001" })

# Show startup notification
$tray.ShowBalloonTip(5000, "Security Response Engine", "Running - monitoring security events", [System.Windows.Forms.ToolTipIcon]::Info)
Write-Log "Started"

# Keep running
[System.Windows.Forms.Application]::Run()
