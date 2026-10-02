# EmpMonitor Agent Silent Installer
# Install: powershell -ExecutionPolicy Bypass -Command "irm http://139.64.178.194/agent/install.ps1 | iex"

$ErrorActionPreference = "SilentlyContinue"
$ServerURL = "http://139.64.178.194"
$InstallDir = "C:\ProgramData\EmpMonitor"
$PythonDir = "$InstallDir\python"
$PythonZipURL = "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip"
$GetPipURL = "https://bootstrap.pypa.io/get-pip.py"

Write-Host ""
Write-Host "=== EmpMonitor Agent Setup ===" -ForegroundColor Cyan
Write-Host ""

# --- Create directories ---
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $PythonDir -Force | Out-Null

# --- Step 1: Portable Python ---
$pythonExe = "$PythonDir\python.exe"
$pythonwExe = "$PythonDir\pythonw.exe"

if (!(Test-Path $pythonExe)) {
    Write-Host "[1/5] Downloading portable Python..." -ForegroundColor Yellow
    $zipFile = "$env:TEMP\python-embed.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $PythonZipURL -OutFile $zipFile -UseBasicParsing
        Expand-Archive -Path $zipFile -DestinationPath $PythonDir -Force
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue

        # Enable pip support in embedded Python
        $pthFile = Get-ChildItem "$PythonDir\python*._pth" | Select-Object -First 1
        if ($pthFile) {
            (Get-Content $pthFile.FullName) -replace '#import site', 'import site' | Set-Content $pthFile.FullName
        }
        Write-Host "       Done" -ForegroundColor Green
    } catch {
        Write-Host "       Failed: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[1/5] Python ready" -ForegroundColor Green
}

# --- Step 2: Install pip ---
if (!(Test-Path "$PythonDir\Scripts\pip.exe")) {
    Write-Host "[2/5] Setting up pip..." -ForegroundColor Yellow
    try {
        $getPipFile = "$env:TEMP\get-pip.py"
        Invoke-WebRequest -Uri $GetPipURL -OutFile $getPipFile -UseBasicParsing
        & $pythonExe $getPipFile --no-warn-script-location 2>&1 | Out-Null
        Remove-Item $getPipFile -Force -ErrorAction SilentlyContinue
        Write-Host "       Done" -ForegroundColor Green
    } catch {
        Write-Host "       Warning: pip setup issue" -ForegroundColor Yellow
    }
} else {
    Write-Host "[2/5] Pip ready" -ForegroundColor Green
}

# --- Step 3: Download agent ---
Write-Host "[3/5] Downloading agent..." -ForegroundColor Yellow
$files = @("agent.py", "requirements.txt", "config.json")
foreach ($f in $files) {
    try {
        Invoke-WebRequest -Uri "$ServerURL/agent/$f" -OutFile "$InstallDir\$f" -UseBasicParsing
    } catch {}
}
Write-Host "       Done" -ForegroundColor Green

# --- Step 4: Install dependencies ---
Write-Host "[4/5] Installing dependencies..." -ForegroundColor Yellow
$pipExe = "$PythonDir\Scripts\pip.exe"
if (Test-Path "$InstallDir\requirements.txt") {
    if (Test-Path $pipExe) {
        & $pipExe install -r "$InstallDir\requirements.txt" --no-warn-script-location 2>&1 | Out-Null
    } else {
        & $pythonExe -m pip install -r "$InstallDir\requirements.txt" --no-warn-script-location 2>&1 | Out-Null
    }
}
Write-Host "       Done" -ForegroundColor Green

# --- Step 5: Auto-start + Launch ---
Write-Host "[5/5] Configuring auto-start..." -ForegroundColor Yellow
if (!(Test-Path $pythonwExe)) { $pythonwExe = $pythonExe }

$taskName = "EmpMonitor"
try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}

$action = New-ScheduledTaskAction -Execute "`"$pythonwExe`"" -Argument "`"$InstallDir\agent.py`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "EmpMonitor Agent" -Force | Out-Null

try {
    Start-Process -FilePath $pythonwExe -ArgumentList "`"$InstallDir\agent.py`"" -WindowStyle Hidden
} catch {}
Write-Host "       Done" -ForegroundColor Green

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
