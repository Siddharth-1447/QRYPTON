# Start the local UI and API together; keep both alive after this shell exits.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
$webPath = Join-Path $projectRoot 'web'
$nextPath = Join-Path $webPath 'node_modules\next\dist\bin\next'
$logPath = Join-Path $projectRoot 'tmp\dev-servers'

foreach ($dependency in @($pythonPath, $nextPath)) {
    if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) {
        throw "Missing dependency: $dependency. Install the Python and web dependencies first."
    }
}
$nodePath = (Get-Command node -ErrorAction Stop).Source
New-Item -ItemType Directory -Path $logPath -Force | Out-Null

function Start-LocalService {
    param([string]$Name, [int]$Port, [string]$Executable, [string[]]$Arguments, [string]$Directory, [string]$ReadyUrl)
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    $started = $null
    if (-not $listener) {
        $started = Start-Process -FilePath $Executable -ArgumentList $Arguments -WorkingDirectory $Directory `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $logPath "$Name.out.log") `
            -RedirectStandardError (Join-Path $logPath "$Name.err.log")
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        if ($started -and $started.HasExited) {
            throw "$Name exited with code $($started.ExitCode). See $logPath\$Name.err.log."
        }
        try {
            $response = Invoke-WebRequest -Uri $ReadyUrl -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-Output "$Name ready at $ReadyUrl"
                return
            }
        } catch {
            # A newly started server can refuse connections while importing or compiling.
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$Name did not become ready on port $Port. Check the listener and logs in $logPath."
}

Start-LocalService -Name 'api' -Port 8000 -Executable $pythonPath `
    -Arguments @('-m', 'uvicorn', 'qrypton.api.app:app', '--host', '127.0.0.1', '--port', '8000') `
    -Directory $projectRoot -ReadyUrl 'http://127.0.0.1:8000/openapi.json'
Start-LocalService -Name 'web' -Port 3000 -Executable $nodePath `
    -Arguments @(('"{0}"' -f $nextPath), 'dev', '--webpack', '--hostname', '127.0.0.1', '--port', '3000') `
    -Directory $webPath -ReadyUrl 'http://localhost:3000/'
Write-Output "Open http://localhost:3000/. Logs: $logPath"
