# NexusGuard AI - Root Launcher
# Starts: AI Service (8000) | Backend (3000) | Frontend (3001)
# Usage:  powershell -ExecutionPolicy Bypass -File start.ps1

$root        = Split-Path -Parent $MyInvocation.MyCommand.Path
$aiDir       = Join-Path $root "AI Integration"
$backendDir  = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "   NexusGuard AI  --  Full Stack Launcher        " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] node not found. Install Node.js 20+." -ForegroundColor Red; exit 1
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] python not found. Install Python 3.10+." -ForegroundColor Red; exit 1
}

$envFile = Join-Path $backendDir ".env"
if (-not (Test-Path $envFile)) {
    $example = Join-Path $backendDir ".env.example"
    if (Test-Path $example) {
        Copy-Item $example $envFile
        Write-Host "[WARN] Copied .env.example -> backend\.env  -- fill in your keys!" -ForegroundColor Yellow
    } else {
        Write-Host "[ERROR] backend\.env not found." -ForegroundColor Red; exit 1
    }
}

if (-not (Test-Path (Join-Path $backendDir "node_modules"))) {
    Write-Host "[INFO] Installing backend node_modules..." -ForegroundColor Yellow
    Push-Location $backendDir
    npm install
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "[ERROR] npm install failed (backend)" -ForegroundColor Red; exit 1 }
    Pop-Location
    Write-Host "[OK] Backend dependencies ready." -ForegroundColor Green
}

if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Write-Host "[INFO] Installing frontend node_modules..." -ForegroundColor Yellow
    Push-Location $frontendDir
    npm install
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "[ERROR] npm install failed (frontend)" -ForegroundColor Red; exit 1 }
    Pop-Location
    Write-Host "[OK] Frontend dependencies ready." -ForegroundColor Green
}

$reqFile = Join-Path $aiDir "requirements.txt"
if (Test-Path $reqFile) {
    python -c "import uvicorn" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[INFO] Installing Python dependencies..." -ForegroundColor Yellow
        pip install -r $reqFile
        if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] pip install failed" -ForegroundColor Red; exit 1 }
        Write-Host "[OK] Python dependencies ready." -ForegroundColor Green
    }
}

function Free-Port {
    param([int]$Port)
    $ids = netstat -ano 2>$null |
           Select-String (":$Port ") |
           ForEach-Object { ($_ -split "\s+")[-1] } |
           Where-Object { $_ -match "^\d+$" } |
           Sort-Object -Unique
    foreach ($id in $ids) {
        try {
            Stop-Process -Id ([int]$id) -Force -ErrorAction SilentlyContinue
            Write-Host "[INFO] Freed port $Port (PID $id)" -ForegroundColor Yellow
        } catch {}
    }
}

Write-Host "[INFO] Checking ports..." -ForegroundColor Cyan
Free-Port 8000
Free-Port 3000
Free-Port 3001
Write-Host ""

Write-Host "[START] AI Service  -> http://localhost:8000" -ForegroundColor Green
$aiEsc  = $aiDir -replace "'", "''"
Start-Process powershell -ArgumentList @("-NoExit","-Command","Set-Location '$aiEsc'; Write-Host '[AI Service]' -ForegroundColor Cyan; python -m uvicorn ai_service:app --host 0.0.0.0 --port 8000 --reload")
Start-Sleep -Seconds 2

Write-Host "[START] Backend     -> http://localhost:3000" -ForegroundColor Green
$beEsc  = $backendDir -replace "'", "''"
Start-Process powershell -ArgumentList @("-NoExit","-Command","Set-Location '$beEsc'; Write-Host '[Backend]' -ForegroundColor Yellow; node --env-file=.env server.js")
Start-Sleep -Seconds 2

Write-Host "[START] Frontend    -> http://localhost:3001" -ForegroundColor Green
$feEsc  = $frontendDir -replace "'", "''"
Start-Process powershell -ArgumentList @("-NoExit","-Command","Set-Location '$feEsc'; Write-Host '[Frontend]' -ForegroundColor Magenta; npm run dev")

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  All 3 services launched in separate windows.   " -ForegroundColor White
Write-Host "  Frontend  : http://localhost:3001              " -ForegroundColor White
Write-Host "  Backend   : http://localhost:3000              " -ForegroundColor White
Write-Host "  AI Svc    : http://localhost:8000              " -ForegroundColor White
Write-Host "  Close each terminal window to stop a service.  " -ForegroundColor Gray
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""