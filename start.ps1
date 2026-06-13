# NexusGuard AI — Root Launcher
# Starts BOTH services needed for the full pipeline:
#   1. Python FastAPI AI Service   (port 8000)
#   2. Node.js Backend Server      (port 3000)
#
# Run from the project root:
#   powershell -ExecutionPolicy Bypass -File start.ps1

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       NexusGuard AI — Full Stack Launcher         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$aiDir = Join-Path $root "AI Integration"
$backendDir = Join-Path $root "backend"

# ── Check prerequisites ────────────────────────────────────────
if (-not (Test-Path (Join-Path $backendDir ".env"))) {
    Write-Host "❌  backend\.env not found." -ForegroundColor Red
    Write-Host "   Copy backend\.env.example to backend\.env and fill in your keys." -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path (Join-Path $backendDir "node_modules"))) {
    Write-Host "📦  Installing Node.js backend dependencies..." -ForegroundColor Yellow
    Push-Location $backendDir
    npm install
    Pop-Location
}

# ── Start Python AI Service in a new window ────────────────────
Write-Host "🚀  Starting Python AI Service (port 8000)..." -ForegroundColor Green
$aiProcess = Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$aiDir'; Write-Host '🤖 AI Service' -ForegroundColor Cyan; python -m uvicorn ai_service:app --host 0.0.0.0 --port 8000 --reload"
) -PassThru

Start-Sleep -Seconds 3

# ── Start Node.js Backend ──────────────────────────────────────
Write-Host "🚀  Starting Node.js Backend (port 3000)..." -ForegroundColor Green
Write-Host ""
Write-Host "   Backend  : http://localhost:3000" -ForegroundColor Gray
Write-Host "   Health   : http://localhost:3000/health" -ForegroundColor Gray
Write-Host "   Web3     : http://localhost:3000/api/web3/health" -ForegroundColor Gray
Write-Host "   AI Svc   : http://localhost:8000/health" -ForegroundColor Gray
Write-Host "   WebSocket: ws://localhost:3000" -ForegroundColor Gray
Write-Host ""
Write-Host "   Press Ctrl+C to stop the Node.js backend." -ForegroundColor Gray
Write-Host "   Close the AI Service window to stop the Python server." -ForegroundColor Gray
Write-Host ""

Push-Location $backendDir
node --env-file=.env server.js
Pop-Location
