# NexusGuard AI — Start AI Service (Python FastAPI)
# Run from the "AI Integration" directory:
#   powershell -ExecutionPolicy Bypass -File start_ai_service.ps1

Write-Host ""
Write-Host "🤖  NexusGuard AI Service — Starting..." -ForegroundColor Cyan
Write-Host ""

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌  Python not found. Please install Python 3.10+." -ForegroundColor Red
    exit 1
}

# Check uvicorn
$uvicornCheck = python -c "import uvicorn" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "📦  Installing Python dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌  pip install failed. Check requirements.txt." -ForegroundColor Red
        exit 1
    }
}

Write-Host "✅  Dependencies ready." -ForegroundColor Green
Write-Host ""
Write-Host "   Health  : http://localhost:8000/health" -ForegroundColor Gray
Write-Host "   API     : POST http://localhost:8000/api/ai/generate-patch" -ForegroundColor Gray
Write-Host ""

# Load .env from the AI Integration dir if it exists, else fall back to backend/.env
$envFile = ".env"
if (-not (Test-Path $envFile)) {
    $envFile = "..\backend\.env"
    Write-Host "WARNING: No local .env found - using backend .env" -ForegroundColor Yellow
}

# Start the FastAPI server
python -m uvicorn ai_service:app --host 0.0.0.0 --port 8000 --reload
