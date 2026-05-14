# Advanced Encryption Tool — Test Runner (Windows PowerShell)
#
# Usage:
#   .\run_tests.ps1
#
# Run from the project root directory (the folder containing src\ and tests\).

$ErrorActionPreference = "Stop"

$VenvDir   = ".venv"
$CovFloor  = 90
$CovTarget = "src/core"

Write-Host "==> Checking virtual environment..." -ForegroundColor Cyan
if (-not (Test-Path $VenvDir)) {
    python -m venv $VenvDir
}

& "$VenvDir\Scripts\Activate.ps1"

Write-Host "==> Installing dependencies..." -ForegroundColor Cyan
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

Write-Host "==> Running test suite with coverage..." -ForegroundColor Cyan
python -m pytest tests/ `
    "--cov=$CovTarget" `
    --cov-report=term-missing `
    "--cov-fail-under=$CovFloor" `
    -v `
    --tb=short

Write-Host "==> All tests passed. Coverage floor of $CovFloor% met for $CovTarget." -ForegroundColor Green
