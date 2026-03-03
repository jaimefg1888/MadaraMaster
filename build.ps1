# build.ps1 — MadaraMaster release builder
# ─────────────────────────────────────────────────────────────────────────────
# Run from the project root in an ELEVATED PowerShell session:
#
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\build.ps1
#
# What it does:
#   1. Creates (or reuses) a clean virtual environment in .venv\
#   2. Installs all runtime and build dependencies
#   3. Runs PyInstaller with MadaraMaster.spec
#   4. Copies the finished .exe to the project root for easy upload to GitHub
#
# Output: MadaraMaster.exe in the project root
# ─────────────────────────────────────────────────────────────────────────────

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = $PSScriptRoot
$VenvDir     = Join-Path $ProjectRoot '.venv'
$Python      = 'python'          # must be Python 3.10+ on PATH
$DistExe     = Join-Path $ProjectRoot 'dist\MadaraMaster.exe'
$ReleaseExe  = Join-Path $ProjectRoot 'MadaraMaster.exe'

Write-Host ''
Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '  MadaraMaster — Release Builder' -ForegroundColor Cyan
Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''

# ── 1. Virtual environment ─────────────────────────────────────────────────
if (-Not (Test-Path $VenvDir)) {
    Write-Host '[1/4] Creating virtual environment...' -ForegroundColor Yellow
    & $Python -m venv $VenvDir
} else {
    Write-Host '[1/4] Virtual environment already exists, reusing.' -ForegroundColor Green
}

$PipExe = Join-Path $VenvDir 'Scripts\pip.exe'
$PyExe  = Join-Path $VenvDir 'Scripts\python.exe'

# ── 2. Dependencies ───────────────────────────────────────────────────────
Write-Host '[2/4] Installing dependencies...' -ForegroundColor Yellow
& $PipExe install --upgrade pip --quiet
& $PipExe install -r (Join-Path $ProjectRoot 'requirements.txt') --quiet
& $PipExe install 'pyinstaller>=6.0' --quiet

# ── 3. PyInstaller ────────────────────────────────────────────────────────
Write-Host '[3/4] Running PyInstaller...' -ForegroundColor Yellow
Set-Location $ProjectRoot

$PyInstallerExe = Join-Path $VenvDir 'Scripts\pyinstaller.exe'
& $PyInstallerExe `
    MadaraMaster.spec `
    --clean `
    --noconfirm

if (-Not (Test-Path $DistExe)) {
    Write-Host ''
    Write-Host '  ERROR: Build failed — dist\MadaraMaster.exe not found.' -ForegroundColor Red
    exit 1
}

# ── 4. Copy to project root ────────────────────────────────────────────────
Write-Host '[4/4] Copying executable to project root...' -ForegroundColor Yellow
Copy-Item $DistExe $ReleaseExe -Force

$SizeKB = [math]::Round((Get-Item $ReleaseExe).Length / 1KB)
Write-Host ''
Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Green
Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "  Output : $ReleaseExe" -ForegroundColor Green
Write-Host "  Size   : $SizeKB KB" -ForegroundColor Green
Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Green
Write-Host ''
Write-Host '  Next steps:'
Write-Host '    1. Test: .\MadaraMaster.exe --help'
Write-Host '    2. Tag : git tag v4.0.0 && git push origin v4.0.0'
Write-Host '    3. Upload MadaraMaster.exe to the GitHub Release'
Write-Host ''
