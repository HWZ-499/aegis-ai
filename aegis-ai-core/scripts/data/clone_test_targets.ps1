# Aegis AI 实测目标一键克隆脚本（Windows PowerShell）
# 用法：在希望存放项目的目录执行，或指定 -BaseDir
# 示例：cd C:\ ; .\aegis-ai-core\scripts\clone_test_targets.ps1
#       .\aegis-ai-core\scripts\clone_test_targets.ps1 -BaseDir D:\AegisTargets

param(
    [string]$BaseDir = "C:\AegisTestTargets"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null
Set-Location $BaseDir

Write-Host "目标目录: $BaseDir" -ForegroundColor Cyan

if (-not (Test-Path "NodeGoat")) {
    Write-Host "正在克隆 NodeGoat ..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/OWASP/NodeGoat.git
    Write-Host "NodeGoat 已克隆到 $BaseDir\NodeGoat" -ForegroundColor Green
} else {
    Write-Host "NodeGoat 已存在，跳过克隆" -ForegroundColor Gray
}

if (-not (Test-Path "juice-shop")) {
    Write-Host "正在克隆 Juice Shop（体积较大，请稍候）..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/juice-shop/juice-shop.git
    Write-Host "Juice Shop 已克隆到 $BaseDir\juice-shop" -ForegroundColor Green
} else {
    Write-Host "juice-shop 已存在，跳过克隆" -ForegroundColor Gray
}

if (-not (Test-Path "vulnerable-nodejs-express-mysql")) {
    Write-Host "正在克隆 vulnerable-nodejs-express-mysql（小型 Express 示例）..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/stypr/vulnerable-nodejs-express-mysql.git
    Write-Host "vulnerable-nodejs-express-mysql 已克隆到 $BaseDir\vulnerable-nodejs-express-mysql" -ForegroundColor Green
} else {
    Write-Host "vulnerable-nodejs-express-mysql 已存在，跳过克隆" -ForegroundColor Gray
}

if (-not (Test-Path "DVWA")) {
    Write-Host "正在克隆 DVWA（PHP 真实项目评估目标）..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/digininja/DVWA.git
    Write-Host "DVWA 已克隆到 $BaseDir\DVWA" -ForegroundColor Green
} else {
    Write-Host "DVWA 已存在，跳过克隆" -ForegroundColor Gray
}

if (-not (Test-Path "java-webapp-security-lab")) {
    Write-Host "正在克隆 Java WebApp Security Lab（Java pilot 评估目标）..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/DularaAbhiranda/WebApp-Security-Vulnerabilities-Lab.git java-webapp-security-lab
    Write-Host "java-webapp-security-lab 已克隆到 $BaseDir\java-webapp-security-lab" -ForegroundColor Green
} else {
    Write-Host "java-webapp-security-lab 已存在，跳过克隆" -ForegroundColor Gray
}

if (-not (Test-Path "go-insecure-web-app")) {
    Write-Host "正在克隆 Go Insecure Web App（Go pilot 评估目标）..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/Emin-F/Go-Insecure-Web-APP.git go-insecure-web-app
    Write-Host "go-insecure-web-app 已克隆到 $BaseDir\go-insecure-web-app" -ForegroundColor Green
} else {
    Write-Host "go-insecure-web-app 已存在，跳过克隆" -ForegroundColor Gray
}

Write-Host ""
Write-Host "克隆完成。在 aegis-ai-core 目录下执行扫描示例：" -ForegroundColor Cyan
Write-Host "  python -m src.scanner.cli `"$BaseDir\NodeGoat`" --engine new -o reports/nodegoat-report.html -v" -ForegroundColor White
Write-Host "  python -m src.scanner.cli `"$BaseDir\juice-shop`" --engine new -o reports/juice-shop-report.html -v" -ForegroundColor White
Write-Host "  python -m src.scanner.cli `"$BaseDir\vulnerable-nodejs-express-mysql`" --engine new -o reports/vuln-express-report.html -v" -ForegroundColor White
Write-Host "  python scripts/run_benchmark_report.py --project-dir `"$BaseDir\juice-shop`"" -ForegroundColor White
Write-Host "  python scripts/benchmark/evaluate_project.py --project-dir `"$BaseDir\DVWA`" --ground-truth scripts/data/ground_truth_dvwa.json" -ForegroundColor White
Write-Host "  python scripts/benchmark/evaluate_project.py --project-dir `"$BaseDir\java-webapp-security-lab\java-deserialization-demo`" --ground-truth scripts/data/ground_truth_java_deserialization_demo.json" -ForegroundColor White
Write-Host "  python scripts/benchmark/evaluate_project.py --project-dir `"$BaseDir\go-insecure-web-app`" --ground-truth scripts/data/ground_truth_go_insecure_web_app.json" -ForegroundColor White
