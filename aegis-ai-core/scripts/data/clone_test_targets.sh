#!/usr/bin/env bash
# Aegis AI 实测目标一键克隆脚本（Mac/Linux）
# 用法：chmod +x scripts/clone_test_targets.sh && ./scripts/clone_test_targets.sh
#       或指定目录：BASE_DIR=/tmp/targets ./scripts/clone_test_targets.sh

set -e
BASE_DIR="${BASE_DIR:-$HOME/AegisTestTargets}"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

echo "目标目录: $BASE_DIR"

if [ ! -d "NodeGoat" ]; then
  echo "正在克隆 NodeGoat ..."
  git clone --depth 1 https://github.com/OWASP/NodeGoat.git
  echo "NodeGoat 已克隆到 $BASE_DIR/NodeGoat"
else
  echo "NodeGoat 已存在，跳过克隆"
fi

if [ ! -d "juice-shop" ]; then
  echo "正在克隆 Juice Shop（体积较大，请稍候）..."
  git clone --depth 1 https://github.com/juice-shop/juice-shop.git
  echo "Juice Shop 已克隆到 $BASE_DIR/juice-shop"
else
  echo "juice-shop 已存在，跳过克隆"
fi

if [ ! -d "vulnerable-nodejs-express-mysql" ]; then
  echo "正在克隆 vulnerable-nodejs-express-mysql（小型 Express 示例）..."
  git clone --depth 1 https://github.com/stypr/vulnerable-nodejs-express-mysql.git
  echo "vulnerable-nodejs-express-mysql 已克隆到 $BASE_DIR/vulnerable-nodejs-express-mysql"
else
  echo "vulnerable-nodejs-express-mysql 已存在，跳过克隆"
fi

if [ ! -d "DVWA" ]; then
  echo "正在克隆 DVWA（PHP 真实项目评估目标）..."
  git clone --depth 1 https://github.com/digininja/DVWA.git
  echo "DVWA 已克隆到 $BASE_DIR/DVWA"
else
  echo "DVWA 已存在，跳过克隆"
fi

if [ ! -d "java-webapp-security-lab" ]; then
  echo "正在克隆 Java WebApp Security Lab（Java pilot 评估目标）..."
  git clone --depth 1 https://github.com/DularaAbhiranda/WebApp-Security-Vulnerabilities-Lab.git java-webapp-security-lab
  echo "java-webapp-security-lab 已克隆到 $BASE_DIR/java-webapp-security-lab"
else
  echo "java-webapp-security-lab 已存在，跳过克隆"
fi

if [ ! -d "go-insecure-web-app" ]; then
  echo "正在克隆 Go Insecure Web App（Go pilot 评估目标）..."
  git clone --depth 1 https://github.com/Emin-F/Go-Insecure-Web-APP.git go-insecure-web-app
  echo "go-insecure-web-app 已克隆到 $BASE_DIR/go-insecure-web-app"
else
  echo "go-insecure-web-app 已存在，跳过克隆"
fi

echo ""
echo "克隆完成。在 aegis-ai-core 目录下执行扫描示例："
echo "  python -m src.scanner.cli \"$BASE_DIR/NodeGoat\" --engine new -o reports/nodegoat-report.html -v"
echo "  python -m src.scanner.cli \"$BASE_DIR/juice-shop\" --engine new -o reports/juice-shop-report.html -v"
echo "  python -m src.scanner.cli \"$BASE_DIR/vulnerable-nodejs-express-mysql\" --engine new -o reports/vuln-express-report.html -v"
echo "  python scripts/run_benchmark_report.py --project-dir \"$BASE_DIR/juice-shop\""
echo "  python scripts/benchmark/evaluate_project.py --project-dir \"$BASE_DIR/DVWA\" --ground-truth scripts/data/ground_truth_dvwa.json"
echo "  python scripts/benchmark/evaluate_project.py --project-dir \"$BASE_DIR/java-webapp-security-lab/java-deserialization-demo\" --ground-truth scripts/data/ground_truth_java_deserialization_demo.json"
echo "  python scripts/benchmark/evaluate_project.py --project-dir \"$BASE_DIR/go-insecure-web-app\" --ground-truth scripts/data/ground_truth_go_insecure_web_app.json"
