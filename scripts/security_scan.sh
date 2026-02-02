#!/usr/bin/env bash
set -euo pipefail

python -m pip install --upgrade pip >/dev/null
python -m pip install -q pip-audit bandit
python -m pip install -q "semgrep>=1.0.0"

echo "==> pip-audit"
pip-audit

echo "==> bandit"
bandit -c bandit.yaml -r src -ll

echo "==> semgrep"
semgrep --config p/ci --error --metrics=off
