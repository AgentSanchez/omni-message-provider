#!/usr/bin/env bash
set -euo pipefail

python -m pip install --upgrade pip >/dev/null
python -m pip install -q pip-audit bandit semgrep

echo "==> pip-audit"
pip-audit

echo "==> bandit"
bandit -r src -ll

echo "==> semgrep"
semgrep --config p/ci --error --metrics=off
