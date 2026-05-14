#!/usr/bin/env bash
# Advanced Encryption Tool — Test Runner (Linux / macOS)
#
# Usage:
#   chmod +x run_tests.sh
#   ./run_tests.sh
#
# Run from the project root directory (the folder containing src/ and tests/).

set -e

VENV_DIR=".venv"
COV_FLOOR=90
COV_TARGET="src/core"

echo "==> Checking virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

echo "==> Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "==> Running test suite with coverage..."
python -m pytest tests/ \
    --cov="$COV_TARGET" \
    --cov-report=term-missing \
    "--cov-fail-under=$COV_FLOOR" \
    -v \
    --tb=short

echo "==> All tests passed. Coverage floor of ${COV_FLOOR}% met for ${COV_TARGET}."
