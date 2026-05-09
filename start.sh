#!/bin/bash
# 3x-ui 兑换码系统启动脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi

if [ -d venv ]; then
    source venv/bin/activate
elif [ -d .venv ]; then
    source .venv/bin/activate
fi

python app.py
