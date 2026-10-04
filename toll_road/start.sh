#!/usr/bin/env bash
cd "$(dirname "$0")"
python3 -c "import flask" 2>/dev/null || python3 -m pip install -r requirements.txt
python3 app.py
