#!/bin/sh
set -eu
cd "$(dirname "$0")"
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
exec .venv/bin/python p2peeonme.py gui
