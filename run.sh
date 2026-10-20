#!/bin/sh
# Запуск TracertMap в Linux / macOS
cd "$(dirname "$0")"
python3 -c "import tkinter" 2>/dev/null || { echo "Нужен tkinter: sudo apt install python3-tk (Debian/Ubuntu)"; exit 1; }
python3 -c "import tkintermapview" 2>/dev/null || python3 -m pip install --user -r requirements.txt || exit 1
exec python3 main.py "$@"
