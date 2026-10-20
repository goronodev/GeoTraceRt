@echo off
REM Build a single TracertMap.exe (needs Python + pip)
cd /d "%~dp0"
set PY=python
where py >nul 2>nul && set PY=py -3
%PY% -m pip install -r requirements.txt pyinstaller
%PY% -m PyInstaller --noconfirm --onefile --windowed --name TracertMap --collect-all tkintermapview --add-data "samples;samples" main.py
echo.
echo Done: dist\TracertMap.exe
pause
