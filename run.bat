@echo off
cd /d "%~dp0"
set PY=python
where py >nul 2>nul && set PY=py -3
%PY% -c "import tkintermapview" 2>nul
if errorlevel 1 (
  echo Installing dependencies from requirements.txt ...
  %PY% -m pip install -r requirements.txt
  if errorlevel 1 ( pause & exit /b 1 )
)
%PY% main.py %*
if errorlevel 1 pause
