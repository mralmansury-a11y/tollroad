@echo off
chcp 65001 >nul
title Toll Road Services Management
cd /d "%~dp0"

set PY=
where python >nul 2>nul && set PY=python
if "%PY%"=="" ( where py >nul 2>nul && set PY=py )
if "%PY%"=="" (
    echo [ERROR] Python was not found. Install Python 3.9+ from python.org and tick "Add to PATH".
    pause
    exit /b 1
)

%PY% -c "import flask" >nul 2>nul
if errorlevel 1 (
    echo Installing Flask ...
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Could not install Flask. Check your internet connection and run again.
        pause
        exit /b 1
    )
)

%PY% app.py
pause
