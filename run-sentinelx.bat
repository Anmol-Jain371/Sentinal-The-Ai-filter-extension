@echo off
title SentinelX System Controller
cls
echo ====================================================================
echo                   SENTINELX SYSTEM LAUNCHER
echo ====================================================================
echo.
echo [1/3] Starting SentinelX Backend on http://localhost:8000...
start /B "" python -m uvicorn main:app --app-dir "%~dp0backend" --port 8000

:: Give the server 2 seconds to initialize
timeout /t 2 /nobreak >nul

echo [2/2] Opening SentinelX Security Test Lab (http://localhost:8000/test)...
start "" "http://localhost:8000/test/"

echo.
echo ====================================================================
echo                     READY FOR TESTING!
echo ====================================================================
echo.
echo HOW TO TEST IN 3 QUICK STEPS:
echo.
echo STEP 1: Make sure the extension is loaded in Chrome / Edge:
echo         - Open chrome://extensions
echo         - Turn on 'Developer mode' (top right)
echo         - Click 'Load unpacked' and pick:
echo           %~dp0extension
echo.
echo STEP 2: On the Test Harness page (http://localhost:8000/test):
echo         - Click [AWS Credentials] on the left side.
echo           (This copies a sensitive API key to your clipboard).
echo.
echo STEP 3: Click inside the 'AI Chat / Prompt Input' box and press Ctrl+V:
echo         - SentinelX will IMMEDIATELY popup right over the box!
echo         - Click [Redact ^& Paste] to sanitize the secret.
echo.
echo Check the SOC Dashboard tab to see the threat logged in real-time!
echo.
echo ====================================================================
echo Press any key to stop backend or close this window when done...
pause >nul
