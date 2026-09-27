@echo off
echo ========================================================
echo CYBERSENTINEL: Defensive Web Security ^& Posture Auditor
echo Team: Parth Pawar (2024SEPVUGP0021), Aryaman V Saboo (2024SEPVUGP0039)
echo Course: Foundation of Cyber Security (STCS225)
echo Institution: Vijaybhoomi University (VSST)
echo ========================================================
echo.
echo Starting CyberSentinel API ^& Dashboard on http://127.0.0.1:8000 ...

set PYTHON_CMD=python
where python >nul 2>nul
if %errorlevel% neq 0 (
    set PYTHON_CMD="C:\Users\umach\AppData\Local\Programs\Python\Python312\python.exe"
)

start "" http://127.0.0.1:8000
%PYTHON_CMD% -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
pause
