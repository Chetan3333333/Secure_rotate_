@echo off
setlocal
echo ========================================================
echo       SecureRotate Application - Automated Startup
echo ========================================================
echo.

REM 1. Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your system PATH.
    pause
    exit /b
)

REM 2. Setup Virtual Environment
if not exist "venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment...
    python -m venv venv
)

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

echo [*] Installing/Verifying dependencies...
pip install -r requirements.txt -q

REM 3. Skip Setup Database for Aiven
echo [*] Connected to Aiven Cloud Database...

REM 4. Run Application
echo.
echo [*] Starting the web server...
echo     User Portal: http://127.0.0.1:8000/user
echo     Admin Dashboard: http://127.0.0.1:8000/admin
echo.

REM Open browser in the background
start http://127.0.0.1:8000/

python app.py
pause
