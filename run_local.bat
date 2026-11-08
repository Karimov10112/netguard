@echo off
setlocal
cd /d %~dp0

set "PYTHON=python"
if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PYTHON=%LocalAppData%\Programs\Python\Python313\python.exe"
if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set "PYTHON=%LocalAppData%\Programs\Python\Python312\python.exe"
if exist "%LocalAppData%\Programs\Python\Python311\python.exe" set "PYTHON=%LocalAppData%\Programs\Python\Python311\python.exe"

if "%PYTHON%"=="python" (
  where python >nul 2>nul
  if errorlevel 1 (
    echo Python topilmadi. Python 3.10+ o'rnating yoki PATH ga qo'shing.
    pause
    exit /b 1
  )
)

echo NetGuard lokal rejimda ishga tushmoqda...
echo Backend:  http://127.0.0.1:5000
echo Frontend: http://127.0.0.1:5173

start "NetGuard Backend" /D "%~dp0" "%PYTHON%" -m backend.server
timeout /t 2 /nobreak >nul
start "NetGuard Frontend" /D "%~dp0frontend" "%PYTHON%" -m http.server 5173 --bind 127.0.0.1
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:5173

echo.
echo Brauzer ochildi. To'xtatish uchun ochilgan ikkita oynani yoping.
endlocal
