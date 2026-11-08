@echo off
setlocal
cd /d %~dp0
echo NetGuard frontend: http://127.0.0.1:5173
python -m http.server 5173 --bind 127.0.0.1 --directory "%~dp0frontend"
endlocal
