@echo off
cd /d %~dp0
echo NetGuard backend: http://127.0.0.1:5000
python -m backend.server
