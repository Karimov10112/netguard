@echo off
chcp 65001 >nul
cd /d %~dp0
if not exist .venv (
  echo [1/4] Virtual muhit yaratilmoqda...
  python -m venv .venv || (echo Python topilmadi. python.org dan Python 3.10+ o'rnating & pause & exit /b 1)
)
call .venv\Scripts\activate
echo [2/4] Kutubxonalar o'rnatilmoqda...
pip install -q -r requirements.txt
echo [3/4] Modellar tekshirilmoqda...
python -c "from netguard.models import Detector; from netguard.features import FeatureExtractor, Conn; d=Detector(); d.score([FeatureExtractor().features(Conn(ts=1, src='10.0.10.5', sport=50000, dst='10.0.2.10', dport=80))]); d.full" 2>nul
if errorlevel 1 (
  echo Modellar bu kutubxona versiyalarida yuklanmadi - qayta o'qitiladi, 5-10 daqiqa...
  python train\download_data.py
  python train\train_models.py
  python train\train_profile.py
)
echo [4/4] SOC konsoli ishga tushmoqda: http://127.0.0.1:5000
start "" http://127.0.0.1:5000
python app.py
pause
