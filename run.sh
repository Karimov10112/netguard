#!/usr/bin/env bash
# NetGuard — Linux/macOS uchun ishga tushirish
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
if ! python -c "from netguard.models import Detector; from netguard.features import FeatureExtractor, Conn; d=Detector(); d.score([FeatureExtractor().features(Conn(ts=1, src='10.0.10.5', sport=50000, dst='10.0.2.10', dport=80))]); d.full" 2>/dev/null; then
  echo "Modellar yuklanmadi — qayta o‘qitiladi (5–10 daqiqa)..."
  python train/download_data.py && python train/train_models.py && python train/train_profile.py
fi
echo "SOC konsoli: http://127.0.0.1:5000"
python app.py
