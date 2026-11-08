"""NSL-KDD datasetini yuklab olish (data/nsl-kdd/): KDDTrain+.txt, KDDTest+.txt, KDDTest-21.txt.

Manba: Kanada kiberxavfsizlik instituti (UNB CIC) NSL-KDD; GitHub nusxasi defcom17/NSL_KDD.
"""
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "nsl-kdd")
BASE = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
FILES = ["KDDTrain+.txt", "KDDTest+.txt", "KDDTest-21.txt"]

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for f in FILES:
        path = os.path.join(OUT, f)
        if os.path.exists(path) and os.path.getsize(path) > 1000:
            print(f"bor: {f}")
            continue
        print(f"yuklanmoqda: {f}")
        try:
            urllib.request.urlretrieve(BASE + f, path)
        except Exception as e:  # noqa: BLE001
            sys.exit(f"Xato: {e}\nFaylni qo‘lda yuklab, {OUT} papkasiga qo‘ying: https://www.unb.ca/cic/datasets/nsl.html")
    print("Tayyor:", OUT)
