# NetGuard — korxona tarmog‘ida kiberhujumlarni aniqlash va oldini olish tizimi

Diplom loyihasining dasturiy qismi. Tizim diplomning 3-bobida taklif etilgan **to‘rt qatlamli gibrid arxitekturani**
amalga oshiradi:

| Qatlam | Vazifasi | Modullar |
|---|---|---|
| 1. Ma’lumot yig‘ish | Sensor jurnallari | Zeek `conn.log`/`dns.log`, Suricata `eve.json`, Wazuh `alerts.json`, trafik simulyatori |
| 2. Aniqlash | Signatura + ML | C-ilova qoidalari va IoC; **XGBoost** (P_XGB, hujum turi); **Isolation Forest** (S_IF, normal profil) |
| 3. Korrelyatsiya | SIEM | gibrid qoida (3.1), risk balli (3.2), 8 ta korrelyatsiya qoidasi, MITRE ATT&CK, insidentlar |
| 4. Javob | IPS / SOAR | ≥ 0,8 — 24 soatga bloklash / karantin; 0,5–0,8 — SOC; < 0,5 — jurnal; oq ro‘yxat, IDS rejimi, bekor qilish |

```
Ogohlantirish = Sig ∨ [P_XGB ≥ 0,5] ∨ [IF anomaliya]                 (3.1)
Risk = 0,4·S_sig + 0,3·P_XGB + 0,2·S_IF + 0,1·S_aktiv                (3.2)
```

## Tez ishga tushirish

**Windows:** `run_windows.bat` faylini ikki marta bosing. U virtual muhit yaratadi, kutubxonalarni o‘rnatadi,
modellarni tekshiradi va brauzerda http://127.0.0.1:5000 ni ochadi. Python 3.10+ talab qilinadi.

**Linux / macOS:**
```bash
./run.sh
# yoki qo‘lda:
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py
```

So‘ng konsolda **«▶ Barcha sinov hujumlarini simulyatsiya qilish»** tugmasini bosing. Tizim 10 daqiqalik normal korxona
trafigini va 10 ta sinov hujumini (3.10-jadval) tahlil qiladi, insidentlar yaratadi va javob choralarini qo‘llaydi.

## Alohida frontend va backend

Frontend va backend mustaqil ishga tushirilishi mumkin:

1. Backend terminalida `run_backend.bat` ni ishga tushiring (`http://127.0.0.1:5000`).
2. Ikkinchi terminalda `run_frontend.bat` ni ishga tushiring (`http://127.0.0.1:5173`).
3. Brauzerda `http://127.0.0.1:5173` ni oching. Frontend `/api/v1/health`, `/stats`,
   `/incidents`, `/alerts` va `/blocklist` endpointlaridan ma’lumot oladi.

`5173` manzilida repository fayllari ro‘yxati ko‘rinsa, server root papkadan ishga
tushirilgan bo‘ladi. Uni to‘xtatib, `run_frontend.bat` ni ishga tushiring; launcher
frontend papkasini aniq ko‘rsatib beradi.

Yoki Windows’da [run_local.bat](./run_local.bat) faylini ikki marta bosing:
u backend, frontend va brauzerni lokal (`127.0.0.1`) rejimda avtomatik ochadi.

`frontend/` faqat statik HTML/CSS/JavaScript bo‘lib, uni alohida hostingga joylashtirish mumkin.
`backend/` esa mavjud Flask domen mantiqi va REST API uchun alohida ishga tushirish nuqtasidir.
Agar `NETGUARD_API_KEY` ishlatilsa, frontenddagi **API kalit** maydoniga shu qiymatni kiriting.
Frontend boshqa host yoki portda joylashsa, backend CORS manzilini
`NETGUARD_FRONTEND_ORIGIN` orqali belgilang.

### Vercel + Render deploy

Ishlaydigan internet deploy uchun backendni Render, frontendni Vercel’ga joylashtiring:

1. Repository’ni GitHub’ga push qiling.
2. Render’da **New Web Service** ochib repository’ni tanlang. `render.yaml` dagi
   sozlamalar avtomatik ishlatiladi. `NETGUARD_FRONTEND_ORIGIN` qiymatini Vercel
   domeniga, `NETGUARD_API_KEY` qiymatini esa o‘zingiz yaratgan maxfiy kalitga qo‘ying.
3. Vercel’da **Import Project** qilib, **Root Directory** sifatida `frontend` ni
   tanlang va deploy qiling.
4. Vercel sahifasidagi **API URL** maydoniga Render bergan
   `https://netguard-backend.onrender.com` manzilini, API kaliti maydoniga esa
   Render’dagi `NETGUARD_API_KEY` qiymatini kiriting.

Render bepul rejimda uzoq vaqt ishlatilmaganda uxlaydi; birinchi so‘rov 30–60 soniya
kechikishi mumkin. SQLite ma’lumotlari bepul rejim qayta ishga tushganda saqlanmasligi
mumkin, shuning uchun bu sozlama demo va diplom taqdimoti uchun mo‘ljallangan.

## Veb-konsol (SOC) sahifalari

- **Boshqaruv paneli** — KPI (ulanishlar, ogohlantirishlar, ochiq insidentlar, faol bloklashlar, IPS to‘xtatgan ulanishlar, MTTD/MTTR), trafik grafigi, eng xavfli manbalar, MITRE ATT&CK taktikalari.
- **Insidentlar** — hodisa kartalari: risk tarkibi, ishlagan korrelyatsiya qoidalari, ogohlantirishlar, javob choralari va ularning `ipset`/AD/RPZ buyruqlari, tahlilchi holati va izohi, qo‘lda chora.
- **Ogohlantirishlar** — barcha modullar ogohlantirishlari, daraja va qidiruv bo‘yicha filtr.
- **Javob choralari** — IDS/IPS rejimi, faol bloklashlar (TTL), bekor qilish, qo‘lda bloklash, oq ro‘yxat, choralar jurnali.
- **Aktivlar va IoC** — S_aktiv (muhimlik) jadvali, zararli IP/domenlar ro‘yxati.
- **Ma’lumotlar** — jurnallarni yuklash, simulyatsiya, normal profilni o‘qitish, namunaviy fayllar, tahlillar tarixi.
- **ML modellar** — NSL-KDD eksperimenti: modellar jadvali, ROC, chegara tahlili, 5 sinf, xususiyatlar guruhlari va muhimligi, qaror daraxti qoidalari.
- **API**, **Tizim haqida**.

## NSL-KDD eksperimenti (diplom, 3.2-band)

`python train/train_models.py` (≈ 3–6 daqiqa) diplomdagi tajribani to‘liq takrorlaydi. KDDTest+ natijalari:

| Model | Accuracy | Recall | F1 | FPR | ROC-AUC | Yangi hujumlar |
|---|---|---|---|---|---|---|
| Logistic Regression | 75,4% | 0,624 | 0,743 | 7,39% | 0,792 | 40,7% |
| Decision Tree | 79,8% | 0,675 | 0,792 | 3,87% | 0,818 | 44,3% |
| Random Forest | 77,8% | 0,630 | 0,763 | 2,67% | 0,962 | 29,0% |
| XGBoost | 79,6% | 0,664 | **0,788** | 2,85% | 0,969 | 39,6% |
| MLP | 80,7% | 0,683 | 0,801 | 3,01% | 0,903 | 48,6% |
| Isolation Forest | 80,2% | 0,672 | 0,795 | 2,45% | 0,945 | 65,1% |
| **Gibrid (XGBoost + IF)** | **84,6%** | **0,754** | **0,848** | 3,32% | 0,948 | **68,4%** |

Besh sinfli XGBoost: aniqlik 77,9%, makro-F1 0,560. Chuqurligi 3 bo‘lgan qaror daraxti qoidalari: F1 0,777, Recall 65,1%, FPR 3,39%.
Random Forest natijalari diplomdagidan 0,1–0,2 punktga farq qiladi (tasodifiylik va kutubxona versiyasi); qolganlari to‘liq mos.

Saqlanadigan modellar (`models/`):
- `full41.joblib` — 41 xususiyatli XGBoost + IF + 5 sinfli XGBoost (yuklangan NSL-KDD fayllarini baholash);
- `zeek.joblib` — Zeek jurnalidan hisoblanadigan 26 xususiyat (asosiy + vaqt + xost; D-ilova) bo‘yicha modellar — real trafik uchun. Mazmun xususiyatlari (13 ta) paket ichidan olinadi va Zeek `conn.log` da yo‘q;
- `profile.joblib` — korxona **normal profili** (IF). Namoyish uchun simulyatsiya qilingan normal trafikda o‘qitilgan; real korxonada hujumsiz deb tekshirilgan 1–2 haftalik `conn.log` bilan qayta o‘qiting: `python train/train_profile.py --conn conn.log` yoki konsolning «Ma’lumotlar» sahifasidan.
- `metrics.json` — barcha eksperiment natijalari (ML modellar sahifasi shu fayldan chiziladi).

## Signatura va korrelyatsiya qoidalari

Signatura (C-ilova, `integrations/suricata/local.rules` bilan bir xil sid):
`1000010` port skanerlash · `1000011/14` RDP/SSH brute force · `1000012` stansiyalararo SMB · `1000013` uzun DNS so‘rovi · `1000015` SYN flood · `1000020` IoC.
Suricata EVE ogohlantirishlari ham import qilinadi (severity 1/2/3 → S_sig 1,0/0,6/0,3).

SIEM korrelyatsiyasi (3.9-jadval):

| | Qoida | ATT&CK | Javob |
|---|---|---|---|
| R1 | 5 daq ≥ 20 muvaffaqiyatsiz kirish → muvaffaqiyatli kirish | T1110, T1078 | hisob + IP bloklanadi |
| R2 | Skanerlash → 1 soat ichida eksployt | T1595, T1190 | IP bloklanadi |
| R3 | Stansiyadan ≥ 5 stansiyaga SMB/RDP (10 daq) | T1021 | xost karantinga |
| R4 | Muntazam intervalli kichik ulanishlar (beaconing) | T1071 | C2 manzili bloklanadi |
| R5 | Ish vaqtidan tashqari > 1 GB chiquvchi trafik | T1041 | SOC + ulanishni cheklash |
| R6 | 60 s da ≥ 100 fayl o‘zgarishi (FIM) + SMB | T1486 | xost izolyatsiya |
| R7* | 5 daq ≥ 20 uzun DNS so‘rovi bitta domenga | T1071.004 | domen bloklanadi |
| R8* | Bitta nostandart portga takroriy IF anomaliyalari | T1571 | SOC ga |

\* R7 va R8 diplom jadvalidagi 6- va 7-sinov stsenariylarining kutilgan javobini ta’minlash uchun qo‘shilgan.

## Sinov stsenariylari (3.10-jadval + qo‘shimcha)

Simulyatsiya natijasi (10 daqiqa normal trafik + barcha stsenariylar, IPS rejimi):

| Stsenariy | Natija | Javob |
|---|---|---|
| Port skanerlash (nmap) | Yuqori, 0,84 | IP bloklandi; keyingi SQL in’eksiya urinishlari IPS tomonidan to‘xtatildi |
| RDP parol tanlash (hydra) | Yuqori, 0,95 (R1) | IP va `administrator` hisobi bloklandi |
| SYN flood (hping3) | Yuqori, 0,99 | IP bloklandi, keyingi ulanishlar IPS tomonidan to‘xtatildi |
| SQL in’eksiya (sqlmap) | skaner bilan bitta insident | IDS rejimida R2 ishlaydi |
| Stansiyalararo SMB (PsExec) | Yuqori, 0,85 (R3) | xost karantinga |
| DNS tunnel (dnscat2) | Yuqori, 0,85 (R7) | domen bloklandi, xost karantinga |
| Noma’lum protokol | O‘rta, 0,60 (R8) | SOC ga |
| C2 beaconing | Yuqori, 0,85 (R4) | C2 IP bloklandi |
| Tungi eksfiltratsiya | O‘rta, 0,70 (R5) | ulanish cheklandi, SOC ga |
| Ransomware | Yuqori, 0,95 (R6) | xost izolyatsiya |

Faqat normal trafik (30 daqiqa, ~14 000 ulanish) — **0 ta insident** (barcha ogohlantirishlar «past» darajada, faqat jurnalga yoziladi).

## Real tarmoqqa ulash

```
SPAN/TAP ─► Zeek (JSON) ─┐
          ─► Suricata ───┼─► integrations/log_shipper.py ─► NetGuard /api/v1/ingest
Wazuh agentlari ─────────┘                                         │
                         NGFW / Linux shlyuz ◄─ integrations/blocker_agent.py ◄─ /api/v1/blocklist
```

1. Zeek’da JSON jurnallarni yoqing: `@load policy/tuning/json-logs.zeek`.
2. Suricata’ga `integrations/suricata/local.rules` ni qo‘shing, `USER_NET` ni sozlang.
3. Serverni API kaliti bilan ishga tushiring: `NETGUARD_API_KEY=maxfiy NETGUARD_MODE=ids python app.py` (dastlab **IDS — monitoring** rejimi, kamida 2 hafta).
4. Sensor: `python integrations/log_shipper.py --server http://soc:5000 conn.log dns.log eve.json alerts.json`.
5. Shlyuz (root): `ipset create blocklist hash:ip timeout 86400` va `iptables` qoidalari (fayl boshidagi izohga qarang), so‘ng `python integrations/blocker_agent.py --server http://soc:5000`.
6. Isolation Forest’ni korxona trafigida qayta o‘qiting, `netguard/config.py` dagi segmentlar va konsoldagi aktivlar/oq ro‘yxatni to‘ldiring, so‘ng IPS rejimini yoqing.

`integrations/eve_blocker.py` — diplom B-ilovasidagi mustaqil skript (serversiz ishlaydi).

## Loyiha tuzilmasi

```
app.py                     Flask SOC konsoli va REST API
netguard/
  config.py                segmentlar, vaznlar, chegaralar, standart aktivlar/oq ro‘yxat/IoC
  features.py              NSL-KDD ustunlari, Zeek → NSL-KDD xususiyatlari (2 s / 100 ulanish oynalari)
  models.py                XGBoost / Isolation Forest / 5 sinf; normal profil
  signatures.py            C-ilova qoidalari, IoC, Suricata EVE, MITRE ATT&CK
  correlation.py           SIEM qoidalari R1–R8
  risk.py                  (3.1), (3.2), darajalar
  response.py              bloklash / karantin / domen / hisob, oq ro‘yxat, buyruqlar
  engine.py                to‘rt qatlamli quvur, insidentlar, NSL-KDD baholash
  parsers.py               Zeek TSV/JSON, Suricata EVE, Wazuh, NSL-KDD
  simulator.py             normal trafik va 10 ta hujum stsenariysi
  storage.py               SQLite (ogohlantirishlar, insidentlar, choralar, aktivlar …)
train/                     download_data.py, train_models.py, train_profile.py, make_samples.py
integrations/              log_shipper.py, blocker_agent.py, eve_blocker.py, suricata/local.rules
samples/                   namunaviy conn.log, dns.log, eve.json, Wazuh alerts.json, NSL-KDD
tests/test_netguard.py     35 ta avtomatik test:  python -m pytest -q
```

## Cheklovlar (himoyada aytish uchun)

- ML modellari ochiq NSL-KDD datasetida o‘qitilgan; real korxonada XGBoost laboratoriya sinovlarining yorliqlangan ma’lumotlari bilan, IF esa korxona normal trafigida qayta o‘qitilishi kerak.
- Simulyator laboratoriyani (Kali Linux, nmap, hydra …) almashtirmaydi: u modullarni namoyish qilish va avtomatik testlar uchun Zeek/Suricata/Wazuh formatidagi yozuvlarni hosil qiladi.
- Bloklash buyruqlari konsolda ko‘rsatiladi va agent tomonidan qo‘llanadi; konsolning o‘zi tarmoq qurilmalarini o‘zgartirmaydi.
- API kaliti berilmasa API ochiq — faqat laboratoriya uchun.
