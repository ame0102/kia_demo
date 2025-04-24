
# Vehicle Security Architecture Demo 

Interactive lab that contrasts **insecure** (red) and **secure** (green) implementations of three critical automotive-security layers:

| Layer | Insecure (Red) | Secure (Green) |
|-------|----------------|----------------|
| **Cloud API** | static `Sid`, no auth, SQL-injection | OAuth 2.1 + PKCE, 5-min EdDSA JWT, WebAuthn MFA, RBAC |
| **OTA updates** | unsigned `latest.bin`, rollback allowed | TUF-signed metadata, 4-role key hierarchy, version monotonicity |
| **CAN bus** | raw CAN frames accepted | CAN-FD + AES-CMAC firewall, nonce replay-block |

The front-end ( `frontend/templates/frontend/simple_demo.html` ) lets visitors toggle **Insecure/Secure** tabs and run an *Attack Simulation* that either succeeds (red) or is blocked (green).

---

## Repo layout

```
vehicle_security_demo/
├── manage.py                 # Django launcher
├── requirements.txt          # everything you need (`pip install -r`)
├── setup.sh                  # one-shot auto-installer (Linux/macOS)
├── api/
│   ├── urls.py / views.py    # REST endpoints (simulate_attack, etc.)
│   ├── insecure/             # ✗ bad reference code
│   │   ├── insecure_api.py
│   │   ├── ota_server.py
│   │   └── can_bus_sim.py
│   └── secure/               # ✓ good reference code
│       ├── secure_api.py
│       ├── secure_ota_server.py
│       ├── can_firewall.py
│       └── init_tuf_repo.py
├── frontend/
│   ├── urls.py / views.py
│   └── templates/frontend/simple_demo.html
├── static/                   # Tailwind CSS + vanilla JS helpers
└── vehicle_security/         # Django project settings / routing
```

---

## 1  Quick start (Linux / macOS)

```bash
git clone git@github.com:ame0102/kia_demo.git
cd vehicle_security_demo

chmod +x setup.sh
./setup.sh          # ≈60 s: venv, pip install, DB migrate, TUF init

source venv/bin/activate
python manage.py runserver
```

Open **http://127.0.0.1:8000** – switch tabs, press **Run Attack Simulation** and watch the difference.

---

## 2  Quick start (Windows PowerShell)

```powershell
git clone https://github.com/ame0102/kia_demo.git
cd vehicle_security_demo

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
mkdir firmware; echo DEMO > firmware\latest.bin
python manage.py makemigrations api; python manage.py migrate
python api\secure\init_tuf_repo.py firmware\latest.bin
python manage.py runserver
```

OR

```powershell
# Clone the repository
git clone https://github.com/ame0102/kia_demo.git
cd vehicle_security_demo

# Run the setup script
chmod +x setup.sh
./setup.sh

# Start the server
source venv/bin/activate
python manage.py runserver
```

---

## 3  How it works

1. **/api/simulate_attack**   (front-end Ajax POST)  
   * `mode=insecure` → returns JSON sequence of four compromised steps  
   * `mode=secure`   → randomly blocks at API, OTA, or CAN layer  
   * No DB writes—we keep the lab stateless and easy to reset

2. **Secure back-end** (`api/secure/secure_api.py`) is served on `localhost:8443` when you want to show real JWT+MFA flow; the HTML demo calls only the stub endpoint above for simplicity.

3. **Firmware & CAN code** live in `api/secure/` and `api/insecure/` so students can run either family of scripts side-by-side and read the diff.

---

## 4  Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: django` | Activate venv *first* (`source venv/bin/activate`), then `pip install -r requirements.txt`. |
| `no such table: api_securitylog` | `python manage.py migrate` (models were simplified, but you may still need fresh migrations). |
| Browser shows 500 on `/api/simulate_attack/` | Check server console; common cause is missing `rest_framework` in `INSTALLED_APPS`. |
| Lucide icons not rendered | The HTML already loads `lucide.min.js` via jsDelivr. Make sure you’re online or serve it locally. |

---

## 5  License

MIT.  Academic use only; **do not** deploy the insecure code anywhere public.
