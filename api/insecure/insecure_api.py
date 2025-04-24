#!/usr/bin/env python3
"""
A deliberately insecure HTTP back-end that emulates four Kia dealer API
endpoints:

    POST /prof/authUser          → returns a static Sid token
    POST /dec/dlr/dvl            → VIN → PII lookup
    POST /dec/dlr/rvp            → demote existing owner
    POST /ownr/dicve             → add attacker as primary owner

• No TLS, no OAuth, no MFA, no RBAC.
• SQLite used without parameterised queries → SQLi possible.
• Single-threaded HTTPServer (easy DoS).
"""

import json, sqlite3, time
from http.server import HTTPServer, BaseHTTPRequestHandler
DB = "vehicles.db"
SID = "insecure-sid-0001"                      # hard-coded session token

# ────────────────────── database bootstrap ────────────────────────────
def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS vehicles(
        vin TEXT PRIMARY KEY,
        email TEXT,
        phone TEXT,
        owner_role TEXT
    );
    INSERT OR IGNORE INTO vehicles VALUES
      ('5XYP3DHC9NG310533','victim@gmail.com','402-718-1388','PRIMARY');
    """)
    con.commit(); con.close()

# ───────────────────────── HTTP handler ───────────────────────────────
class KiaHandler(BaseHTTPRequestHandler):
    def _json(self, payload, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.loads(raw or "{}")
        route = self.path

        # ───────── 1. authUser  ─────────
        if route == "/prof/authUser":
            return self._json({"Sid": SID, "status":"OK"})

        # reject if client forgot Sid header (but do not validate value!)
        if self.headers.get("Sid") is None:
            return self._json({"err":"missing Sid"}, 401)

        # ───────── 2. VIN → PII lookup ─────────
        if route == "/dec/dlr/dvl":
            vin = body.get("vin","")
            con = sqlite3.connect(DB); cur = con.cursor()
            cur.execute(f"SELECT email,phone,owner_role FROM vehicles WHERE vin='{vin}'")
            row = cur.fetchone(); con.close()
            if not row:
                return self._json({"err":"vin not found"},404)
            email,phone,role = row
            return self._json({"payload":{"profiles":[{
                "email": email, "phone": phone, "loginId": email
            }]} })

        # ───────── 3. role demotion ─────────
        if route == "/dec/dlr/rvp":
            vin  = body.get("vin","")
            email= body.get("loginId","")
            # blindly update
            con=sqlite3.connect(DB); cur=con.cursor()
            cur.execute(f"UPDATE vehicles SET owner_role='SECONDARY' "
                        f"WHERE vin='{vin}' AND email='{email}'")
            con.commit(); con.close()
            return self._json({"status":"demoted"})

        # ───────── 4. add attacker ─────────
        if route == "/ownr/dicve":
            vin  = body.get("vin","")
            email= body.get("loginId","")
            con=sqlite3.connect(DB); cur=con.cursor()
            cur.execute(f"INSERT OR REPLACE INTO vehicles(vin,email,phone,owner_role) "
                        f"VALUES('{vin}','{email}','000-000-0000','PRIMARY')")
            con.commit(); con.close()
            return self._json({"status":"attacker-now-owner"})

        # unknown route
        self._json({"err":"bad endpoint"},404)

# ────────────────────────── main ──────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("[!]   Insecure Kia back-end listening on :8000  (CTRL-C to quit)")
    HTTPServer(("",8000), KiaHandler).serve_forever()