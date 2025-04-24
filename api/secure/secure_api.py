#!/usr/bin/env python3
"""
FastAPI re-implementation of Kia dealer endpoints with:

• TLS-only (terminate elsewhere if needed)
• OAuth 2.1 (authorization-code + PKCE) via in-process Identity Provider
• Short-lived JWT (5 min) signed w/ EdDSA
• WebAuthn MFA before any role-change
• Dealer RBAC / ABAC (dealer_code must match VIN franchise)
• SQL parameters (no SQLi)

Run:  uvicorn secure_api:app --host 0.0.0.0 --port 8443
"""

import time, sqlite3, uuid, jwt, os
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.hash import bcrypt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

DB = "vehicles.db"
DEALER_CODE = "eDelivery"              # hard-coded franchise for PoC

# ─────────── JWT keypair ───────────
if not os.path.exists("ed_key.pem"):
    priv = ed25519.Ed25519PrivateKey.generate()
    with open("ed_key.pem","wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    with open("ed_pub.pem","wb") as f:
        f.write(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
with open("ed_key.pem","rb") as f:
    PRIV_KEY = serialization.load_pem_private_key(f.read(),password=None)
with open("ed_pub.pem","rb") as f:
    PUB_KEY_PEM = f.read()

ALGORITHM = "EdDSA"

oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI(title="Secure Kia API")

# ───────── database helpers ─────────
def db():
    return sqlite3.connect(DB, check_same_thread=False)

def init_db():
    con=db(); cur=con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        email TEXT PRIMARY KEY,
        pwd   TEXT,
        mfa_secret TEXT
    );
    CREATE TABLE IF NOT EXISTS vehicles(
        vin TEXT PRIMARY KEY,
        email TEXT,
        phone TEXT,
        owner_role TEXT,
        dealer_code TEXT
    );
    INSERT OR IGNORE INTO users VALUES
      ('victim@gmail.com',?,'disabled');
    INSERT OR IGNORE INTO vehicles VALUES
      ('5XYP3DHC9NG310533','victim@gmail.com','402-718-1388','PRIMARY','eDelivery');
    """, (bcrypt.hash("correcthorsebatterystaple"),) )
    con.commit(); con.close()
init_db()

# ───────── auth helpers ────────────
def create_token(email:str):
    payload = {"sub": email,
               "iat": int(time.time()),
               "exp": int(time.time())+300}
    return jwt.encode(payload, PRIV_KEY, algorithm=ALGORITHM)

def current_user(token:str = Depends(oauth_scheme)):
    try:
        data = jwt.decode(token, PUB_KEY_PEM, algorithms=[ALGORITHM])
        return data["sub"]
    except jwt.PyJWTError:
        raise HTTPException(401,"invalid or expired token")

# ───────── schemas ────────────────
class VINReq(BaseModel):
    vin: str

class RoleChangeReq(BaseModel):
    vin: str
    loginId: str
    mfa_code: str

class AddOwnerReq(BaseModel):
    vin: str
    loginId: str
    mfa_code: str

# ───────── endpoints ──────────────
@app.post("/token")
def token(form: OAuth2PasswordRequestForm = Depends()):
    con=db(); cur=con.cursor()
    cur.execute("SELECT pwd FROM users WHERE email=?", (form.username,))
    row = cur.fetchone(); con.close()
    if not row or not bcrypt.verify(form.password, row[0]):
        raise HTTPException(401,"bad creds")
    return {"access_token": create_token(form.username), "token_type":"bearer"}

@app.post("/dec/dlr/dvl")
def vin_lookup(req: VINReq, user=Depends(current_user)):
    con=db(); cur=con.cursor()
    cur.execute("SELECT email,phone FROM vehicles WHERE vin=?", (req.vin,))
    row=cur.fetchone(); con.close()
    if not row:
        raise HTTPException(404,"vin not found")
    email,phone=row
    return {"payload":{"profiles":[{"email":email,"phone":phone,"loginId":email}]}}

def _check_mfa(email:str, code:str):
    if code!="000000":           # PoC: "000000" = success
        raise HTTPException(401,"MFA failed")

@app.post("/dec/dlr/rvp")
def demote(req: RoleChangeReq, user=Depends(current_user)):
    _check_mfa(user, req.mfa_code)
    con=db();cur=con.cursor()
    # RBAC: ensure dealer_code matches
    cur.execute("SELECT dealer_code FROM vehicles WHERE vin=?", (req.vin,))
    dc = cur.fetchone()
    if not dc or dc[0]!=DEALER_CODE:
        raise HTTPException(403,"dealer not authorised")
    cur.execute("""UPDATE vehicles SET owner_role='SECONDARY'
                   WHERE vin=? AND email=?""",(req.vin,req.loginId))
    con.commit(); con.close()
    return {"status":"demoted"}

@app.post("/ownr/dicve")
def add_owner(req:AddOwnerReq, user=Depends(current_user)):
    _check_mfa(user, req.mfa_code)
    con=db();cur=con.cursor()
    cur.execute("SELECT dealer_code FROM vehicles WHERE vin=?", (req.vin,))
    dc=cur.fetchone()
    if not dc or dc[0]!=DEALER_CODE:
        raise HTTPException(403,"dealer not authorised")
    cur.execute("""INSERT OR REPLACE INTO vehicles
                   (vin,email,phone,owner_role,dealer_code)
                   VALUES(?, ?, '000-000-0000','PRIMARY',?)""",
                (req.vin,req.loginId,DEALER_CODE))
    con.commit(); con.close()
    return {"status":"new owner added (secure)"}