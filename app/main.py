"""Secure File Vault — Phase 1 MVP.
Passwordless (email code + magic link) file sharing vault.
Files are stored AES-256-GCM encrypted (chunked) on disk; SQLite holds metadata.
"""
import asyncio, base64, hashlib, json, os, secrets, shutil, socket, sqlite3, string, struct, time, urllib.request
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "db" / "vault.db"
FILES_DIR = DATA_DIR / "files"
TMP_DIR = DATA_DIR / "tmp"
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8080").rstrip("/")
EMAIL_MODE = os.environ.get("EMAIL_MODE", "console")  # console | resend
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "Vault <vault@example.com>")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
CLAMAV_HOST = os.environ.get("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT", "3310"))
KEY_B64 = os.environ.get("VAULT_KEY_B64", "")
ENC_CHUNK = 4 * 1024 * 1024
UPLOAD_CHUNK_DEFAULT = 8 * 1024 * 1024

def now_ts():
    return int(time.time())

def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def get_key() -> bytes:
    if not KEY_B64:
        raise RuntimeError("VAULT_KEY_B64 not set")
    k = base64.b64decode(KEY_B64)
    if len(k) != 32:
        raise RuntimeError("VAULT_KEY_B64 must decode to 32 bytes")
    return k

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def audit(conn, action, detail="", user=None, username="", ip=""):
    conn.execute(
        "INSERT INTO audit(ts,user_id,username,action,detail,ip) VALUES(?,?,?,?,?,?)",
        (now_ts(), (user["id"] if user else None), (user["username"] if user else username), action, detail, ip),
    )

def get_setting(conn, key, default):
    r = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default

def init_db():
    for d in (DB_PATH.parent, FILES_DIR, TMP_DIR, DATA_DIR / "logs"):
        d.mkdir(parents=True, exist_ok=True)
    with closing(db()) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT NOT NULL,
            display_name TEXT DEFAULT '', role TEXT DEFAULT 'user', active INTEGER DEFAULT 1,
            quota_bytes INTEGER, created_at INTEGER);
        CREATE TABLE IF NOT EXISTS login_tokens(
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, code_hash TEXT, magic_hash TEXT,
            expires_at INTEGER, used_at INTEGER, attempts INTEGER DEFAULT 0, created_ip TEXT, created_at INTEGER);
        CREATE TABLE IF NOT EXISTS sessions(
            id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL,
            expires_at INTEGER, created_at INTEGER, ip TEXT, revoked INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS folders(
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER NOT NULL,
            parent_id INTEGER, created_at INTEGER, deleted_at INTEGER);
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, folder_id INTEGER, owner_id INTEGER NOT NULL,
            size INTEGER NOT NULL, sha256 TEXT, mime TEXT DEFAULT '', storage_name TEXT NOT NULL,
            base_nonce TEXT, created_at INTEGER, deleted_at INTEGER, expires_at INTEGER);
        CREATE TABLE IF NOT EXISTS shares(
            id INTEGER PRIMARY KEY, resource_type TEXT NOT NULL, resource_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL, can_download INTEGER DEFAULT 1, can_upload INTEGER DEFAULT 0,
            can_delete INTEGER DEFAULT 0, expires_at INTEGER, created_by INTEGER, created_at INTEGER);
        CREATE TABLE IF NOT EXISTS uploads(
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, filename TEXT NOT NULL, folder_id INTEGER,
            total_size INTEGER NOT NULL, chunk_size INTEGER NOT NULL, total_chunks INTEGER NOT NULL,
            received TEXT DEFAULT '[]', status TEXT DEFAULT 'active', created_at INTEGER);
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY, ts INTEGER, user_id INTEGER, username TEXT, action TEXT, detail TEXT, ip TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS groups_tbl(
            id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at INTEGER);
        CREATE TABLE IF NOT EXISTS group_members(
            group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(group_id,user_id));
        CREATE TABLE IF NOT EXISTS group_shares(
            id INTEGER PRIMARY KEY, resource_type TEXT NOT NULL, resource_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL, can_download INTEGER DEFAULT 1, can_upload INTEGER DEFAULT 0,
            can_delete INTEGER DEFAULT 0, expires_at INTEGER, created_by INTEGER, created_at INTEGER);
        CREATE TABLE IF NOT EXISTS share_links(
            id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, resource_type TEXT NOT NULL,
            resource_id INTEGER NOT NULL, created_by INTEGER NOT NULL, expires_at INTEGER,
            max_downloads INTEGER DEFAULT 0, downloads INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0,
            created_at INTEGER);
        """)
        # --- migrations (columns added after v1) ---
        def add_col(table, col, decl):
            cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]
            if col not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        add_col("files", "scan_status", "TEXT DEFAULT 'unscanned'")
        add_col("users", "can_share_link", "INTEGER DEFAULT 0")
        conn.execute("UPDATE users SET can_share_link=1 WHERE role='admin'")
        add_col("uploads", "mime", "TEXT DEFAULT ''")
        add_col("sessions", "ua", "TEXT DEFAULT ''")
        add_col("sessions", "reauth_at", "INTEGER DEFAULT 0")
        defaults = {
            "max_upload_gb": "25", "token_ttl_minutes": "15", "session_hours": "8",
            "site_name": "Fixin Hixon Vault", "auto_expire_days": "0", "trash_days": "30",
            "av_scanning": "on",
        }
        for k, v in defaults.items():
            conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        # Bootstrap admin
        email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "")
        uname = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "admin")
        if email and conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
            conn.execute(
                "INSERT INTO users(username,email,display_name,role,active,created_at) VALUES(?,?,?,'admin',1,?)",
                (uname.lower(), email, os.environ.get("BOOTSTRAP_ADMIN_NAME", "Admin"), now_ts()))
        conn.commit()

# ---------- crypto (chunked AES-256-GCM) ----------
def chunk_nonce(base_nonce: bytes, idx: int) -> bytes:
    b = bytearray(base_nonce)
    x = int.from_bytes(b[8:12], "big") ^ idx
    b[8:12] = x.to_bytes(4, "big")
    return bytes(b)

def encrypt_stream(src_path: Path, dst_path: Path, file_id_str: str):
    key, aes = get_key(), None
    aes = AESGCM(key)
    base_nonce = os.urandom(12)
    h = hashlib.sha256()
    size = 0
    with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
        idx = 0
        while True:
            chunk = fin.read(ENC_CHUNK)
            if not chunk:
                break
            h.update(chunk); size += len(chunk)
            ct = aes.encrypt(chunk_nonce(base_nonce, idx), chunk, file_id_str.encode())
            fout.write(struct.pack(">Q", len(ct))); fout.write(ct)
            idx += 1
    return base_nonce, h.hexdigest(), size

def decrypt_iter(storage_path: Path, base_nonce_b64: str, file_id_str: str):
    aes = AESGCM(get_key())
    base_nonce = base64.b64decode(base_nonce_b64)
    with open(storage_path, "rb") as f:
        idx = 0
        while True:
            hdr = f.read(8)
            if not hdr:
                break
            (ln,) = struct.unpack(">Q", hdr)
            ct = f.read(ln)
            yield aes.decrypt(chunk_nonce(base_nonce, idx), ct, file_id_str.encode())
            idx += 1

# ---------- ClamAV ----------
def clamav_scan(path: Path):
    """Returns (status, detail): status is 'clean', 'infected', or 'unscanned' (daemon unavailable)."""
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=60) as s:
            s.sendall(b"zINSTREAM\x00")
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            resp = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                resp += data
        text = resp.decode(errors="ignore")
        if "OK" in text and "FOUND" not in text:
            return "clean", ""
        if "FOUND" in text:
            return "infected", text.strip()
        return "unscanned", text.strip()
    except Exception as e:
        return "unscanned", f"scanner unavailable: {e}"

# ---------- email ----------
def send_login_email(email, username, code, magic_url):
    site = PUBLIC_URL
    text = (f"Your login for {site}\n\nCode: {code}\n\nOr click to log in: {magic_url}\n\n"
            f"The link opens a confirmation page. Code and link expire soon and can only be used once.\n"
            f"If you did not request this, ignore this email.")
    if EMAIL_MODE == "resend" and RESEND_API_KEY:
        payload = json.dumps({"from": EMAIL_FROM, "to": [email], "subject": "Your vault login code",
                              "text": text}).encode()
        req = urllib.request.Request("https://api.resend.com/emails", data=payload, method="POST",
                                     headers={"Authorization": f"Bearer {RESEND_API_KEY}",
                                              "Content-Type": "application/json",
                                              # api.resend.com is behind Cloudflare, which bans the
                                              # default Python-urllib user agent (error 1010).
                                              "User-Agent": "secure-file-vault/1.0"})
        try:
            urllib.request.urlopen(req, timeout=15).read()
        except Exception as e:
            print(f"RESEND_ERROR to={email} err={e}", flush=True)
    else:
        # Dev mode: token goes to server log only (docker logs). Never enable in production.
        print(f"LOGIN_EMAIL to={email} username={username} code={code} magic={magic_url}", flush=True)

# ---------- auth helpers ----------
app = FastAPI(title="Secure File Vault", docs_url=None, redoc_url=None, openapi_url=None)

def client_ip(req: Request):
    fwd = req.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (req.client.host if req.client else "")

def current_user(req: Request):
    tok = req.cookies.get("vault_session", "")
    if not tok:
        return None
    with closing(db()) as conn:
        r = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at>? AND u.active=1",
            (sha256_hex(tok), now_ts())).fetchone()
        return dict(r) if r else None

def require_user(req: Request):
    u = current_user(req)
    if not u:
        raise HTTPException(401, "Not logged in")
    return u

def can_share_link(user) -> bool:
    """Share-link creation is a granted privilege: admins always, other users
    only when the admin enabled can_share_link on their account."""
    if user["role"] == "admin":
        return True
    try:
        return bool(user["can_share_link"])
    except Exception:
        return False

def require_admin(req: Request):
    u = require_user(req)
    if u["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return u

def make_session(conn, user, req):
    tok = secrets.token_urlsafe(32)
    hours = int(get_setting(conn, "session_hours", "8"))
    ua = (req.headers.get("user-agent", "") if req else "")[:200]
    conn.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at,ip,ua,reauth_at) VALUES(?,?,?,?,?,?,?)",
                 (sha256_hex(tok), user["id"], now_ts() + hours * 3600, now_ts(), client_ip(req), ua, now_ts()))
    return tok

def require_reauth(req: Request, user):
    """Sensitive admin actions need a fresh authentication within the last 15 minutes.
    A fresh login counts; otherwise the admin requests a new code and calls /api/auth/reauth."""
    tok = req.cookies.get("vault_session", "")
    with closing(db()) as conn:
        s = conn.execute("SELECT reauth_at FROM sessions WHERE token_hash=? AND user_id=? AND revoked=0",
                         (sha256_hex(tok), user["id"])).fetchone()
    if not s or now_ts() - (s["reauth_at"] or 0) > 900:
        raise HTTPException(403, "reauth_required")

def session_response(user, tok):
    resp = JSONResponse({"ok": True, "username": user["username"], "role": user["role"]})
    resp.set_cookie("vault_session", tok, max_age=12 * 3600, httponly=True, samesite="lax", secure=COOKIE_SECURE, path="/")
    return resp

@app.on_event("startup")
def _startup():
    get_key()
    init_db()

@app.middleware("http")
async def security_headers(req: Request, call_next):
    resp = await call_next(req)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if COOKIE_SECURE:  # only promise HTTPS when actually behind it (Phase 3 tunnel)
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

@app.get("/api/health")
def health():
    total, used, free = shutil.disk_usage(DATA_DIR)
    return {"ok": True, "free_bytes": free, "total_bytes": total, "email_mode": EMAIL_MODE}

# ---------- auth endpoints ----------
@app.post("/api/auth/request")
async def auth_request(req: Request):
    body = await req.json()
    username = str(body.get("username", "")).strip().lower()
    ip = client_ip(req)
    with closing(db()) as conn:
        u = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if u:
            # rate limit: max 3 emailed codes / user / 15 min, 20 / IP / hour.
            # Only count real code requests (code_hash set) — break-glass recovery
            # tokens (code_hash NULL) must not eat the user's email quota.
            c_user = conn.execute("SELECT COUNT(*) c FROM login_tokens WHERE user_id=? AND code_hash IS NOT NULL AND created_at>?",
                                  (u["id"], now_ts() - 900)).fetchone()["c"]
            c_ip = conn.execute("SELECT COUNT(*) c FROM login_tokens WHERE created_ip=? AND code_hash IS NOT NULL AND created_at>?",
                                (ip, now_ts() - 3600)).fetchone()["c"]
            if c_user < 3 and c_ip < 20:
                ttl = int(get_setting(conn, "token_ttl_minutes", "15"))
                code = "".join(secrets.choice(string.digits) for _ in range(6))
                magic = secrets.token_urlsafe(32)
                conn.execute("INSERT INTO login_tokens(user_id,code_hash,magic_hash,expires_at,created_ip,created_at) VALUES(?,?,?,?,?,?)",
                             (u["id"], sha256_hex(code), sha256_hex(magic), now_ts() + ttl * 60, ip, now_ts()))
                conn.commit()
                send_login_email(u["email"], u["username"], code, f"{PUBLIC_URL}/auth/magic?token={magic}")
                audit(conn, "login_requested", "", user=dict(u), ip=ip); conn.commit()
            else:
                audit(conn, "login_rate_limited", "", user=dict(u), ip=ip); conn.commit()
        else:
            audit(conn, "login_unknown_user", "", username=username, ip=ip); conn.commit()
    # Identical response whether or not the account exists (no enumeration).
    return {"ok": True, "message": "If that account exists, a login code is on its way."}

@app.post("/api/auth/verify-code")
async def verify_code(req: Request):
    body = await req.json()
    username = str(body.get("username", "")).strip().lower()
    code = str(body.get("code", "")).strip()
    ip = client_ip(req)
    with closing(db()) as conn:
        u = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if not u:
            raise HTTPException(400, "Invalid or expired code")
        t = conn.execute("SELECT * FROM login_tokens WHERE user_id=? AND code_hash=? AND used_at IS NULL ORDER BY id DESC",
                         (u["id"], sha256_hex(code))).fetchone()
        if not t:
            last = conn.execute("SELECT * FROM login_tokens WHERE user_id=? AND used_at IS NULL ORDER BY id DESC", (u["id"],)).fetchone()
            if last:
                conn.execute("UPDATE login_tokens SET attempts=attempts+1 WHERE id=?", (last["id"],)); conn.commit()
            raise HTTPException(400, "Invalid or expired code")
        if t["expires_at"] < now_ts() or t["attempts"] >= 5:
            raise HTTPException(400, "Invalid or expired code")
        conn.execute("UPDATE login_tokens SET used_at=? WHERE id=?", (now_ts(), t["id"]))
        user = dict(u)
        tok = make_session(conn, user, req)
        audit(conn, "login_success_code", "", user=user, ip=ip); conn.commit()
    return session_response(user, tok)

@app.get("/auth/magic", response_class=HTMLResponse)
def magic_page(token: str = ""):
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8"><title>Confirm login</title>
<link rel="stylesheet" href="/static/style.css"></head><body><main class="card">
<h1>Confirm login</h1><p>Click below to finish logging in to the vault. This link can only be used once.</p>
<button id="b">Log me in</button><p id="m"></p></main>
<script>document.getElementById('b').onclick=async()=>{{const r=await fetch('/api/auth/verify-magic',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token:{json.dumps(token)}}})}});if(r.ok){{location.href='/'}}else{{document.getElementById('m').textContent='This link is invalid or expired. Request a new code.'}}}};</script>
</body></html>""")

@app.post("/api/auth/verify-magic")
async def verify_magic(req: Request):
    body = await req.json()
    token = str(body.get("token", ""))
    ip = client_ip(req)
    with closing(db()) as conn:
        t = conn.execute("SELECT * FROM login_tokens WHERE magic_hash=? AND used_at IS NULL", (sha256_hex(token),)).fetchone()
        if not t or t["expires_at"] < now_ts():
            raise HTTPException(400, "Invalid or expired link")
        conn.execute("UPDATE login_tokens SET used_at=? WHERE id=?", (now_ts(), t["id"]))
        u = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (t["user_id"],)).fetchone()
        if not u:
            raise HTTPException(400, "Account disabled")
        user = dict(u)
        tok = make_session(conn, user, req)
        audit(conn, "login_success_magic", "", user=user, ip=ip); conn.commit()
    return session_response(user, tok)

@app.post("/api/auth/logout")
async def logout(req: Request):
    u = require_user(req)
    tok = req.cookies.get("vault_session", "")
    with closing(db()) as conn:
        conn.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (sha256_hex(tok),))
        audit(conn, "logout", "", user=u, ip=client_ip(req)); conn.commit()
    resp = JSONResponse({"ok": True}); resp.delete_cookie("vault_session", path="/")
    return resp

@app.get("/api/me")
def me(req: Request):
    u = require_user(req)
    return {"id": u["id"], "username": u["username"], "email": u["email"], "display_name": u["display_name"], "role": u["role"],
            "can_share_link": can_share_link(u)}

@app.post("/api/auth/reauth")
async def reauth(req: Request):
    """Step-up authentication for sensitive actions: verify a fresh emailed code
    against the already logged-in user and stamp the session."""
    u = require_user(req)
    body = await req.json()
    code = str(body.get("code", "")).strip()
    tok = req.cookies.get("vault_session", "")
    with closing(db()) as conn:
        t = conn.execute("SELECT * FROM login_tokens WHERE user_id=? AND code_hash=? AND used_at IS NULL ORDER BY id DESC",
                         (u["id"], sha256_hex(code))).fetchone()
        if not t or t["expires_at"] < now_ts() or t["attempts"] >= 5:
            raise HTTPException(400, "Invalid or expired code")
        conn.execute("UPDATE login_tokens SET used_at=? WHERE id=?", (now_ts(), t["id"]))
        conn.execute("UPDATE sessions SET reauth_at=? WHERE token_hash=?", (now_ts(), sha256_hex(tok)))
        audit(conn, "reauth_success", "", user=u, ip=client_ip(req)); conn.commit()
    return {"ok": True}

@app.get("/api/me/sessions")
def my_sessions(req: Request):
    u = require_user(req)
    cur = sha256_hex(req.cookies.get("vault_session", ""))
    with closing(db()) as conn:
        out = []
        for s in conn.execute("SELECT * FROM sessions WHERE user_id=? AND revoked=0 AND expires_at>? ORDER BY id DESC", (u["id"], now_ts())):
            d = dict(s); d["current"] = (s["token_hash"] == cur); d.pop("token_hash", None); out.append(d)
        return out

@app.delete("/api/me/sessions/{session_id}")
def revoke_my_session(session_id: int, req: Request):
    u = require_user(req)
    with closing(db()) as conn:
        conn.execute("UPDATE sessions SET revoked=1 WHERE id=? AND user_id=?", (session_id, u["id"])); conn.commit()
    return {"ok": True}

@app.post("/api/me/sessions/revoke-others")
def revoke_other_sessions(req: Request):
    u = require_user(req)
    cur = sha256_hex(req.cookies.get("vault_session", ""))
    with closing(db()) as conn:
        conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash!=?", (u["id"], cur))
        audit(conn, "sessions_revoked_others", "", user=u, ip=client_ip(req)); conn.commit()
    return {"ok": True}

# ---------- permissions ----------
def share_for(conn, rtype, rid, user_id):
    s = conn.execute(
        "SELECT * FROM shares WHERE resource_type=? AND resource_id=? AND user_id=? AND (expires_at IS NULL OR expires_at>?)",
        (rtype, rid, user_id, now_ts())).fetchone()
    if s:
        return s
    return conn.execute(
        """SELECT gs.* FROM group_shares gs JOIN group_members gm ON gm.group_id=gs.group_id
           WHERE gs.resource_type=? AND gs.resource_id=? AND gm.user_id=? AND (gs.expires_at IS NULL OR gs.expires_at>?)""",
        (rtype, rid, user_id, now_ts())).fetchone()

def can_access_folder(conn, user, folder):
    if user["role"] == "admin" or folder["owner_id"] == user["id"]:
        return {"download": True, "upload": True, "delete": True}
    s = share_for(conn, "folder", folder["id"], user["id"])
    if s:
        return {"download": bool(s["can_download"]), "upload": bool(s["can_upload"]), "delete": bool(s["can_delete"])}
    return None

def can_access_file(conn, user, f):
    if user["role"] == "admin" or f["owner_id"] == user["id"]:
        return {"download": True, "upload": False, "delete": True}
    s = share_for(conn, "file", f["id"], user["id"])
    if s:
        return {"download": bool(s["can_download"]), "upload": False, "delete": bool(s["can_delete"])}
    if f["folder_id"]:
        folder = conn.execute("SELECT * FROM folders WHERE id=?", (f["folder_id"],)).fetchone()
        if folder:
            fs = share_for(conn, "folder", folder["id"], user["id"])
            if fs:
                return {"download": bool(fs["can_download"]), "upload": False, "delete": bool(fs["can_delete"])}
    return None

def file_json(conn, user, f):
    perms = can_access_file(conn, user, f)
    owner = conn.execute("SELECT username FROM users WHERE id=?", (f["owner_id"],)).fetchone()
    return {"id": f["id"], "name": f["name"], "folder_id": f["folder_id"], "size": f["size"],
            "sha256": f["sha256"], "mime": f["mime"], "scan_status": f["scan_status"] if "scan_status" in f.keys() else "unscanned",
            "owner": owner["username"] if owner else "",
            "created_at": f["created_at"], "expires_at": f["expires_at"], "perms": perms}

def folder_json(conn, user, fo):
    perms = can_access_folder(conn, user, fo)
    owner = conn.execute("SELECT username FROM users WHERE id=?", (fo["owner_id"],)).fetchone()
    return {"id": fo["id"], "name": fo["name"], "parent_id": fo["parent_id"],
            "owner": owner["username"] if owner else "", "perms": perms}

# ---------- folders & files ----------
@app.get("/api/vault")
def vault_list(req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        folders, files = [], []
        for fo in conn.execute("SELECT * FROM folders WHERE deleted_at IS NULL ORDER BY name"):
            if can_access_folder(conn, user, fo):
                folders.append(folder_json(conn, user, fo))
        for f in conn.execute("SELECT * FROM files WHERE deleted_at IS NULL ORDER BY created_at DESC"):
            if can_access_file(conn, user, f):
                files.append(file_json(conn, user, f))
        return {"folders": folders, "files": files}

@app.post("/api/folders")
async def create_folder(req: Request):
    user = require_user(req)
    body = await req.json()
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(400, "Name required")
    with closing(db()) as conn:
        cur = conn.execute("INSERT INTO folders(name,owner_id,parent_id,created_at) VALUES(?,?,?,?)",
                           (name, user["id"], body.get("parent_id"), now_ts()))
        conn.commit()
        fo = conn.execute("SELECT * FROM folders WHERE id=?", (cur.lastrowid,)).fetchone()
        audit(conn, "folder_created", name, user=user, ip=client_ip(req)); conn.commit()
        return folder_json(conn, user, fo)

@app.delete("/api/folders/{folder_id}")
def delete_folder(folder_id: int, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        fo = conn.execute("SELECT * FROM folders WHERE id=? AND deleted_at IS NULL", (folder_id,)).fetchone()
        if not fo or not (p := can_access_folder(conn, user, fo)) or not p["delete"]:
            raise HTTPException(404, "Not found")
        conn.execute("UPDATE folders SET deleted_at=? WHERE id=?", (now_ts(), folder_id)); conn.commit()
        return {"ok": True}

@app.get("/api/files/{file_id}/download")
def download(file_id: int, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f or not (p := can_access_file(conn, user, f)) or not p["download"]:
            raise HTTPException(404, "Not found")
        audit(conn, "file_downloaded", f["name"], user=user, ip=client_ip(req)); conn.commit()
        path, nonce, size, name = FILES_DIR / f["storage_name"], f["base_nonce"], f["size"], f["name"]
    return StreamingResponse(decrypt_iter(path, nonce, str(file_id)), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{name}"', "Content-Length": str(size)})

@app.delete("/api/files/{file_id}")
def delete_file(file_id: int, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f or not (p := can_access_file(conn, user, f)) or not p["delete"]:
            raise HTTPException(404, "Not found")
        conn.execute("UPDATE files SET deleted_at=? WHERE id=?", (now_ts(), file_id))
        audit(conn, "file_deleted", f["name"], user=user, ip=client_ip(req)); conn.commit()
        return {"ok": True}

@app.post("/api/files/{file_id}/share")
async def share_file(file_id: int, req: Request):
    return await _share("file", file_id, req)

@app.post("/api/folders/{folder_id}/share")
async def share_folder(folder_id: int, req: Request):
    return await _share("folder", folder_id, req)

async def _share(rtype, rid, req: Request):
    user = require_user(req)
    body = await req.json()
    with closing(db()) as conn:
        table = "files" if rtype == "file" else "folders"
        res = conn.execute(f"SELECT * FROM {table} WHERE id=? AND deleted_at IS NULL", (rid,)).fetchone()
        if not res:
            raise HTTPException(404, "Not found")
        perms = can_access_file(conn, user, res) if rtype == "file" else can_access_folder(conn, user, res)
        if user["role"] != "admin" and res["owner_id"] != user["id"]:
            raise HTTPException(403, "Only the owner or an admin can share")
        exp = now_ts() + int(body["expires_days"]) * 86400 if body.get("expires_days") else None
        dl, ul, dele = (1 if body.get("can_download", True) else 0, 1 if body.get("can_upload") else 0,
                        1 if body.get("can_delete") else 0)
        if body.get("group"):
            g = conn.execute("SELECT * FROM groups_tbl WHERE name=?", (str(body["group"]).strip(),)).fetchone()
            if not g:
                raise HTTPException(400, "No such group")
            cur = conn.execute(
                "INSERT INTO group_shares(resource_type,resource_id,group_id,can_download,can_upload,can_delete,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (rtype, rid, g["id"], dl, ul, dele, exp, user["id"], now_ts()))
            conn.commit()
            audit(conn, "share_granted_group", f"{rtype}:{rid} -> group:{g['name']}", user=user, ip=client_ip(req)); conn.commit()
            return {"ok": True, "share_id": cur.lastrowid, "group": g["name"]}
        target = conn.execute("SELECT * FROM users WHERE username=?", (str(body.get("username", "")).strip().lower(),)).fetchone()
        if not target:
            raise HTTPException(400, "No such user")
        cur = conn.execute(
            "INSERT INTO shares(resource_type,resource_id,user_id,can_download,can_upload,can_delete,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (rtype, rid, target["id"], dl, ul, dele, exp, user["id"], now_ts()))
        conn.commit()
        audit(conn, "share_granted", f"{rtype}:{rid} -> {target['username']}", user=user, ip=client_ip(req)); conn.commit()
        return {"ok": True, "share_id": cur.lastrowid}

@app.get("/api/shares")
def list_shares(req: Request, resource_type: str, resource_id: int):
    user = require_user(req)
    with closing(db()) as conn:
        out = []
        for s in conn.execute("SELECT s.*, u.username, 'user' AS kind FROM shares s JOIN users u ON u.id=s.user_id WHERE s.resource_type=? AND s.resource_id=?", (resource_type, resource_id)):
            out.append(dict(s))
        for s in conn.execute("SELECT gs.*, g.name AS group_name, 'group' AS kind FROM group_shares gs JOIN groups_tbl g ON g.id=gs.group_id WHERE gs.resource_type=? AND gs.resource_id=?", (resource_type, resource_id)):
            out.append(dict(s))
        return out

@app.delete("/api/shares/{share_id}")
def delete_share(share_id: int, req: Request, kind: str = "user"):
    user = require_user(req)
    table = "group_shares" if kind == "group" else "shares"
    with closing(db()) as conn:
        s = conn.execute(f"SELECT * FROM {table} WHERE id=?", (share_id,)).fetchone()
        if not s:
            raise HTTPException(404, "Not found")
        if user["role"] != "admin" and s["created_by"] != user["id"]:
            raise HTTPException(403, "Not your share")
        conn.execute(f"DELETE FROM {table} WHERE id=?", (share_id,))
        audit(conn, "share_revoked", f"{kind}-share:{share_id}", user=user, ip=client_ip(req)); conn.commit()
        return {"ok": True}

# ---------- chunked uploads ----------
@app.post("/api/uploads/init")
async def upload_init(req: Request):
    user = require_user(req)
    body = await req.json()
    filename = str(body.get("filename", "")).strip()
    size = int(body.get("size", 0))
    folder_id = body.get("folder_id")
    if not filename or size <= 0:
        raise HTTPException(400, "Filename and size required")
    with closing(db()) as conn:
        max_bytes = int(get_setting(conn, "max_upload_gb", "25")) * 1024 ** 3
        if size > max_bytes:
            raise HTTPException(400, f"File exceeds the {get_setting(conn,'max_upload_gb','25')} GB limit")
        if folder_id:
            fo = conn.execute("SELECT * FROM folders WHERE id=? AND deleted_at IS NULL", (folder_id,)).fetchone()
            if not fo or not (p := can_access_folder(conn, user, fo)) or not p["upload"]:
                raise HTTPException(403, "No upload permission for that folder")
        if user.get("quota_bytes"):
            used = conn.execute("SELECT COALESCE(SUM(size),0) s FROM files WHERE owner_id=? AND deleted_at IS NULL", (user["id"],)).fetchone()["s"]
            if used + size > user["quota_bytes"]:
                raise HTTPException(400, "Storage quota exceeded")
        upload_id = secrets.token_hex(16)
        (TMP_DIR / upload_id).mkdir(parents=True, exist_ok=True)
        total_chunks = (size + UPLOAD_CHUNK_DEFAULT - 1) // UPLOAD_CHUNK_DEFAULT
        conn.execute("INSERT INTO uploads(id,user_id,filename,folder_id,total_size,chunk_size,total_chunks,created_at,mime) VALUES(?,?,?,?,?,?,?,?,?)",
                     (upload_id, user["id"], filename, folder_id, size, UPLOAD_CHUNK_DEFAULT, total_chunks, now_ts(), str(body.get("mime", ""))[:120]))
        conn.commit()
        return {"upload_id": upload_id, "chunk_size": UPLOAD_CHUNK_DEFAULT, "total_chunks": total_chunks}

@app.get("/api/uploads/{upload_id}/status")
def upload_status(upload_id: str, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        up = conn.execute("SELECT * FROM uploads WHERE id=? AND user_id=?", (upload_id, user["id"])).fetchone()
        if not up:
            raise HTTPException(404, "Not found")
        return {"received": json.loads(up["received"]), "status": up["status"], "total_chunks": up["total_chunks"]}

@app.put("/api/uploads/{upload_id}/chunk/{index}")
async def upload_chunk(upload_id: str, index: int, req: Request):
    user = require_user(req)
    data = await req.body()
    with closing(db()) as conn:
        up = conn.execute("SELECT * FROM uploads WHERE id=? AND user_id=? AND status='active'", (upload_id, user["id"])).fetchone()
        if not up or index < 0 or index >= up["total_chunks"]:
            raise HTTPException(404, "Upload not found")
        dest = TMP_DIR / upload_id / f"chunk_{index:06d}"
        with open(dest, "wb") as f:
            f.write(data)
        received = set(json.loads(up["received"])); received.add(index)
        conn.execute("UPDATE uploads SET received=? WHERE id=?", (json.dumps(sorted(received)), upload_id)); conn.commit()
        return {"ok": True, "received": len(received), "total_chunks": up["total_chunks"]}

@app.post("/api/uploads/{upload_id}/complete")
def upload_complete(upload_id: str, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        up = conn.execute("SELECT * FROM uploads WHERE id=? AND user_id=? AND status='active'", (upload_id, user["id"])).fetchone()
        if not up:
            raise HTTPException(404, "Upload not found")
        received = json.loads(up["received"])
        if len(received) != up["total_chunks"]:
            raise HTTPException(400, f"Missing chunks: {len(received)}/{up['total_chunks']}")
        # assemble
        assembled = TMP_DIR / f"{upload_id}.assembled"
        with open(assembled, "wb") as out:
            for i in range(up["total_chunks"]):
                with open(TMP_DIR / upload_id / f"chunk_{i:06d}", "rb") as cf:
                    shutil.copyfileobj(cf, out, 1024 * 1024)
        if assembled.stat().st_size != up["total_size"]:
            assembled.unlink(missing_ok=True)
            raise HTTPException(400, "Assembled size mismatch")
        # Virus scan of the assembled plaintext before it is encrypted/stored.
        if get_setting(conn, "av_scanning", "on") != "off":
            scan_status, scan_detail = clamav_scan(assembled)
        else:
            scan_status, scan_detail = "unscanned", "scanning disabled in settings"
        if scan_status == "infected":
            conn.execute("UPDATE uploads SET status='rejected_virus' WHERE id=?", (upload_id,))
            audit(conn, "upload_rejected_virus", f"{up['filename']} :: {scan_detail}", user=user, ip=client_ip(req))
            conn.commit()
            assembled.unlink(missing_ok=True)
            shutil.rmtree(TMP_DIR / upload_id, ignore_errors=True)
            raise HTTPException(400, f"File rejected — virus detected ({scan_detail})")
        owner_dir = FILES_DIR / str(user["id"]); owner_dir.mkdir(parents=True, exist_ok=True)
        storage_name = f"{user['id']}/{secrets.token_hex(16)}.enc"
        # create file row first to have an id for encryption AAD
        exp_days = int(get_setting(conn, "auto_expire_days", "0"))
        exp = now_ts() + exp_days * 86400 if exp_days > 0 else None
        cur = conn.execute("INSERT INTO files(name,folder_id,owner_id,size,storage_name,created_at,expires_at,mime,scan_status) VALUES(?,?,?,?,?,?,?,?,?)",
                           (up["filename"], up["folder_id"], user["id"], up["total_size"], storage_name, now_ts(), exp,
                            up["mime"] if "mime" in up.keys() else "", scan_status))
        file_id = cur.lastrowid; conn.commit()
    try:
        nonce, digest, size = encrypt_stream(assembled, FILES_DIR / storage_name, str(file_id))
    finally:
        assembled.unlink(missing_ok=True)
        shutil.rmtree(TMP_DIR / upload_id, ignore_errors=True)
    with closing(db()) as conn:
        conn.execute("UPDATE files SET sha256=?, base_nonce=? WHERE id=?", (digest, base64.b64encode(nonce).decode(), file_id))
        conn.execute("UPDATE uploads SET status='complete' WHERE id=?", (upload_id,))
        audit(conn, "file_uploaded", up["filename"], user=user, ip=client_ip(req)); conn.commit()
        f = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        return file_json(conn, user, f)

@app.post("/api/uploads/{upload_id}/abort")
def upload_abort(upload_id: str, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        conn.execute("UPDATE uploads SET status='aborted' WHERE id=? AND user_id=?", (upload_id, user["id"])); conn.commit()
    shutil.rmtree(TMP_DIR / upload_id, ignore_errors=True)
    return {"ok": True}

# ---------- previews & trash ----------
@app.get("/api/files/{file_id}/preview")
def preview(file_id: int, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f or not (p := can_access_file(conn, user, f)) or not p["download"]:
            raise HTTPException(404, "Not found")
        mime = f["mime"] or ""
        if not (mime.startswith("image/") or mime == "application/pdf"):
            raise HTTPException(400, "No preview for this file type")
        path, nonce, name = FILES_DIR / f["storage_name"], f["base_nonce"], f["name"]
    return StreamingResponse(decrypt_iter(path, nonce, str(file_id)), media_type=mime,
                             headers={"Content-Disposition": f'inline; filename="{name}"'})

@app.get("/api/trash")
def trash_list(req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        td = int(get_setting(conn, "trash_days", "30"))
        out = []
        for f in conn.execute("SELECT * FROM files WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC"):
            if user["role"] == "admin" or f["owner_id"] == user["id"]:
                d = file_json(conn, user, f)
                d["deleted_at"] = f["deleted_at"]
                d["purge_at"] = f["deleted_at"] + td * 86400
                out.append(d)
        return out

@app.post("/api/files/{file_id}/restore")
def restore_file(file_id: int, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NOT NULL", (file_id,)).fetchone()
        if not f or (user["role"] != "admin" and f["owner_id"] != user["id"]):
            raise HTTPException(404, "Not found")
        conn.execute("UPDATE files SET deleted_at=NULL WHERE id=?", (file_id,))
        audit(conn, "file_restored", f["name"], user=user, ip=client_ip(req)); conn.commit()
        return {"ok": True}

@app.delete("/api/files/{file_id}/purge")
def purge_file(file_id: int, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NOT NULL", (file_id,)).fetchone()
        if not f or (user["role"] != "admin" and f["owner_id"] != user["id"]):
            raise HTTPException(404, "Not found")
        storage = f["storage_name"]; name = f["name"]
        conn.execute("DELETE FROM files WHERE id=?", (file_id,))
        conn.execute("DELETE FROM shares WHERE resource_type='file' AND resource_id=?", (file_id,))
        audit(conn, "file_purged", name, user=user, ip=client_ip(req)); conn.commit()
    try:
        (FILES_DIR / storage).unlink(missing_ok=True)
    except Exception:
        pass
    return {"ok": True}

# ---------- share links (Phase 2) ----------
def _make_link(rtype, rid, req: Request):
    user = require_user(req)
    return user

async def _create_link(rtype, rid, req: Request):
    user = require_user(req)
    if not can_share_link(user):
        raise HTTPException(403, "Share links are not enabled for your account — ask the vault admin to enable them")
    body = await req.json()
    with closing(db()) as conn:
        table = "files" if rtype == "file" else "folders"
        res = conn.execute(f"SELECT * FROM {table} WHERE id=? AND deleted_at IS NULL", (rid,)).fetchone()
        if not res or (user["role"] != "admin" and res["owner_id"] != user["id"]):
            raise HTTPException(404, "Not found")
        days = int(body.get("expires_days", 7))
        exp = now_ts() + days * 86400 if days > 0 else None
        token = secrets.token_urlsafe(32)
        cur = conn.execute(
            "INSERT INTO share_links(token_hash,resource_type,resource_id,created_by,expires_at,max_downloads,created_at) VALUES(?,?,?,?,?,?,?)",
            (sha256_hex(token), rtype, rid, user["id"], exp, int(body.get("max_downloads", 0)), now_ts()))
        conn.commit()
        audit(conn, "share_link_created", f"{rtype}:{rid} days={days} maxdl={body.get('max_downloads', 0)}", user=user, ip=client_ip(req)); conn.commit()
        return {"ok": True, "url": f"{PUBLIC_URL}/s/{token}", "link_id": cur.lastrowid, "expires_at": exp}

@app.post("/api/files/{file_id}/link")
async def link_file(file_id: int, req: Request):
    return await _create_link("file", file_id, req)

@app.post("/api/folders/{folder_id}/link")
async def link_folder(folder_id: int, req: Request):
    return await _create_link("folder", folder_id, req)

def link_status(l, ts=None):
    """Computed share-link status + usage/time remaining, for list views."""
    ts = ts if ts is not None else now_ts()
    if l["revoked"]:
        status = "revoked"
    elif l["expires_at"] and l["expires_at"] < ts:
        status = "expired"
    elif l["max_downloads"] and l["downloads"] >= l["max_downloads"]:
        status = "exhausted"
    else:
        status = "active"
    uses_remaining = (l["max_downloads"] - l["downloads"]) if l["max_downloads"] else None
    secs_remaining = (l["expires_at"] - ts) if l["expires_at"] else None
    return {"status": status,
            "is_active": status == "active",
            "uses_remaining": uses_remaining,
            "seconds_remaining": secs_remaining,
            "days_remaining": round(secs_remaining / 86400, 2) if secs_remaining is not None else None}

@app.get("/api/links")
def my_links(req: Request, active_only: bool = False):
    user = require_user(req)
    with closing(db()) as conn:
        q = "SELECT l.*, u.username creator FROM share_links l JOIN users u ON u.id=l.created_by"
        rows = conn.execute(q + ("" if user["role"] == "admin" else " WHERE l.created_by=?") + " ORDER BY l.id DESC",
                            () if user["role"] == "admin" else (user["id"],))
        out = []
        for l in rows:
            d = dict(l); d.pop("token_hash", None)
            table = "files" if l["resource_type"] == "file" else "folders"
            r = conn.execute(f"SELECT name FROM {table} WHERE id=?", (l["resource_id"],)).fetchone()
            d["resource_name"] = r["name"] if r else "(deleted)"
            d.update(link_status(l))
            if active_only and not d["is_active"]:
                continue
            out.append(d)
        return out

@app.delete("/api/links/{link_id}")
def revoke_link(link_id: int, req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        l = conn.execute("SELECT * FROM share_links WHERE id=?", (link_id,)).fetchone()
        if not l or (user["role"] != "admin" and l["created_by"] != user["id"]):
            raise HTTPException(404, "Not found")
        conn.execute("UPDATE share_links SET revoked=1 WHERE id=?", (link_id,))
        audit(conn, "share_link_revoked", f"link:{link_id}", user=user, ip=client_ip(req)); conn.commit()
        return {"ok": True}

@app.post("/api/links/{link_id}/regenerate")
def regenerate_link(link_id: int, req: Request):
    """Issue a fresh token for an existing share link: the old URL dies immediately,
    downloads reset to 0, and the expiry window restarts at its original duration.
    Same limits. Creator or admin; non-admins also need the share-link permission."""
    user = require_user(req)
    with closing(db()) as conn:
        l = conn.execute("SELECT * FROM share_links WHERE id=?", (link_id,)).fetchone()
        if not l or (user["role"] != "admin" and l["created_by"] != user["id"]):
            raise HTTPException(404, "Not found")
        if not can_share_link(user):
            raise HTTPException(403, "Share links are not enabled for your account — ask the vault admin to enable them")
        duration = (l["expires_at"] - l["created_at"]) if (l["expires_at"] and l["created_at"]) else None
        new_exp = now_ts() + duration if duration else None
        token = secrets.token_urlsafe(32)
        conn.execute("UPDATE share_links SET token_hash=?, downloads=0, revoked=0, created_at=?, expires_at=? WHERE id=?",
                     (sha256_hex(token), now_ts(), new_exp, link_id))
        audit(conn, "share_link_regenerated", f"link:{link_id}", user=user, ip=client_ip(req)); conn.commit()
        return {"ok": True, "url": f"{PUBLIC_URL}/s/{token}", "link_id": link_id, "expires_at": new_exp}

def _valid_link(conn, token):
    l = conn.execute("SELECT * FROM share_links WHERE token_hash=?", (sha256_hex(token),)).fetchone()
    if not l or l["revoked"]:
        return None
    if l["expires_at"] and l["expires_at"] < now_ts():
        return None
    if l["max_downloads"] and l["downloads"] >= l["max_downloads"]:
        return None
    return l

@app.get("/s/{token}", response_class=HTMLResponse)
def share_link_page(token: str):
    with closing(db()) as conn:
        l = _valid_link(conn, token)
        if not l:
            return HTMLResponse("<!doctype html><meta charset=utf-8><title>Link unavailable</title><link rel=stylesheet href=/static/style.css><main class=card><h1>Link unavailable</h1><p>This share link is invalid, expired, revoked, or has reached its download limit.</p></main>", status_code=410)
        if l["resource_type"] == "file":
            f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (l["resource_id"],)).fetchone()
            if not f:
                return HTMLResponse("<main class=card><h1>File gone</h1></main>", status_code=410)
            body = f"<h1>📄 {f['name']}</h1><p>{f['size']} bytes</p><p><a href='/s/{token}/download'><button>Download</button></a></p>"
        else:
            fo = conn.execute("SELECT * FROM folders WHERE id=? AND deleted_at IS NULL", (l["resource_id"],)).fetchone()
            if not fo:
                return HTMLResponse("<main class=card><h1>Folder gone</h1></main>", status_code=410)
            items = conn.execute("SELECT * FROM files WHERE folder_id=? AND deleted_at IS NULL ORDER BY name", (fo["id"],)).fetchall()
            lis = "".join(f"<li>{x['name']} ({x['size']} bytes) — <a href='/s/{token}/download?file_id={x['id']}'>Download</a></li>" for x in items)
            body = f"<h1>📁 {fo['name']}</h1><ul>{lis or '<li>Empty folder</li>'}</ul>"
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>Shared with you</title><link rel=stylesheet href=/static/style.css><main class=card style='max-width:640px'>{body}<p class=msg>Shared via Fixin Hixon Vault. Downloads are logged.</p></main>")

@app.get("/s/{token}/download")
def share_link_download(token: str, req: Request, file_id: int = 0):
    with closing(db()) as conn:
        l = _valid_link(conn, token)
        if not l:
            raise HTTPException(410, "Link unavailable")
        if l["resource_type"] == "file":
            fid = l["resource_id"]
        else:
            fid = file_id
            chk = conn.execute("SELECT id FROM files WHERE id=? AND folder_id=? AND deleted_at IS NULL", (fid, l["resource_id"])).fetchone()
            if not chk:
                raise HTTPException(404, "Not found")
        f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (fid,)).fetchone()
        if not f:
            raise HTTPException(404, "Not found")
        conn.execute("UPDATE share_links SET downloads=downloads+1 WHERE id=?", (l["id"],))
        audit(conn, "share_link_download", f["name"], username="sharelink", ip=client_ip(req)); conn.commit()
        path, nonce, size, name = FILES_DIR / f["storage_name"], f["base_nonce"], f["size"], f["name"]
    return StreamingResponse(decrypt_iter(path, nonce, str(fid)), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{name}"', "Content-Length": str(size)})

# ---------- cleanup job ----------
def run_cleanup():
    counts = {"purged": 0, "expired_to_trash": 0, "uploads_cleaned": 0}
    with closing(db()) as conn:
        td = int(get_setting(conn, "trash_days", "30"))
        cutoff = now_ts() - td * 86400
        blobs = []
        for f in conn.execute("SELECT * FROM files WHERE deleted_at IS NOT NULL AND deleted_at<?", (cutoff,)):
            blobs.append(f["storage_name"])
            conn.execute("DELETE FROM files WHERE id=?", (f["id"],))
            counts["purged"] += 1
        for f in conn.execute("SELECT * FROM files WHERE deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at<?", (now_ts(),)):
            conn.execute("UPDATE files SET deleted_at=? WHERE id=?", (now_ts(), f["id"]))
            counts["expired_to_trash"] += 1
        stale = now_ts() - 86400
        for up in conn.execute("SELECT * FROM uploads WHERE status='active' AND created_at<?", (stale,)):
            conn.execute("UPDATE uploads SET status='aborted' WHERE id=?", (up["id"],))
            shutil.rmtree(TMP_DIR / up["id"], ignore_errors=True)
            counts["uploads_cleaned"] += 1
        conn.commit()
    for b in blobs:
        try:
            (FILES_DIR / b).unlink(missing_ok=True)
        except Exception:
            pass
    return counts

@app.post("/api/admin/run-cleanup")
def admin_cleanup(req: Request):
    require_admin(req)
    return run_cleanup()

async def _cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            run_cleanup()
        except Exception as e:
            print(f"cleanup error: {e}", flush=True)

@app.on_event("startup")
async def _start_cleanup():
    asyncio.get_event_loop().create_task(_cleanup_loop())

# ---------- admin ----------
def _resource_label(conn, rtype, rid):
    t = "files" if rtype == "file" else "folders"
    r = conn.execute(f"SELECT f.name, u.username AS owner FROM {t} f JOIN users u ON u.id=f.owner_id WHERE f.id=?",
                     (rid,)).fetchone()
    return (r["name"], r["owner"]) if r else ("(deleted)", "")

@app.get("/api/admin/files")
def admin_files(req: Request, owner: str = "", q: str = ""):
    require_admin(req)
    with closing(db()) as conn:
        rows = conn.execute(
            """SELECT f.*, u.username AS owner, fo.name AS folder_name FROM files f
               JOIN users u ON u.id=f.owner_id LEFT JOIN folders fo ON fo.id=f.folder_id
               WHERE f.deleted_at IS NULL ORDER BY f.created_at DESC""").fetchall()
        out = []
        for f in rows:
            if owner and f["owner"] != owner:
                continue
            if q and q.lower() not in f["name"].lower():
                continue
            d = dict(f)
            d["user_shares"] = conn.execute("SELECT COUNT(*) c FROM shares WHERE resource_type='file' AND resource_id=?", (f["id"],)).fetchone()["c"]
            d["group_shares"] = conn.execute("SELECT COUNT(*) c FROM group_shares WHERE resource_type='file' AND resource_id=?", (f["id"],)).fetchone()["c"]
            d["links"] = conn.execute("SELECT COUNT(*) c FROM share_links WHERE resource_type='file' AND resource_id=? AND revoked=0 AND (expires_at IS NULL OR expires_at>?)", (f["id"], now_ts())).fetchone()["c"]
            d.pop("storage_name", None); d.pop("base_nonce", None)
            out.append(d)
        folders = []
        for fo in conn.execute("SELECT fo.*, u.username AS owner FROM folders fo JOIN users u ON u.id=fo.owner_id WHERE fo.deleted_at IS NULL ORDER BY fo.name"):
            if owner and fo["owner"] != owner:
                continue
            d = dict(fo)
            d["user_shares"] = conn.execute("SELECT COUNT(*) c FROM shares WHERE resource_type='folder' AND resource_id=?", (fo["id"],)).fetchone()["c"]
            d["group_shares"] = conn.execute("SELECT COUNT(*) c FROM group_shares WHERE resource_type='folder' AND resource_id=?", (fo["id"],)).fetchone()["c"]
            folders.append(d)
        return {"files": out, "folders": folders}

@app.delete("/api/admin/files/{file_id}")
def admin_trash_file(file_id: int, req: Request):
    admin = require_admin(req)
    with closing(db()) as conn:
        f = conn.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f:
            raise HTTPException(404, "Not found")
        conn.execute("UPDATE files SET deleted_at=? WHERE id=?", (now_ts(), file_id))
        audit(conn, "admin_trashed_file", f"{f['name']} (owner {f['owner_id']})", user=admin, ip=client_ip(req)); conn.commit()
        return {"ok": True}

@app.delete("/api/admin/folders/{folder_id}")
def admin_trash_folder(folder_id: int, req: Request):
    admin = require_admin(req)
    with closing(db()) as conn:
        fo = conn.execute("SELECT * FROM folders WHERE id=? AND deleted_at IS NULL", (folder_id,)).fetchone()
        if not fo:
            raise HTTPException(404, "Not found")
        conn.execute("UPDATE folders SET deleted_at=? WHERE id=?", (now_ts(), folder_id))
        audit(conn, "admin_trashed_folder", f"{fo['name']} (owner {fo['owner_id']})", user=admin, ip=client_ip(req)); conn.commit()
        return {"ok": True}

@app.get("/api/admin/shares")
def admin_shares(req: Request):
    require_admin(req)
    with closing(db()) as conn:
        out = []
        for s in conn.execute("SELECT s.*, u.username AS target, c.username AS granted_by FROM shares s JOIN users u ON u.id=s.user_id JOIN users c ON c.id=s.created_by ORDER BY s.created_at DESC"):
            d = dict(s); d["kind"] = "user"
            d["resource_name"], d["owner"] = _resource_label(conn, s["resource_type"], s["resource_id"])
            out.append(d)
        for s in conn.execute("SELECT gs.*, g.name AS target, c.username AS granted_by FROM group_shares gs JOIN groups_tbl g ON g.id=gs.group_id JOIN users c ON c.id=gs.created_by ORDER BY gs.created_at DESC"):
            d = dict(s); d["kind"] = "group"
            d["resource_name"], d["owner"] = _resource_label(conn, s["resource_type"], s["resource_id"])
            out.append(d)
        out.sort(key=lambda d: d["created_at"], reverse=True)
        return out

@app.get("/api/sharing")
def sharing_overview(req: Request):
    user = require_user(req)
    with closing(db()) as conn:
        by_me, with_me = [], []
        for s in conn.execute("SELECT s.*, u.username AS target FROM shares s JOIN users u ON u.id=s.user_id WHERE s.created_by=?", (user["id"],)):
            d = dict(s); d["kind"] = "user"
            d["resource_name"], d["owner"] = _resource_label(conn, s["resource_type"], s["resource_id"])
            by_me.append(d)
        for s in conn.execute("SELECT gs.*, g.name AS target FROM group_shares gs JOIN groups_tbl g ON g.id=gs.group_id WHERE gs.created_by=?", (user["id"],)):
            d = dict(s); d["kind"] = "group"
            d["resource_name"], d["owner"] = _resource_label(conn, s["resource_type"], s["resource_id"])
            by_me.append(d)
        for s in conn.execute("SELECT s.* FROM shares s WHERE s.user_id=?", (user["id"],)):
            d = dict(s); d["kind"] = "user"; d["via"] = "direct"
            d["resource_name"], d["owner"] = _resource_label(conn, s["resource_type"], s["resource_id"])
            with_me.append(d)
        for s in conn.execute("""SELECT gs.*, g.name AS gname FROM group_shares gs JOIN groups_tbl g ON g.id=gs.group_id
                                  JOIN group_members gm ON gm.group_id=gs.group_id WHERE gm.user_id=?""", (user["id"],)):
            d = dict(s); d["kind"] = "group"; d["via"] = f"group {s['gname']}"
            d["resource_name"], d["owner"] = _resource_label(conn, s["resource_type"], s["resource_id"])
            with_me.append(d)
        return {"by_me": by_me, "with_me": with_me}

@app.get("/api/admin/stats")
def admin_stats(req: Request):
    require_admin(req)
    with closing(db()) as conn:
        total, used, free = shutil.disk_usage(DATA_DIR)
        return {"users": conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
                "files": conn.execute("SELECT COUNT(*) c FROM files WHERE deleted_at IS NULL").fetchone()["c"],
                "files_bytes": conn.execute("SELECT COALESCE(SUM(size),0) s FROM files WHERE deleted_at IS NULL").fetchone()["s"],
                "disk_free": free, "disk_total": total}

@app.get("/api/admin/users")
def admin_users(req: Request):
    require_admin(req)
    with closing(db()) as conn:
        return [dict(r) for r in conn.execute(
            """SELECT u.id,u.username,u.email,u.display_name,u.role,u.active,u.quota_bytes,u.created_at,u.can_share_link,
               (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id AND f.deleted_at IS NULL) AS file_count,
               (SELECT COALESCE(SUM(size),0) FROM files f WHERE f.owner_id=u.id AND f.deleted_at IS NULL) AS files_bytes
               FROM users u ORDER BY u.username""")]

@app.post("/api/admin/users")
async def admin_create_user(req: Request):
    admin = require_admin(req)
    body = await req.json()
    username = str(body.get("username", "")).strip().lower()
    email = str(body.get("email", "")).strip()
    if not username or "@" not in email:
        raise HTTPException(400, "Username and a valid email are required")
    with closing(db()) as conn:
        try:
            role = "admin" if body.get("role") == "admin" else "user"
            link_flag = 1 if (role == "admin" or body.get("can_share_link")) else 0
            cur = conn.execute("INSERT INTO users(username,email,display_name,role,active,quota_bytes,created_at,can_share_link) VALUES(?,?,?,?,1,?,?,?)",
                               (username, email, str(body.get("display_name", "")), role,
                                body.get("quota_bytes"), now_ts(), link_flag))
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Username already exists")
        audit(conn, "user_created", username, user=admin, ip=client_ip(req)); conn.commit()
        return {"ok": True, "id": cur.lastrowid}

@app.patch("/api/admin/users/{user_id}")
async def admin_patch_user(user_id: int, req: Request):
    admin = require_admin(req)
    require_reauth(req, admin)
    body = await req.json()
    allowed = {"email", "display_name", "role", "active", "quota_bytes", "can_share_link"}
    sets = {k: v for k, v in body.items() if k in allowed}
    if not sets:
        raise HTTPException(400, "Nothing to change")
    with closing(db()) as conn:
        conn.execute(f"UPDATE users SET {', '.join(f'{k}=?' for k in sets)} WHERE id=?", (*sets.values(), user_id))
        if sets.get("active") == 0:
            conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))
        conn.commit()
        audit(conn, "user_updated", f"id:{user_id} {list(sets)}", user=admin, ip=client_ip(req)); conn.commit()
        return {"ok": True}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, req: Request, owned_files: str = "transfer"):
    """Permanently delete a user. owned_files: 'transfer' (to the deleting admin, default)
    or 'delete' (remove their files and encrypted blobs too).
    Guards: cannot delete yourself; cannot delete the last admin."""
    admin = require_admin(req)
    require_reauth(req, admin)
    if owned_files not in ("transfer", "delete"):
        raise HTTPException(400, "owned_files must be 'transfer' or 'delete'")
    if user_id == admin["id"]:
        raise HTTPException(400, "You cannot delete your own account")
    blobs = []
    with closing(db()) as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "No such user")
        if target["role"] == "admin":
            admins = conn.execute("SELECT COUNT(*) c FROM users WHERE role='admin' AND active=1").fetchone()["c"]
            if admins <= 1:
                raise HTTPException(400, "Cannot delete the last admin")
        if owned_files == "delete":
            blobs = [r["storage_name"] for r in conn.execute(
                "SELECT storage_name FROM files WHERE owner_id=?", (user_id,))]
            conn.execute("DELETE FROM files WHERE owner_id=?", (user_id,))
            conn.execute("DELETE FROM folders WHERE owner_id=?", (user_id,))
        else:
            conn.execute("UPDATE files SET owner_id=? WHERE owner_id=?", (admin["id"], user_id))
            conn.execute("UPDATE folders SET owner_id=? WHERE owner_id=?", (admin["id"], user_id))
        conn.execute("DELETE FROM shares WHERE user_id=? OR created_by=?", (user_id, user_id))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM login_tokens WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM uploads WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        audit(conn, "user_deleted", f"{target['username']} files={owned_files}", user=admin, ip=client_ip(req))
        conn.commit()
    for name in blobs:
        try:
            (FILES_DIR / name).unlink(missing_ok=True)
        except Exception:
            pass
    return {"ok": True, "username": target["username"], "files": owned_files}

@app.post("/api/admin/users/{user_id}/revoke-sessions")
def admin_revoke(user_id: int, req: Request):
    admin = require_admin(req)
    with closing(db()) as conn:
        conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,)); conn.commit()
        return {"ok": True}

# ---------- groups (admin) ----------
@app.get("/api/admin/groups")
def admin_groups(req: Request):
    require_admin(req)
    with closing(db()) as conn:
        out = []
        for g in conn.execute("SELECT * FROM groups_tbl ORDER BY name"):
            members = [r["username"] for r in conn.execute(
                "SELECT u.username FROM group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=? ORDER BY u.username", (g["id"],))]
            out.append({"id": g["id"], "name": g["name"], "members": members})
        return out

@app.post("/api/admin/groups")
async def admin_create_group(req: Request):
    admin = require_admin(req)
    body = await req.json()
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(400, "Name required")
    with closing(db()) as conn:
        try:
            cur = conn.execute("INSERT INTO groups_tbl(name,created_at) VALUES(?,?)", (name, now_ts())); conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Group already exists")
        audit(conn, "group_created", name, user=admin, ip=client_ip(req)); conn.commit()
        return {"ok": True, "id": cur.lastrowid}

@app.delete("/api/admin/groups/{group_id}")
def admin_delete_group(group_id: int, req: Request):
    admin = require_admin(req)
    with closing(db()) as conn:
        conn.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
        conn.execute("DELETE FROM group_shares WHERE group_id=?", (group_id,))
        conn.execute("DELETE FROM groups_tbl WHERE id=?", (group_id,))
        audit(conn, "group_deleted", f"id:{group_id}", user=admin, ip=client_ip(req)); conn.commit()
        return {"ok": True}

@app.post("/api/admin/groups/{group_id}/members")
async def admin_group_add_member(group_id: int, req: Request):
    admin = require_admin(req)
    body = await req.json()
    with closing(db()) as conn:
        u = conn.execute("SELECT * FROM users WHERE username=?", (str(body.get("username", "")).strip().lower(),)).fetchone()
        if not u:
            raise HTTPException(400, "No such user")
        conn.execute("INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)", (group_id, u["id"])); conn.commit()
        return {"ok": True}

@app.delete("/api/admin/groups/{group_id}/members/{user_id}")
def admin_group_remove_member(group_id: int, user_id: int, req: Request):
    require_admin(req)
    with closing(db()) as conn:
        conn.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id)); conn.commit()
        return {"ok": True}

@app.get("/api/admin/audit")
def admin_audit(req: Request, limit: int = 200):
    require_admin(req)
    with closing(db()) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (min(limit, 1000),))]

@app.get("/api/admin/settings")
def admin_get_settings(req: Request):
    require_admin(req)
    with closing(db()) as conn:
        return {r["key"]: r["value"] for r in conn.execute("SELECT * FROM settings")}

@app.put("/api/admin/settings")
async def admin_put_settings(req: Request):
    admin = require_admin(req)
    require_reauth(req, admin)
    body = await req.json()
    with closing(db()) as conn:
        for k, v in body.items():
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
        conn.commit()
        audit(conn, "settings_updated", ",".join(body.keys()), user=admin, ip=client_ip(req)); conn.commit()
        return {"ok": True}

# ---------- static ----------
STATIC_DIR = Path(__file__).parent.parent / "static"

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/static/{name}")
def static_file(name: str):
    p = STATIC_DIR / Path(name).name
    if not p.exists():
        raise HTTPException(404, "Not found")
    return FileResponse(p)
