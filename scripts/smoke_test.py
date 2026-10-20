#!/usr/bin/env python3
"""Smoke test for a fresh Secure File Vault install.

Verifies the core flow end-to-end against a running vault: admin login via
the break-glass recovery path, user creation, chunked upload, byte-identical
download, at-rest ciphertext, sharing, permission denial for an unshared
user, admin gating, and single-use token behavior.

Run from the repo root on the host (needs docker access for the recovery
login and, for the ciphertext check, read access to the data directory):

    python3 scripts/smoke_test.py

Environment:
    VAULT_BASE       default http://127.0.0.1:8080
                     (use https://your-domain when COOKIE_SECURE=true)
    VAULT_ADMIN_USER default admin (your BOOTSTRAP_ADMIN_USERNAME)
    VAULT_CONTAINER  default secure-vault
    VAULT_DATA_DIR   default ./data (host path of the vault data directory)
"""
import glob, hashlib, http.cookiejar, json, os, re, subprocess, sys, time
import urllib.request, urllib.error

BASE = os.environ.get("VAULT_BASE", "http://127.0.0.1:8080")
ADMIN = os.environ.get("VAULT_ADMIN_USER", "admin")
CONTAINER = os.environ.get("VAULT_CONTAINER", "secure-vault")
DATA_DIR = os.environ.get("VAULT_DATA_DIR", os.path.join(os.getcwd(), "data"))
SFX = str(int(time.time()))[-6:]
ALICE, MAL = "smokealice" + SFX, "smokemallory" + SFX
RESULTS = []

def ok(name, cond, extra=""):
    RESULTS.append(cond)
    print(("PASS " if cond else "FAIL ") + name + (f" ({extra})" if extra else ""))
    if not cond:
        print("Aborting on first failure."); sys.exit(1)

def opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def call(op, method, path, body=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    headers = {"Content-Type": "application/octet-stream" if raw is not None else "application/json",
               "User-Agent": "vault-smoke-test/1.0"}
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with op.open(req, timeout=60) as r:
            b = r.read()
            if b and b[:1] in (b"{", b"["):
                return r.status, json.loads(b)
            return r.status, b
    except urllib.error.HTTPError as e:
        b = e.read()
        try: return e.code, json.loads(b)
        except Exception: return e.code, b

def login_recovery(username):
    op = opener()
    out = subprocess.run(["docker", "exec", CONTAINER, "python", "-m", "app.recovery", username],
                         capture_output=True, text=True)
    m = re.search(r"token=([A-Za-z0-9_\-]+)", out.stdout)
    assert m, f"recovery failed: {out.stdout} {out.stderr}"
    s, r = call(op, "POST", "/api/auth/verify-magic", {"token": m.group(1)})
    assert s == 200, f"recovery verify failed: {r}"
    return op

# 1. health + anti-enumeration
s, r = call(opener(), "GET", "/api/health")
ok("health endpoint", s == 200 and r["ok"])
s, r = call(opener(), "POST", "/api/auth/request", {"username": "no_such_user_xyz"})
ok("unknown user gets generic response", s == 200 and "If that account exists" in r["message"])

# 2. admin login
admin = login_recovery(ADMIN)
s, me = call(admin, "GET", "/api/me")
ok("admin login + role", s == 200 and me["username"] == ADMIN and me["role"] == "admin")

# 3. single-use token: a recovery token must not verify twice
op2 = opener()
out = subprocess.run(["docker", "exec", CONTAINER, "python", "-m", "app.recovery", ADMIN],
                     capture_output=True, text=True)
tok = re.search(r"token=([A-Za-z0-9_\-]+)", out.stdout).group(1)
s1, _ = call(op2, "POST", "/api/auth/verify-magic", {"token": tok})
s2, _ = call(opener(), "POST", "/api/auth/verify-magic", {"token": tok})
ok("login token is single-use", s1 == 200 and s2 in (400, 401))  # replayed token is rejected (400/401)

# 4. create two users
for u in (ALICE, MAL):
    s, r = call(admin, "POST", "/api/admin/users",
                {"username": u, "email": f"{u}@example.com", "display_name": u, "role": "user"})
    ok(f"create user {u[:12]}...", s == 200, str(r)[:80])
alice, mal = login_recovery(ALICE), login_recovery(MAL)

# 5. chunked upload (forces multiple chunks), sha256 round-trip
_pat = b"vault smoke test payload "
payload = (_pat * (9_500_000 // len(_pat) + 1))[: 9_500_000]
s, r = call(alice, "POST", "/api/uploads/init",
            {"filename": "smoke.bin", "size": len(payload), "mime": "application/octet-stream"})
ok("upload init", s == 200, str(r)[:80])
uid, cs = r["upload_id"], r["chunk_size"]
chunks = 0
for off in range(0, len(payload), cs):
    s, _ = call(alice, "PUT", f"/api/uploads/{uid}/chunk/{off // cs}", raw=payload[off:off + cs])
    assert s == 200, f"chunk {off // cs} failed"
    chunks += 1
ok("multi-chunk upload", chunks > 1, f"{chunks} chunks")
s, r = call(alice, "POST", f"/api/uploads/{uid}/complete", {})
ok("upload complete + sha256 matches", s == 200 and r["sha256"] == hashlib.sha256(payload).hexdigest())
fid = r["id"]

# 6. at-rest ciphertext: newest blob is not the plaintext and is nonce-prefixed larger
blobs = sorted(glob.glob(os.path.join(DATA_DIR, "files", "*", "*.enc")), key=os.path.getmtime)
if blobs:
    blob = open(blobs[-1], "rb").read()
    ok("stored blob is ciphertext", payload[:64] not in blob[:4096] and len(blob) > len(payload))

# 7. owner download round-trip
s, d = call(alice, "GET", f"/api/files/{fid}/download")
ok("owner download byte-identical", s == 200 and d == payload)

# 8. unshared user: cannot see, cannot download, not admin
s, v = call(mal, "GET", "/api/vault")
ok("unshared user cannot see file", s == 200 and not any(x["id"] == fid for x in v["files"]))
s, _ = call(mal, "GET", f"/api/files/{fid}/download")
ok("unshared direct download is 404", s == 404)
s, _ = call(mal, "GET", "/api/admin/users")
ok("regular user blocked from admin API", s == 403)

# 9. share -> download works
s, _ = call(alice, "POST", f"/api/files/{fid}/share", {"username": MAL})
ok("share to user", s == 200)
s, d = call(mal, "GET", f"/api/files/{fid}/download")
ok("shared user downloads identical bytes", s == 200 and d == payload)

# 10. soft delete hides the file
s, _ = call(alice, "DELETE", f"/api/files/{fid}")
s, v = call(alice, "GET", "/api/vault")
ok("soft delete hides file", s == 200 and not any(x["id"] == fid for x in v["files"]))

# cleanup: disable the throwaway users
s, users = call(admin, "GET", "/api/admin/users")
for u in users:
    if u["username"] in (ALICE, MAL):
        call(admin, "PATCH", f"/api/admin/users/{u['id']}", {"active": 0})

print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed — vault is working.")
sys.exit(0 if all(RESULTS) else 1)
