"""Break-glass recovery: generate a one-time magic login token for a user.
Usage (on the host): docker compose exec vault python -m app.recovery <username>
Prints a login URL valid for 60 minutes. Does not depend on email delivery.
"""
import sys, time, secrets
from contextlib import closing
from .main import db, sha256_hex, PUBLIC_URL

def main():
    username = (sys.argv[1] if len(sys.argv) > 1 else "jason").lower()
    with closing(db()) as conn:
        u = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if not u:
            print(f"No active user '{username}'"); sys.exit(1)
        magic = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO login_tokens(user_id,code_hash,magic_hash,expires_at,created_ip,created_at) VALUES(?,?,?,?,?,?)",
                     (u["id"], None, sha256_hex(magic), int(time.time()) + 3600, "recovery", int(time.time())))
        conn.commit()
    print(f"Recovery login (60 min, one use): {PUBLIC_URL}/auth/magic?token={magic}")

if __name__ == "__main__":
    main()
