# Secure File Vault

A self-hosted file vault for people you know: share big files with family,
friends, or a small team from **your own server**, with a real login system
and real permissions — but **no passwords anywhere**.

Users sign in with a one-time code (plus a magic link) sent to their email.
Files up to 10 GB+ upload in resumable chunks. Everything is encrypted at
rest. You manage users, groups, shares, and settings from a web admin panel.

![status](https://img.shields.io/badge/self--hosted-Docker-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## Features

- **Passwordless login** — enter your username, get a 6-digit code *and* a
  magic link by email (the link lands on a confirm page first, so mail
  scanners can't burn it). Tokens are stored hashed, expire in 15 minutes,
  are single-use and rate-limited. There is no password database to leak.
- **Encryption at rest** — files are stored as chunked AES-256-GCM
  ciphertext (4 MiB chunks, per-file nonce) under random filenames; the key
  lives only in your server's config.
- **Virus scanning** — every upload is scanned by a ClamAV sidecar before
  it is encrypted and stored; infected files are rejected.
- **Private by default** — per-file and per-folder permissions enforced
  server-side on every request. Guess an unshared file's ID and you get a
  404, not a hint it exists.
- **Sharing that fits real life** — share files/folders with specific users
  or groups (download / upload / delete permission bits, optional expiry),
  and create **anonymous share links** with expiry dates and download
  limits (optionally restricted to accounts you approve). A status view
  shows every link's uses and time remaining; revoke any of them instantly.
- **Admin panel** — users (create/edit/disable/delete, quotas, per-user
  share-link permission), groups, a view of **every file and every share**
  in the vault, settings, and a full audit log.
- **Sessions you control** — see your signed-in devices, revoke any of
  them; sensitive admin actions require a recent login (step-up re-auth).
- **Trash & lifecycle** — soft-delete with restore, automatic purge,
  optional per-file auto-expiry, and cleanup of abandoned uploads.
- **Break-glass recovery** — locked out because email is down? A one-time
  login link can be generated from the server terminal. Nobody is ever
  locked out of their own vault.

## Quick start

You need a machine with Docker (x86_64 or ARM64) and ~a few GB of free
disk beyond the files you'll store.

### Option A — let an AI agent do it

Clone this repo, open it with your AI coding agent (Claude Code, Cursor,
Codex, …) and say: **"Set up the vault for me following AGENTS.md."**
The agent will ask you a handful of questions (local vs public, admin
account, where the data lives), do the whole install, and verify it with
you. [`AGENTS.md`](AGENTS.md) is the complete playbook it follows.

### Option B — the setup script

```bash
git clone https://github.com/thefixinhixon/secure-file-vault.git
cd secure-file-vault
./setup.sh
```

The script checks prerequisites, asks the same questions, generates your
encryption key, writes the config, builds and starts the vault, and tells
you how to log in for the first time.

### Option C — fully manual

```bash
cp .env.example .env
# fill in .env — at minimum set VAULT_KEY_B64 (openssl rand -base64 32)
# and the BOOTSTRAP_ADMIN_* values; see .env.example for every variable
mkdir -p data/{files,tmp,db,logs}
docker compose up -d --build
curl http://127.0.0.1:8080/api/health
```

By default the vault listens on **127.0.0.1:8080 only**. In the default
`console` email mode, login codes print to the container log
(`docker compose logs vault | grep LOGIN_EMAIL`), which is perfect for
trying it out and for LAN-only use.

> ⚠️ **Back up your encryption key.** `VAULT_KEY_B64` in `.env` is the
> only thing that can decrypt stored files. Put a copy in a password
> manager or on paper somewhere safe, separate from the server. Lose it
> and the files are gone — that's what "encrypted" means.

## Going public

The vault is designed to sit behind a **Cloudflare Tunnel** — no open
ports, no public IP, free HTTPS:

1. Get real email working: create a [Resend](https://resend.com) account
   (free tier: 3,000 emails/month), add and verify your domain (publish
   the DKIM/SPF records Resend shows you — they live on the `send`
   subdomain, so your existing mail setup is untouched — and add a DMARC
   record if you have none), and create a **sending-only** API key.
2. In `.env`: `EMAIL_MODE=resend`, `RESEND_API_KEY=…`,
   `EMAIL_FROM=Vault <vault@yourdomain>`, `PUBLIC_URL=https://yourdomain`,
   `COOKIE_SECURE=true`.
3. Create a tunnel in the Cloudflare dashboard (Zero Trust → Networks →
   Tunnels) pointing your hostname at `http://vault:8080`, put its token
   in `tunnel.env` as `TUNNEL_TOKEN=…`, and start everything:
   `docker compose --profile public up -d`.

Any other HTTPS reverse proxy (Caddy, nginx, Traefik) works just as well —
the requirements are simply: HTTPS in front, and the app never exposed raw.

## Verifying your install

```bash
python3 scripts/smoke_test.py
```

Creates throwaway users and checks the whole flow: login, chunked upload,
byte-identical download, ciphertext at rest, sharing, permission denial
for unshared users, and admin gating. Uses `VAULT_BASE` if your vault
isn't at `http://127.0.0.1:8080`.

## Backups

`scripts/backup.sh` snapshots the database, the config (including the
encryption key) and the code into a timestamped folder — put the
destination on a **different disk** and run it nightly from cron:

```bash
BACKUP_DEST=/mnt/backupdisk/vault-backups scripts/backup.sh
```

File contents are backed up only if you also copy the data directory's
`files/` — decide based on whether your users' files are re-obtainable.

## Configuration

Everything is in `.env` (see [`.env.example`](.env.example) for the
annotated template): encryption key, public URL, email mode/keys, cookie
mode, and the first-run admin account. Compose-level values (data
directory, host port, uid/gid) are documented in
[`docker-compose.yml`](docker-compose.yml). Runtime-editable settings
(virus scanning on/off, trash retention, auto-expiry default, quotas) live
in the Admin UI.

## Security model, briefly

No passwords stored, ever. Login tokens: SHA-256-hashed, 15-minute expiry,
single-use, attempt-capped, rate-limited (per user and per IP), with a
generic anti-enumeration response. Sessions: random tokens, hashed
server-side, HttpOnly cookies, individually revocable. Authorization is
checked on the server for every single request — the UI hiding a button is
never the security boundary. Uploads are virus-scanned, then encrypted,
then stored under random names. All security-relevant actions land in the
audit log.

This is a personal/small-team tool built for a trusted user base (think
~20 people you know), not a hardened multi-tenant SaaS. Run it behind the
tunnel, keep the host patched, back up the key.

## Project layout

```
app/main.py        the application (FastAPI) — auth, ACL, uploads, crypto, admin
app/recovery.py    break-glass one-time login URL generator
static/            the web UI (plain HTML/CSS/JS, no build step)
scripts/           backup.sh, smoke_test.py
setup.sh           interactive installer
AGENTS.md          the AI-agent setup playbook
docker-compose.yml vault + ClamAV + optional cloudflared tunnel
```

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship your own.
