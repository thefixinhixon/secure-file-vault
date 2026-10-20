# Setting up Secure File Vault — instructions for AI agents

You are helping the user install **their own** Secure File Vault from this
repository on **their own** server. By the end, they will have a running,
verified vault and know how to log in. The user answers a few questions and
approves anything public-facing or destructive; you do the rest.

Humans can run `./setup.sh` instead — it does the same core install. Follow
this document when the user asks you to set it up for them.

## Ground rules

- **Secrets discipline.** The vault's encryption key (`VAULT_KEY_B64`) and
  any API keys are generated and stored *on the user's machine only*, in a
  `.env` file with mode 600. Never print a secret's full value into the
  chat, a log, a commit, or a summary. Refer to keys by name and location.
  If the user pastes a live API key into chat anyway, use it once for the
  step at hand, store it in `.env`, and remind them it appeared in chat.
- **Never commit `.env` or `tunnel.env`.** They are gitignored; verify with
  `git status` before any commit the user asks for.
- **Do not overwrite an existing `.env`.** It may hold the only copy of the
  encryption key for files already stored. If one exists, stop and ask.
- **Ask before**: creating accounts on third-party services, changing DNS,
  opening the vault to the internet, or deleting anything. Everything else
  in this guide is safe to do directly.
- **Verify, don't assume.** Each phase ends with a check. If a check fails,
  read the error, fix the cause, and re-run the check — don't skip ahead.

## Phase 0 — Recon (no changes)

Run and note the results; they decide later steps.

```bash
uname -m                      # need x86_64 or arm64 (Docker has no ARMv6/v7 story here)
docker --version && docker compose version
docker info >/dev/null && echo daemon-ok
df -h .                       # data volume headroom — the vault stores big files
ss -ltn | grep -E ':(8080)\b' || echo port-8080-free
git status --porcelain        # know the repo state before you touch it
```

If Docker is missing, install it using Docker's official instructions for
the user's OS (get.docker.com is acceptable), then re-check. On a NAS or
appliance OS, stop and tell the user the Docker path may not fit their
device; the app itself cannot run without a container runtime.

## Phase 1 — Interview (ask these, propose the defaults)

Ask in **one message**, filling in your best guesses so the user can just
say "ok":

1. **Mode**: (a) *Local* — vault on this machine/LAN only, login codes
   printed to the container log (no email account needed). (b) *Public* —
   reachable from the internet with real emailed login codes via Resend.
   Recommend Local first if they're unsure; it's upgradable in place.
2. **Data directory** — where encrypted files + the database live.
   Default: `./data` beside the repo. If they have a big disk/array mount,
   use `<that mount>/vault`.
3. **Admin account** — username, email (login codes go here), display name.
4. **Host port** — default 8080.
5. **Public mode only**: their domain (e.g. `vault.example.com`), whether
   DNS is at Cloudflare (lets you offer the Cloudflare Tunnel path and, if
   they use the Cloudflare MCP/connector, place records for them), and
   whether they already have a Resend account (they create it themselves at
   resend.com — never create accounts for the user).

Record the answers; they map 1:1 onto `.env` variables in Phase 2.

## Phase 2 — Configure

Generate the encryption key **on the user's machine** and write `.env`
without ever displaying the key:

```bash
mkdir -p <data-dir>/{files,tmp,db,logs}
umask 077
{
  echo "VAULT_KEY_B64=$(openssl rand -base64 32)"
  echo "PUBLIC_URL=<http://localhost:PORT or https://their-domain>"
  echo "EMAIL_MODE=<console|resend>"
  echo "RESEND_API_KEY=<from the user via a file/secure prompt, or empty>"
  echo "EMAIL_FROM=Vault <vault@<their-domain or example.com>>"
  echo "COOKIE_SECURE=<false for local, true for public>"
  echo "BOOTSTRAP_ADMIN_USERNAME=<username>"
  echo "BOOTSTRAP_ADMIN_EMAIL=<email>"
  echo "BOOTSTRAP_ADMIN_NAME=<display name>"
  echo "VAULT_UID=$(id -u)"
  echo "VAULT_GID=$(id -g)"
  echo "VAULT_DATA_DIR=<data-dir>"
  echo "VAULT_PORT=<port>"
  echo "VAULT_BIND=127.0.0.1"
} > .env
chmod 600 .env
```

Notes:
- `EMAIL_FROM` must be on a **Resend-verified domain** in resend mode or
  every send fails; see Phase 4. In console mode it's cosmetic.
- The bootstrap admin is created **only when the database is empty**;
  changing these values later does not rename an existing admin (use the
  Admin UI instead).
- Tell the user, verbatim in substance: *the key in `.env` is the only
  thing that can decrypt stored files; back it up offline (password
  manager or paper) before putting real files in.*

## Phase 3 — Build, start, verify locally

```bash
docker compose up -d --build
# wait for health (ClamAV downloads its database on first start — the
# vault may report "unscanned" until clamav is healthy; that's expected)
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:<port>/api/health && break || sleep 2; done
docker compose ps
```

Health must return `{"ok":true,...,"email_mode":"console"|"resend"}`.

**First login proof** (do this with the user watching):

- Console mode: `docker compose exec vault python -m app.recovery <admin>`
  prints a one-time login URL (60 min). Give it to the user to open — they
  should land in the vault as admin. *This recovery path exists so nobody
  is ever locked out by an email problem.*
- Resend mode: have the user request a code at the login page; confirm in
  the Resend dashboard that the message shows **delivered**. If the app log
  shows `RESEND_ERROR`, Phase 4's key/domain checks are the fix list.

**Smoke test** (creates its own throwaway users and cleans them up):

```bash
python3 scripts/smoke_test.py
```

It verifies: admin login via recovery, user creation, chunked upload,
byte-identical download, at-rest ciphertext really is ciphertext, sharing,
permission denial for an unshared user (404), and admin gating. All checks
must pass before you call the install done.

## Phase 4 — Going public (only if the user chose Public mode)

Do these in order; DNS and tunnel steps need the user's go-ahead and their
accounts.

1. **Resend domain**: user adds their domain in Resend (resend.com →
   Domains). Resend shows records to publish: a DKIM TXT
   (`resend._domainkey`), an MX and an SPF TXT on the **`send`**
   subdomain, and possibly a `rsend` CNAME. Publish exactly those at their
   DNS provider. **Do not overwrite the apex SPF** if they already receive
   mail (e.g. forwarding) — Resend deliberately keeps its SPF on `send`.
   Add a DMARC record if none exists: TXT `_dmarc` → `v=DMARC1; p=none;`.
   Wait for Resend to show the domain **Verified**.
2. **Resend key for the app**: a **sending-only** API key restricted to
   that domain (Resend → API Keys). Store it in `.env` as
   `RESEND_API_KEY`. The user should hand it over via a file on the machine
   or a secrets prompt, not pasted in chat; if they paste it anyway, follow
   the ground rule above.
3. **Sender**: set `EMAIL_FROM=Vault <vault@theirdomain>` — the address
   must be on the verified domain.
4. **Cloudflare Tunnel path** (recommended; no open ports): user creates a
   tunnel in the Cloudflare dashboard (Zero Trust → Networks → Tunnels),
   public hostname `<their subdomain>` → service `http://vault:8080`
   (the compose service name). Put the token in `tunnel.env`
   (`TUNNEL_TOKEN=...`, mode 600), then:
   ```bash
   docker compose --profile public up -d
   ```
   Cloudflare creates the DNS record automatically for tunnel hostnames.
   *Alternative*: any reverse proxy (Caddy/nginx/Traefik) terminating HTTPS
   and forwarding to `127.0.0.1:<port>` works; then set `VAULT_BIND` as
   appropriate and never publish the raw port.
5. **Flip `.env` to production**: `EMAIL_MODE=resend`,
   `PUBLIC_URL=https://<domain>`, `COOKIE_SECURE=true`, then
   `docker compose up -d`. Confirm `Strict-Transport-Security` now appears:
   `curl -sI https://<domain>/ | grep -i strict-transport`.
6. **External verification** (this is the definition of done): from a
   network that is *not* the server's LAN — health endpoint answers, a real
   login email is delivered and the code logs the user in, and a small
   upload/download round-trips byte-identically.

## Phase 5 — Backups (do not skip)

```bash
chmod +x scripts/backup.sh
BACKUP_DEST=<somewhere on a DIFFERENT disk than the data dir> scripts/backup.sh
ls <backup-dest>   # timestamped folder: vault.db, env.backup, code tarball
```

Then schedule it nightly (user's crontab), e.g. `30 3 * * *  cd <repo> &&
BACKUP_DEST=<dest> ./scripts/backup.sh >> backups.log 2>&1`. Explain what
the backup does and doesn't do: DB + config/key + code are backed up; file
contents are not (they're large and, in most home setups, re-obtainable —
if the user's files are *not* re-obtainable, add a copy/sync of the data
directory's `files/` folder to the same destination).

## Troubleshooting (field notes)

| Symptom | Likely cause / fix |
|---|---|
| Login button "does nothing" | The app returns 500 on `/api/auth/request` — check `docker compose logs vault` for the exception; the most common cause is the data directory not writable by `VAULT_UID:VAULT_GID`, or the data disk being unavailable. |
| Code requested, nothing arrives (resend) | Domain not Verified in Resend, `EMAIL_FROM` not on the verified domain, or the key is full-access/pasted with extra characters. Logs show `RESEND_OK`/`RESEND_ERROR` per attempt. |
| `error code: 1010` talking to api.resend.com or the vault domain | Cloudflare bans the default Python-urllib user-agent. The app already sends its own UA; if a *custom* client gets 1010, it's the same cause — set a real User-Agent. |
| Tests fail with "Not logged in" over HTTP | With `COOKIE_SECURE=true` the session cookie only travels over HTTPS. Run test scripts with `VAULT_BASE=https://<domain>`. |
| Uploads show `unscanned` | ClamAV is still loading its database on first start (can take minutes), or `av_scanning=off`. Check `docker compose ps` for clamav healthy. |
| Container permission errors on `/data` | The data dir must be owned by / writable for the uid:gid in `.env`; `chown -R $(id -u):$(id -g) <data-dir>`. |
| Forgot admin / email down | Break-glass: `docker compose exec vault python -m app.recovery <username>`. |

## Completion report (end with this)

Tell the user, in plain language:
1. The vault's URL and their admin username.
2. That the first login was verified end-to-end (and how: recovery link /
   delivered email / smoke test all-pass).
3. Where `.env` lives and that the encryption key inside it needs an
   offline backup **now**, naming the options (password manager secure
   note, paper in a safe) — and that losing it means losing the files.
4. Whether the vault is local-only or public, and what the one command to
   start/stop it is (`docker compose up -d` / `docker compose down` in the
   repo directory).
5. The two or three natural next steps for *their* setup (add users in the
   Admin tab, set up the tunnel if they deferred it, confirm tonight's
   backup ran).

## Project layout (for later questions)

- `app/main.py` — the whole application (FastAPI): auth, ACL, chunked
  uploads, AES-256-GCM chunked encryption at rest, sharing, admin, audit.
- `app/recovery.py` — break-glass login URL generator.
- `static/` — the web UI (no build step; plain HTML/CSS/JS).
- `docker-compose.yml` — vault + ClamAV sidecar + optional cloudflared.
- `scripts/backup.sh`, `scripts/smoke_test.py` — see Phases 3 and 5.
- Configuration is entirely via `.env` (see `.env.example`); runtime data
  (SQLite DB in `db/`, encrypted blobs in `files/`) lives under the data
  directory chosen in Phase 1.
