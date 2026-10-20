#!/usr/bin/env bash
# Secure File Vault — interactive setup.
#
# Walks you through configuring and starting your own vault:
#   prerequisites check -> a few questions -> generates .env (with a fresh
#   encryption key) -> creates the data directories -> builds and starts
#   the containers -> verifies the health endpoint.
#
# Non-interactive use: pre-set any of the SETUP_* variables below and the
# matching question is skipped. Example:
#   SETUP_MODE=resend SETUP_PUBLIC_URL=https://vault.example.com \
#   SETUP_ADMIN_USERNAME=alice SETUP_ADMIN_EMAIL=alice@example.com \
#   SETUP_RESEND_API_KEY=re_... ./setup.sh
#
# If you use an AI coding agent, you can skip this script entirely and let
# the agent follow AGENTS.md in this repo instead — it does the same thing.
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\n== %s ==\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# ---------- prerequisites ----------
say "Checking prerequisites"
command -v docker >/dev/null || die "docker not found — install Docker first (https://docs.docker.com/get-docker/)"
docker compose version >/dev/null 2>&1 || die "docker compose v2 not found — it ships with modern Docker"
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable (is it running? are you in the docker group?)"
command -v openssl >/dev/null || die "openssl not found (needed to generate the encryption key)"
info "Docker + compose + openssl: OK"

[ -f .env ] && { printf '\nA .env already exists. Re-running setup would OVERWRITE it, including the encryption key.\nIf the vault already holds files, that key is the only way to decrypt them.\nType "overwrite" to continue, anything else to abort: '; read -r ans; [ "$ans" = "overwrite" ] || die "aborted — existing .env left untouched"; }

# ---------- questions ----------
ask() { # ask VARNAME "Prompt" "default"
  local var="$1" prompt="$2" def="${3:-}" cur="${!1:-}" val
  if [ -n "$cur" ]; then printf -v "$var" '%s' "$cur"; return; fi
  if [ -n "$def" ]; then printf '%s [%s]: ' "$prompt" "$def"; else printf '%s: ' "$prompt"; fi
  read -r val || true
  printf -v "$var" '%s' "${val:-$def}"
}

say "A few questions (Enter accepts the default)"

MODE="${SETUP_MODE:-}"
if [ -z "$MODE" ]; then
  echo "How will you use the vault?"
  echo "  1) local   — just this machine / home network. Login codes print to"
  echo "               the container log; no email service needed."
  echo "  2) resend  — reachable on the internet, real login emails via Resend."
  printf 'Choose 1 or 2 [1]: '; read -r m || true
  case "$m" in 2) MODE=resend ;; *) MODE=local ;; esac
fi

ask DATA_DIR "Data directory (encrypted files + database)" "${SETUP_DATA_DIR:-$PWD/data}"
ask PORT "Host port" "${SETUP_PORT:-8080}"
ask ADMIN_USERNAME "Admin username (you'll log in with this)" "${SETUP_ADMIN_USERNAME:-admin}"
ask ADMIN_EMAIL "Admin email (login codes are sent here)" "${SETUP_ADMIN_EMAIL:-}"
ask ADMIN_NAME "Admin display name" "${SETUP_ADMIN_NAME:-Admin}"

if [ "$MODE" = "resend" ]; then
  ask PUBLIC_URL "Public URL of the vault, e.g. https://vault.example.com" "${SETUP_PUBLIC_URL:-}"
  [ -n "$PUBLIC_URL" ] || die "a public URL is required for resend mode"
  ask EMAIL_FROM "From address for login emails, e.g. Vault <vault@example.com>" "${SETUP_EMAIL_FROM:-Vault <vault@example.com>}"
  if [ -z "${SETUP_RESEND_API_KEY:-}" ]; then
    printf 'Resend API key (input hidden): '; read -rs RESEND_API_KEY || true; echo
  else
    RESEND_API_KEY="$SETUP_RESEND_API_KEY"
  fi
  [ -n "$RESEND_API_KEY" ] || die "a Resend API key is required for resend mode"
  EMAIL_MODE=resend; COOKIE_SECURE=true
else
  PUBLIC_URL="http://localhost:$PORT"
  EMAIL_FROM="Vault <vault@example.com>"
  RESEND_API_KEY=""
  EMAIL_MODE=console; COOKIE_SECURE=false
fi

# ---------- write .env ----------
say "Generating configuration"
KEY="$(openssl rand -base64 32)"
mkdir -p "$DATA_DIR/files" "$DATA_DIR/tmp" "$DATA_DIR/db" "$DATA_DIR/logs"
cat > .env <<EOF
VAULT_KEY_B64=$KEY
PUBLIC_URL=$PUBLIC_URL
EMAIL_MODE=$EMAIL_MODE
RESEND_API_KEY=$RESEND_API_KEY
EMAIL_FROM=$EMAIL_FROM
COOKIE_SECURE=$COOKIE_SECURE
BOOTSTRAP_ADMIN_USERNAME=$ADMIN_USERNAME
BOOTSTRAP_ADMIN_EMAIL=$ADMIN_EMAIL
BOOTSTRAP_ADMIN_NAME=$ADMIN_NAME
EOF
chmod 600 .env

# Host values the compose file needs live next to .env in a compose-readable
# place: docker compose reads .env for interpolation automatically.
cat >> .env <<EOF
VAULT_UID=$(id -u)
VAULT_GID=$(id -g)
VAULT_DATA_DIR=$DATA_DIR
VAULT_PORT=$PORT
VAULT_BIND=127.0.0.1
EOF
info ".env written (mode 600) — it contains your encryption key."

# ---------- build & start ----------
say "Building and starting (first build takes a few minutes)"
docker compose up -d --build

say "Waiting for the vault to answer"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then break; fi
  sleep 2
  [ "$i" = "30" ] && die "vault did not come up — check: docker compose logs vault"
done
curl -sS "http://127.0.0.1:$PORT/api/health"; echo

say "Done"
cat <<EOF
  Open the vault:        $PUBLIC_URL
  Admin username:        $ADMIN_USERNAME
EOF
if [ "$EMAIL_MODE" = "console" ]; then
cat <<EOF
  Log in: request a code on the login page, then read it from the log:
      docker compose logs vault | grep LOGIN_EMAIL
  No email? Use the break-glass login link (valid 60 minutes, once):
      docker compose exec vault python -m app.recovery $ADMIN_USERNAME
EOF
else
cat <<EOF
  Log in: request a code on the login page — it will be emailed to
  $ADMIN_EMAIL from $EMAIL_FROM. If nothing arrives, check the Resend
  dashboard (domain verified? sending key valid?) and the container log:
      docker compose logs vault | grep RESEND
EOF
fi
cat <<EOF

  !! IMPORTANT — your encryption key !!
  The key that decrypts every stored file is VAULT_KEY_B64 in:
      $PWD/.env
  Back it up NOW in a password manager or on paper, stored separately
  from this machine. If you lose it, the files in $DATA_DIR are
  unrecoverable — there is no reset and no back door.

  Next steps: docs in README.md (going public with a Cloudflare Tunnel,
  backups, adding users). Run the smoke test any time:
      python3 scripts/smoke_test.py
EOF
