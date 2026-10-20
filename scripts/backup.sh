#!/usr/bin/env bash
# Secure File Vault backup — DB + config/encryption key + code.
#
#   BACKUP_DEST=/some/other/disk/vault-backups ./scripts/backup.sh
#
# Produces <BACKUP_DEST>/<timestamp>/ containing:
#   vault.db          consistent SQLite snapshot (via the backup API)
#   env.backup        your .env — includes the encryption key (mode 600)
#   vault-code.tar.gz the code (without .env, which is backed up above)
#   MANIFEST.sha256   checksums of the three
# Keeps the newest 14 backups. Put BACKUP_DEST on a DIFFERENT disk than the
# vault's data directory, or the backup dies with the data.
#
# File CONTENTS are not backed up by this script: also copy the data
# directory's files/ tree if your users' files are not re-obtainable.
#
# Configuration (environment):
#   BACKUP_DEST      destination root        (default: ./backups)
#   VAULT_DATA_DIR   the vault's data dir    (default: read from .env, else ./data)
#   VAULT_CONTAINER  vault container name    (default: secure-vault)
set -euo pipefail
cd "$(dirname "$0")/.."

DEST_ROOT="${BACKUP_DEST:-$PWD/backups}"
CONTAINER="${VAULT_CONTAINER:-secure-vault}"
if [ -z "${VAULT_DATA_DIR:-}" ] && [ -f .env ]; then
  VAULT_DATA_DIR="$(grep -E '^VAULT_DATA_DIR=' .env | tail -1 | cut -d= -f2- || true)"
fi
DATA_DIR="${VAULT_DATA_DIR:-$PWD/data}"
TS="$(date +%Y%m%d-%H%M%S)"
DIR="$DEST_ROOT/$TS"
mkdir -p "$DIR"

# 1. Consistent DB snapshot via SQLite's backup API (through the running container)
docker exec -i "$CONTAINER" python - "$TS" <<'PYEOF'
import sqlite3, sys
ts = sys.argv[1]
src = sqlite3.connect("/data/db/vault.db")
dst = sqlite3.connect(f"/data/db/backup-{ts}.db")
with dst:
    src.backup(dst)
dst.close(); src.close()
print("db snapshot ok")
PYEOF
cp "$DATA_DIR/db/backup-$TS.db" "$DIR/vault.db"
rm -f "$DATA_DIR/db/backup-$TS.db"

# 2. Config + encryption key (this file IS the crown jewels — 600 perms)
cp .env "$DIR/env.backup"
chmod 600 "$DIR/env.backup"

# 3. Code (excluding secrets and runtime data)
tar czf "$DIR/vault-code.tar.gz" \
  --exclude='./.env' --exclude='./tunnel.env' --exclude='./data' \
  --exclude='./backups' --exclude='*/__pycache__' -C "$PWD" .

# 4. Manifest
(cd "$DIR" && sha256sum vault.db env.backup vault-code.tar.gz > MANIFEST.sha256)
chmod 700 "$DIR"

# 5. Retention: keep newest 14 timestamped dirs in DEST_ROOT only
ls -1dt "$DEST_ROOT"/[0-9]* 2>/dev/null | tail -n +15 | while read -r old; do
  [ -n "$old" ] && rm -rf "$old"
done

echo "Backup complete: $DIR"
ls -lh "$DIR"
