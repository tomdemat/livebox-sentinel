#!/bin/sh
# Applies a backup staged from Paramètres › Sauvegardes (data/restore-staged.sqlite3).
# Run on the server, in Sentinel's folder, container stopped:
#   docker compose down && sh tools/restore.sh
set -eu
cd "$(dirname "$0")/.."
DB="data/livebox-sentinel.sqlite3"
STAGED="data/restore-staged.sqlite3"

if [ -n "$(docker compose ps --status running -q)" ]; then
    echo "Arrête d'abord le conteneur avec : docker compose down"
    exit 1
fi
if [ ! -f "$STAGED" ]; then
    echo "Fichier de restauration absent : $STAGED"
    exit 1
fi
python3 -c 'import sqlite3,sys; c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); assert c.execute("PRAGMA quick_check").fetchone()[0]=="ok"; t={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type=\"table\"")}; assert {"devices","traffic"} <= t; c.close()' "$STAGED"

if [ ! -f "$DB" ]; then
    echo "Base actuelle absente : $DB"
    exit 1
fi
STAMP="$(date +%Y%m%d-%H%M%S)"
ROLLBACK="data/livebox-sentinel-before-restore-$STAMP.sqlite3"
cp -a "$DB" "$ROLLBACK"
# Sessions saved in the backup must not come back to life.
python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); t={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type=\"table\"")}; [c.execute("DELETE FROM web_sessions") for _ in [1] if "web_sessions" in t]; c.commit(); c.close()' "$STAGED"
rm -f "$DB-wal" "$DB-shm"
mv "$STAGED" "$DB"

if ! docker compose up -d; then
    echo "Le redémarrage a échoué ; restauration de la base précédente."
    cp -a "$ROLLBACK" "$DB"
    docker compose up -d || true
    exit 1
fi
echo "Restauration terminée. Copie précédente : $ROLLBACK"
