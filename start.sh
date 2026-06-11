#!/usr/bin/env bash
# ============================================================================
#  VibeDocs — one-command launcher for macOS / Linux
#  Usage:  ./start.sh        (build + run, then open http://localhost:8000)
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo
echo "  ============================================================"
echo "    VibeDocs — a vibecoded report generator by Brendon Teo"
echo "  ============================================================"
echo

if ! docker version >/dev/null 2>&1; then
  echo "  X  Docker is not running. Install/start Docker, then re-run ./start.sh"
  echo "     https://www.docker.com/products/docker-desktop"
  exit 1
fi

# First run: generate unique local secrets into .env
if [ ! -f .env ]; then
  echo "  First run — generating unique local secrets..."
  rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
  {
    echo "# Auto-generated local secrets. Safe to keep; delete to regenerate."
    echo "POSTGRES_USER=vibedocs"
    echo "POSTGRES_PASSWORD=$(rand 24)"
    echo "POSTGRES_DB=vibedocs"
    echo "SECRET_KEY=$(rand 64)"
    echo "APP_PORT=8000"
    echo "MAILPIT_UI_PORT=8025"
    echo "ENV=production"
    echo "AUTH_PROVIDER=local"
  } > .env
fi

echo "  Building and starting (first build can take a few minutes)..."
docker compose up -d --build

echo -n "  Waiting for first-boot seeding"
for _ in $(seq 1 60); do
  if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then echo " — ready!"; break; fi
  echo -n "."; sleep 3
done

echo
echo "  ============================================================"
echo "    READY!  VibeDocs is running."
echo "    Web app .......  http://localhost:8000"
echo "    Email inbox ...  http://localhost:8025  (Mailpit)"
echo "    Login:  admin / change_me_now   (change it after first login)"
echo "  ============================================================"

# Best-effort open the browser
( command -v open  >/dev/null && open http://localhost:8000 ) 2>/dev/null || \
( command -v xdg-open >/dev/null && xdg-open http://localhost:8000 ) 2>/dev/null || true
