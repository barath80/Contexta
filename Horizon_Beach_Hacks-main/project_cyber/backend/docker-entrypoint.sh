#!/bin/sh
# Apply database migrations, then start the API.
# A single worker is intentional: the background scheduler runs inside the app process,
# so more workers would run every job more than once.
set -e

if [ "${APP_ENV:-development}" = "production" ]; then
  alembic upgrade head
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
