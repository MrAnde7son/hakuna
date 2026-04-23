Detect model changes and manage database migrations.

User description: $ARGUMENTS

## Setup

- **ORM**: SQLAlchemy 2.0, models in `backend/models/models.py` (and `backend/models/threat_intel_models.py`)
- **Migrations**: Alembic, configured in `backend/alembic.ini` and `backend/alembic/`
- **DB**: PostgreSQL everywhere — Cloud SQL (project `hakuna-prod-2026`) in production, the `postgres` docker-compose service in dev. `DATABASE_URL` is required; SQLite is not supported.
- **Session**: `backend/core/database.py` — `get_db()`, `init_db()`

## Steps

1. Read `backend/models/models.py` to understand current SQLAlchemy models
2. Read `backend/core/database.py` to confirm the engine/session setup
3. Check Alembic is configured: `ls backend/alembic/` and `cat backend/alembic.ini`

### Generate and apply a migration

```bash
cd backend && source .venv/bin/activate

# Auto-detect changes and generate migration
alembic revision --autogenerate -m "<short description>"

# Review the generated file in backend/alembic/versions/ for correctness
# (check for missed renames, dropped columns, or type changes)

# Apply to local DB
alembic upgrade head
```

### Apply to production (GCP Cloud SQL)

Migrations run automatically on deploy via `./deploy.sh --migrate`, which starts the Cloud SQL Auth Proxy and runs `alembic upgrade head` against the production database.

To run manually:
```bash
./deploy.sh --migrate
```

### Savepoints / transaction safety

If a migration step fails mid-transaction and poisons the connection, use savepoints:
```python
op.execute("SAVEPOINT sp1")
# ... risky operation ...
op.execute("RELEASE SAVEPOINT sp1")
```
See recent migrations in `backend/alembic/versions/` for examples.

### Dev-only schema reset

For quick local iteration (adds new tables/columns but does NOT handle column changes or drops):
```bash
python -c "from core.database import engine; from models.models import Base; Base.metadata.create_all(bind=engine)"
```

Only use this for local dev — always use Alembic for any change that needs to reach production.
