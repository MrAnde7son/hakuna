Detect model changes and manage database migrations.

User description: $ARGUMENTS

Steps:
1. Read `backend/models/models.py` (or `backend/models.py`) to understand current SQLAlchemy models
2. Read `backend/core/database.py` (or `backend/database.py`) for the engine/session setup and `Base.metadata.create_all` usage
3. Check if Alembic is set up: look for `alembic.ini` and `alembic/` directory in `backend/`
4. If Alembic is NOT set up:
   - Install alembic: `pip install alembic`
   - Initialize: `cd backend && alembic init alembic`
   - Configure `alembic/env.py` to import the project's Base and models
   - Update `alembic.ini` with the correct database URL
5. If Alembic IS set up:
   - Auto-generate a migration: `cd backend && alembic revision --autogenerate -m "<description>"`
   - Review the generated migration file for correctness
   - Apply: `cd backend && alembic upgrade head`
6. If the user just wants a quick schema reset (dev only): `Base.metadata.create_all(bind=engine)` handles new tables but not column changes
7. Warn about Render's ephemeral SQLite — migrations run on every deploy or data is lost on restart
