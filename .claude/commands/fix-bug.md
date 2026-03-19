Debug and fix a bug in the application.

User description: $ARGUMENTS

Steps:
1. Analyze the bug description to identify likely affected files
2. Check Sentry for recent errors if available: `SENTRY_DSN` is set in production — ask the user to share the Sentry event URL or traceback if they have it
3. Read the relevant backend files:
   - Core logic: `backend/app.py`, `backend/models/models.py`, `backend/core/database.py`
   - Route files: `backend/routes/*.py` (auth, agents, exports, integrations, EASM, VM, SBOM, threat intel)
   - Services: `backend/services/<name>.py`
   - Parsers: `backend/parsers/parser.py`, `backend/parsers/nessus_parser.py`, `backend/parsers/inventory_extractor.py`
   And/or frontend files in `frontend/src/`
4. Search the codebase for related code using Grep
5. Identify the root cause
6. Implement the fix with minimal changes
7. Verify: `cd backend && source .venv/bin/activate && python -c "from app import app"` for backend syntax
8. Explain what caused the bug and what was changed
