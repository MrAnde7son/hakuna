Implement a full-stack feature across backend and frontend.

User description: $ARGUMENTS

Steps:
1. Read `backend/models/models.py`, `backend/app.py`, `backend/routes/` (relevant route files), and `frontend/src/App.jsx` to understand current architecture
2. Plan the feature: identify needed models, endpoints, services, and UI components
3. Present the plan to the user before implementing
4. Implement backend changes:
   - Add/modify models in `backend/models/models.py`
   - Add endpoints in the appropriate `backend/routes/*.py` file, or `backend/app.py` for core findings/assets/scans
   - Add business logic in `backend/services/` if it spans multiple routes
   - Use `get_accessible_org_ids` + `apply_scan_org_filter` for all multi-tenant queries
5. Implement frontend changes:
   - Add API calls to `frontend/src/api.js`
   - Create/modify components in `frontend/src/components/`
   - Update routing and sidebar in `App.jsx` if needed
   - Use existing UI primitives from `frontend/src/components/shared/ui.jsx`
6. If new DB columns/tables were added, create an Alembic migration: `cd backend && alembic revision --autogenerate -m "<description>"`
7. Verify syntax: `cd backend && source .venv/bin/activate && python -c "from app import app"` and `cd frontend && npx vite build`
