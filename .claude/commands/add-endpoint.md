Add a new FastAPI endpoint to the backend.

User description: $ARGUMENTS

Steps:
1. Determine which router the endpoint belongs to:
   - Auth/users → `backend/routes/auth_routes.py`
   - Agent AI → `backend/routes/agent_routes.py`
   - Threat Intel → `backend/routes/threat_intel_routes.py`
   - EASM/discovery → `backend/routes/easm_routes.py` or `backend/routes/discovery_routes.py`
   - VM scanner → `backend/routes/vm_routes.py`
   - SBOM → `backend/routes/sbom_routes.py`
   - Exports → `backend/routes/export.py`
   - Integrations → `backend/routes/integration_builder_routes.py`
   - Benchmarks → `backend/routes/benchmark_routes.py`
   - Config portability → `backend/routes/config_portability.py`
   - Core findings/assets/scans/reports → `backend/app.py`
2. Read the target file to understand existing route patterns and imports
3. Read `backend/models/models.py` to understand available models
4. Read `backend/core/database.py` for DB session patterns (use `get_db` dependency)
5. Implement the endpoint following existing conventions:
   - Use `get_accessible_org_ids` + `apply_scan_org_filter` for multi-tenant filtering
   - Return consistent JSON shapes (match existing similar endpoints)
   - Use `HTTPException` with appropriate status codes
6. If a new model is needed, add it to `backend/models/models.py` and create a migration
7. Add the corresponding frontend API call to `frontend/src/api.js`
8. Verify syntax: `cd backend && source .venv/bin/activate && python -c "from app import app"`
