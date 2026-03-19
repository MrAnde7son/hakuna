Audit all API endpoints for proper authentication and tenant filtering.

Steps:
1. Read `backend/core/auth.py` to understand the auth dependencies: `get_current_user`, `get_accessible_org_ids`, `apply_org_filter`, `apply_scan_org_filter`
2. Read `backend/app.py` and all files in `backend/routes/` to list all endpoint functions
3. For each endpoint, check:
   - Does it use `get_current_user` or `get_accessible_org_ids` as a dependency?
   - Does it apply `apply_org_filter` or `apply_scan_org_filter` to queries?
   - Are there any unprotected routes that should require auth?
4. Check for common issues:
   - Endpoints that query Scan/Asset/Finding without org filtering
   - Missing auth on write operations (POST/PUT/DELETE)
   - Direct object access without ownership check (IDOR)
5. Report findings:
   - List of properly protected endpoints
   - List of endpoints missing auth or tenant filtering
   - Recommended fixes for each issue
