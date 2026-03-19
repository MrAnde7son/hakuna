Profile and optimize a slow endpoint or page.

User description: $ARGUMENTS

Steps:
1. Identify the target from user arguments (endpoint path or frontend page)
2. For backend endpoints:
   - Locate the endpoint in `backend/app.py` or the appropriate `backend/routes/*.py` file
   - Check for N+1 queries, missing indexes, large unbounded queries
   - Read the relevant models in `backend/models/models.py` for index definitions
   - Look for missing eager loading (joinedload/subqueryload) on relationships
   - Check if pagination is implemented for list endpoints
   - Suggest adding database indexes on frequently filtered columns
   - Time the endpoint: `curl -w "\n%{time_total}s\n" http://localhost:8000/api/<path>`
3. For frontend pages:
   - Read the component file to check for unnecessary re-renders, large data fetching, missing pagination
   - Check if React.memo, useMemo, or useCallback could help
   - Look for unbounded list rendering (should use virtualization for 1000+ items)
4. Propose specific optimizations with expected impact
5. Implement fixes if the user approves
