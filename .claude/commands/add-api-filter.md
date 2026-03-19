Add a new query parameter filter to an existing API endpoint.

User description: $ARGUMENTS

Steps:
1. Locate the target endpoint in `backend/app.py` or the appropriate `backend/routes/*.py` file
2. Read `backend/models/models.py` to understand the model fields available for filtering
3. Add the new query parameter to the endpoint function signature with a default of `None`
4. Add the filter logic to the SQLAlchemy query, following existing patterns:
   - Exact match: `query = query.filter(Model.field == value)`
   - Search/partial: `query = query.filter(Model.field.ilike(f"%{value}%"))`
   - Boolean: `query = query.filter(Model.field == True)`
   - List/comma-separated: split and use `Model.field.in_(values)`
5. Ensure tenant filtering (`apply_org_filter`) is still applied correctly
6. Update the corresponding frontend API call if it exists
7. Test the filter by checking for syntax errors in the endpoint
