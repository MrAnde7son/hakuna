Add a new frontend page/component to the React app with routing and sidebar entry.

User description: $ARGUMENTS

Steps:
1. Read `frontend/src/App.jsx` to understand routing structure, ScanContext usage, and sidebar layout
2. Read `frontend/src/components/ui.jsx` to understand available shared UI primitives (Card, Badge, StatCard, etc.)
3. Read an existing page component similar to what's requested to follow conventions
4. Create the new component in `frontend/src/components/`
5. Add the route in `App.jsx` inside the Routes block
6. Add a sidebar entry in `App.jsx` with an appropriate Lucide icon
7. Add any needed API calls to `frontend/src/api.js`
8. Ensure it uses `useScan()` context for scan filtering if relevant
