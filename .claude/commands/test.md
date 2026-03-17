Run backend and/or frontend tests.

User description: $ARGUMENTS

Steps:
1. Determine scope from user arguments (backend, frontend, or both — default both)
2. For backend tests:
   - Activate venv: `cd /Users/itamar/Documents/Git/hakuna/backend && source .venv/bin/activate`
   - Run pytest: `python -m pytest -v` (install pytest first if missing)
   - Report results with pass/fail counts
3. For frontend tests:
   - Run: `cd /Users/itamar/Documents/Git/hakuna/frontend && npm test`
   - If no test script exists, check for vitest or jest config and run accordingly
4. Summarize results: total tests, passed, failed, and any errors
5. If tests fail, read the failing test files and relevant source to diagnose the issue
