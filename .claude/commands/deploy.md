Deploy the application to Render or check deployment status.

User description: $ARGUMENTS

Steps:
1. Read `render.yaml` to understand the current deployment configuration
2. Run `git status` and `git log --oneline -5` to check what will be deployed
3. If there are uncommitted changes, warn the user before proceeding
4. Push the current branch to the remote: `git push origin main`
5. After push, check the Render deploy status if `render-cli` is available, otherwise remind the user to check the Render dashboard
6. Verify the health endpoint is responding: `curl -s https://hakuna-backend.onrender.com/api/health`
7. Remind about free-tier caveats:
   - First request after idle takes ~30s (cold start)
   - SQLite data is ephemeral — lost on every deploy/restart
   - Env vars (VITE_API_URL, CORS_ORIGINS) must be set in the Render dashboard after first deploy
