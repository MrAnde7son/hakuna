Deploy the application to GCP or check deployment status.

User description: $ARGUMENTS

Steps:
1. Read `deploy.sh` to understand the deployment configuration and available flags
2. Run `git status` and `git log --oneline -5` to check what will be deployed
3. If there are uncommitted changes, commit them or warn the user before proceeding
4. Determine what to deploy based on the user's request:
   - Frontend only (React changes): `./deploy.sh --frontend`
   - Backend API only (Python/Docker changes): `./deploy.sh --api`
   - Both frontend and backend: `./deploy.sh --api --frontend`
   - Scanner images: `./deploy.sh --scanners`
   - Infrastructure changes: `./deploy.sh --infra`
   - DB migrations: `./deploy.sh --migrate`
   - Everything: `./deploy.sh` (no flags)
5. Run the appropriate deploy command and monitor output for errors
6. Verify the health endpoint is responding: `curl -s https://app.hakunahq.com/api/health`

Notes:
- Project: `hakuna-prod-2026`, Region: `me-west1` (GCP)
- Frontend → GCS bucket + Cloud CDN (CDN cache is auto-invalidated on deploy)
- Backend API → Cloud Run service `hakuna-api`
- Scanner VMs → Artifact Registry (must be pulled manually on the VM after push)
- DB migrations require Cloud SQL Auth Proxy (`./deploy.sh --migrate`)
- Requires: `docker`, `gcloud`, `gsutil` authenticated to the project
- Sentry error tracking: set `SENTRY_DSN` env var in Cloud Run to enable. Check GCP Secret Manager for the DSN value.
