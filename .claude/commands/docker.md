Build and run the application using Docker Compose.

User request: $ARGUMENTS

Steps:
1. Read `docker-compose.yml`, `backend/Dockerfile`, and `frontend/Dockerfile` to understand the current setup
2. Based on the user's request, either:
   - **build**: Run `docker compose build`
   - **up**: Run `docker compose up -d` and check container health
   - **down**: Run `docker compose down`
   - **logs**: Run `docker compose logs --tail=50`
   - **restart**: Run `docker compose restart`
3. Report status and any errors
