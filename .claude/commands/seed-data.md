Seed the database with test scan data for local development.

User description: $ARGUMENTS

## Supported scan formats

The upload endpoint auto-detects the format via `backend/parsers/registry.py`:
- **Nessus** `.nessus` (XML), `.html` (Nessus HTML export), `.csv` (Nessus CSV export) — currently registered
- **Qualys**, **OpenVAS**, **Rapid7** — parsers planned (see registry.py comments); upload will fail if attempted without a registered parser

## Steps

1. Check for sample scan files: look in `tests/`, `samples/`, or project root for `.nessus`, `.html`, `.csv` files
2. Ensure the backend is running:
   ```bash
   curl -s http://localhost:8000/api/health
   ```
   If not running, start it:
   ```bash
   cd /Users/itamar/Documents/Git/hakuna/backend && source .venv/bin/activate && uvicorn app:app --port 8000 --reload &
   ```
3. Upload a scan file:
   ```bash
   curl -X POST http://localhost:8000/api/upload \
     -H "Authorization: Bearer <token>" \
     -F "file=@<path_to_file>"
   ```
4. If no sample files exist, inform the user they need to provide a scan file (Nessus format recommended)
5. Verify the upload:
   ```bash
   curl -s http://localhost:8000/api/scans | python3 -m json.tool
   ```
6. Report: number of scans, assets, and findings loaded
