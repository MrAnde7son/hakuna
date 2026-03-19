Add or extend a scanner parser or inventory extraction plugin.

User description: $ARGUMENTS

## Parser Architecture

Parsers live in `backend/parsers/` and follow a pluggable registry pattern:

- `base_parser.py` — `BaseParser` abstract class (implement `can_parse()` and `parse()`)
- `registry.py` — `init_parsers()` auto-registers parsers at startup; `detect_parser()` selects the right one
- `nessus_parser.py` — Nessus HTML/XML/.nessus/CSV parser (the reference implementation)
- `parser.py` — Legacy compatibility shim (`detect_and_parse()`, `load_intel_json`)
- `inventory_extractor.py` — Plugin-based inventory extraction from finding outputs

Currently registered: **Nessus** only. Qualys, OpenVAS, Rapid7 parsers are planned (see `registry.py` comments).

## Adding a New Scanner Parser

1. Read `backend/parsers/base_parser.py` to understand the `BaseParser` interface
2. Read `backend/parsers/nessus_parser.py` as the reference implementation
3. Read `backend/models/models.py` for the `Asset`, `Finding`, and `Scan` models
4. Create `backend/parsers/<scanner>_parser.py` implementing `BaseParser`:
   - `source_type: str` — e.g. `"qualys"`, `"openvas"`, `"rapid7"`
   - `supported_extensions: list[str]` — e.g. `[".xml"]`
   - `can_parse(content: bytes, filename: str) -> bool` — sniff magic bytes or root XML tag
   - `parse(content: bytes, filename: str, scan_id: int, org_id: int) -> dict` — returns `{assets: [...], findings: [...]}`
5. Follow severity normalization: `0=Info, 1=Low, 2=Med, 3=High, 4=Critical`
6. Register the parser in `backend/parsers/registry.py` inside `init_parsers()`
7. Test: upload a sample file via `curl -X POST http://localhost:8000/api/upload -F "file=@<path>"`

## Adding Inventory Extraction for a New Plugin

1. Read `backend/parsers/inventory_extractor.py` for the plugin-to-extractor mapping and patterns
2. Read `backend/models/models.py` for existing `Inventory*` models (InventoryUser, InventoryGroup, InventoryService, InventoryNetConnection, InventorySoftware, etc.)
3. Identify the Nessus plugin ID and output format
4. Add an extractor function and register it in the plugin ID map:
   - Parse `plugin_output` (tab-separated, colon-separated, JSON, or free-form)
   - Map fields to the appropriate `Inventory*` model columns
   - Handle edge cases: missing fields, multiple records per output
5. If a new `Inventory*` model is needed:
   - Add it to `backend/models/models.py` with `scan_id`, `asset_id` FKs
   - Add the API endpoint in `backend/app.py` following existing inventory endpoint patterns
   - Add frontend display in `frontend/src/components/inventory/InventoryExplorer.jsx`
6. Update the inventory summary endpoint if the new data contributes to attack-surface metrics
7. Create an Alembic migration if new columns/tables were added
