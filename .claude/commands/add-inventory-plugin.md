Add extraction logic for a new Nessus plugin ID to the inventory system.

User description: $ARGUMENTS

Steps:
1. Read `backend/parsers/inventory_extractor.py` (or `backend/inventory_extractor.py`) to understand the existing plugin-to-extractor mapping and extraction patterns
2. Read `backend/models/models.py` (or `backend/models.py`) for the Inventory* models (InventoryUser, InventoryGroup, InventoryService, etc.)
3. Identify the plugin ID and the type of data it produces from the user's description
4. If an existing Inventory model fits, add a new extractor function following the pattern:
   - Parse the plugin_output text (tab-separated, colon-separated, JSON, or free-form)
   - Map parsed fields to the model's columns
   - Handle edge cases (missing fields, multiple records per output)
5. If a new Inventory model is needed:
   - Add it to models.py with scan_id, asset_id foreign keys
   - Add the API endpoint in app.py following the existing inventory endpoint pattern
   - Add the frontend data display
6. Register the plugin ID in the extractor mapping
7. Test with sample plugin output if available
8. Update the inventory summary endpoint if the new data contributes to attack surface metrics
