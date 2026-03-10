Add or extend a parser for Nessus scan data or inventory extraction.

User description: $ARGUMENTS

Steps:
1. Read `backend/parser.py` to understand the existing parsing patterns (HTML/XML/CSV) and `detect_and_parse()` flow
2. Read `backend/inventory_extractor.py` to understand plugin-based inventory extraction
3. Read `backend/models.py` for the data models (Scan, Asset, Finding, Inventory* models)
4. Implement the parser changes following existing conventions:
   - Use the same error handling patterns
   - Follow the same data normalization approach
   - Ensure severity mapping is consistent (0=Info, 1=Low, 2=Med, 3=High, 4=Critical)
5. If adding inventory extraction for a new plugin, add the plugin ID mapping and extraction function
6. Test with sample data if available
