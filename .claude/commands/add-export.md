Add a new export format for findings, assets, or reports.

User description: $ARGUMENTS

Steps:
1. Read `backend/app.py` to understand existing export endpoints (if any) and data query patterns
2. Read `backend/models/models.py` for the data models to be exported
3. Determine the export format from user arguments (CSV, Excel, PDF, JSON, JIRA)
4. For CSV export:
   - Use Python's `csv` module with `StreamingResponse`
   - Map model fields to column headers
5. For Excel export:
   - Install openpyxl if needed: `pip install openpyxl`
   - Create workbook with formatted headers, auto-width columns
6. For PDF export:
   - Install reportlab or weasyprint if needed
   - Create a formatted report with title, date, summary table
7. For JIRA integration:
   - Create an endpoint that formats findings as JIRA ticket JSON
   - Include severity, description, remediation steps
8. Add the export endpoint in `backend/app.py`: `GET /api/export/<type>?scan_id=&format=<format>`
9. Add a download button in the relevant frontend component
10. Ensure tenant filtering is applied to exported data
