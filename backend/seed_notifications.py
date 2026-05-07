"""
Quick script to seed test notifications for verifying the notification bell UI.
Run from backend/: python seed_notifications.py

Inserts sample notifications into the local DB, then you can open
http://localhost:3000 and see the bell icon light up.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import SessionLocal, init_db
from services.notifications import create_notification

init_db()
db = SessionLocal()

# Find the first org
from models.models import Organization
org = db.query(Organization).first()
if not org:
    print("No organization found — upload a scan first.")
    sys.exit(1)

org_id = org.id
print(f"Seeding notifications for org '{org.name}' (id={org_id})...")

samples = [
    ("scan_complete", "Scan 'Q1 Internal Scan' completed",
     "142 assets, 1,847 findings processed",
     "/findings?scan_id=1", "scan", 1,
     {"assets": 142, "findings": 1847, "scan_name": "Q1 Internal Scan"}),

    ("scan_failed", "EASM scan 'tenable.com' failed",
     "Scanner: subfinder exited with code 1",
     "/settings?tab=scans", "scan", 1,
     {"scan_name": "tenable.com", "domain": "tenable.com", "source_type": "easm", "phase": "scanner"}),

    ("critical_findings", "23 critical/high findings in 'Q1 Internal Scan'",
     None, "/findings?scan_id=1&severity=3,4", "scan", 1,
     {"count": 23, "scan_name": "Q1 Internal Scan"}),

    ("new_assets", "8 new assets discovered in 'Q1 Internal Scan'",
     None, "/assets?scan_id=1", "scan", 1,
     {"count": 8, "scan_name": "Q1 Internal Scan"}),

    ("kev_update", "5 new CVEs added to CISA KEV",
     "3 of your findings were enriched",
     "/threat-intel/kev", "threat_intel", None,
     {"added": 5, "enriched": 3}),

    ("new_threat_groups", "2 new threat groups identified",
     None, "/threat-intel/groups", "threat_intel", None,
     {"count": 2}),

    ("eol_update", "3 products reached end-of-life",
     None, "/threat-intel/eol", "threat_intel", None,
     {"count": 3}),

    ("campaign_findings", "47 findings matched in campaign 'Log4Shell Remediation'",
     None, "/campaigns/1", "campaign", 1,
     {"count": 47, "campaign_name": "Log4Shell Remediation"}),
]

for cat, title, body, link, etype, eid, meta in samples:
    create_notification(db, org_id, cat, title,
                        body=body, link=link,
                        entity_type=etype, entity_id=eid,
                        metadata=meta)

db.commit()
print(f"Seeded {len(samples)} test notifications. Open http://localhost:3000 and check the bell icon.")
