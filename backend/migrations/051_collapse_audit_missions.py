"""Rewrite legacy per-protocol audit missions to ``exposure_audit``.

Commit 71a676a collapsed the ssh/ldap/smb/snmp/wmi protocols from several
narrow missions (e.g. ``identity``, ``privesc``, ``software_cve``,
``explore``) into a single ``exposure_audit`` mission. Existing scans still
carry the old mission key in ``raw_metadata.mission`` and the audit
registry validator (services/audit_runner.py, routes/audit_routes.py)
rejects them on rerun or save.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from core.database import engine
from models.models import Scan


COLLAPSED_PROTOCOLS = {"ssh", "ldap", "smb", "snmp", "wmi"}


def upgrade():
    fixed = 0
    with Session(engine) as session:
        # scan_type is per-protocol (e.g. "ssh_audit"), so filter by raw_metadata
        # instead. Pull every scan and inspect the JSON column in Python — keeps
        # the query portable across PG/SQLite, and the row count is small.
        scans = session.query(Scan).all()
        for scan in scans:
            md = scan.raw_metadata or {}
            protocol = md.get("protocol")
            mission = md.get("mission")
            if protocol in COLLAPSED_PROTOCOLS and mission and mission != "exposure_audit":
                md["mission"] = "exposure_audit"
                scan.raw_metadata = md
                flag_modified(scan, "raw_metadata")
                fixed += 1
        session.commit()
    print(f"[+] migration 051: rewrote mission on {fixed} scan(s) to exposure_audit")


def downgrade():
    # The original mission key is unrecoverable (many → one). No-op.
    print("Migration 051: not reversible (lossy collapse).")


if __name__ == "__main__":
    upgrade()
