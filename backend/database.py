from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./nessus_remediation.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from models import (  # noqa: F401
        Scan, Asset, Finding, AutomateClick,
        InventoryUser, InventoryGroup, InventoryService,
        InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
        InventoryShare, InventorySoftware, InventorySecurityControl,
        InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
        AssetOwnership, FindingOwnership,
        Campaign, CampaignFinding,
        Tag, TagAssignment, AutoTagRule,
        SLAConfig,
        Workflow, WorkflowNode, WorkflowEdge,
        WorkflowExecution, WorkflowExecutionLog,
    )
    from threat_intel_models import (  # noqa: F401
        ThreatGroup, TTP, ThreatGroupTTP,
        ThreatCVE, ThreatCampaign, IntelRemediationCampaign,
    )
    Base.metadata.create_all(bind=engine)
