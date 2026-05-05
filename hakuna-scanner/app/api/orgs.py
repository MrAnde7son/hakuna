"""CRUD for orgs and target domains."""

import ipaddress
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.org import Org, TargetDomain

router = APIRouter(prefix="/api/v1/orgs", tags=["orgs"])


class OrgCreate(BaseModel):
    name: str


class OrgResponse(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


# Hostname label per RFC 1035 §2.3.1: alphanumeric, internal hyphens allowed,
# 1–63 chars. The full FQDN must have at least two labels (so a bare
# "localhost" doesn't sneak through as a scan target) and total length ≤253.
_HOSTNAME_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_FQDN_RE = re.compile(
    rf"^(?=.{{1,253}}$)(?:{_HOSTNAME_LABEL}\.)+{_HOSTNAME_LABEL}$"
)


class DomainCreate(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, raw: str) -> str:
        # Normalize first so the validator and the DB row agree on the canonical
        # form. Without this, '  HAKUNAHQ.com ' would pass validation as-is and
        # only get lowered/stripped in add_domain.
        v = (raw or "").strip().lower()
        if not v:
            raise ValueError("domain must not be empty")
        # Accept literal IPv4/IPv6 — the scanner already runs against IP targets
        # (see existing target_domains rows like 20.83.163.0).
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        # Otherwise require a valid FQDN. This is what catches typos like
        # 'hakunahq,com' (comma instead of dot) which otherwise get accepted
        # and waste a full scan run on an unresolvable name.
        if not _FQDN_RE.match(v):
            raise ValueError(
                f"'{raw}' is not a valid FQDN or IP address"
            )
        return v


class DomainResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    domain: str
    active: bool

    model_config = {"from_attributes": True}


@router.post("", response_model=OrgResponse, status_code=201)
async def create_org(body: OrgCreate, db: AsyncSession = Depends(get_db)):
    # Return existing org if name matches
    result = await db.execute(select(Org).where(Org.name == body.name).limit(1))
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    org = Org(name=body.name)
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org


@router.get("", response_model=list[OrgResponse])
async def list_orgs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Org).order_by(Org.created_at))
    return result.scalars().all()


@router.get("/{org_id}", response_model=OrgResponse)
async def get_org(org_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org = await db.get(Org, org_id)
    if not org:
        raise HTTPException(404, "Org not found")
    return org


@router.delete("/{org_id}", status_code=204)
async def delete_org(org_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org = await db.get(Org, org_id)
    if not org:
        raise HTTPException(404, "Org not found")
    await db.delete(org)
    await db.commit()


# --- Target Domains ---

@router.post("/{org_id}/domains", response_model=DomainResponse, status_code=201)
async def add_domain(org_id: uuid.UUID, body: DomainCreate, db: AsyncSession = Depends(get_db)):
    org = await db.get(Org, org_id)
    if not org:
        raise HTTPException(404, "Org not found")

    # body.domain is already stripped/lowered and validated by DomainCreate.
    result = await db.execute(
        select(TargetDomain).where(TargetDomain.org_id == org_id, TargetDomain.domain == body.domain)
    )
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    domain = TargetDomain(org_id=org_id, domain=body.domain)
    db.add(domain)
    await db.commit()
    await db.refresh(domain)
    return domain


@router.get("/{org_id}/domains", response_model=list[DomainResponse])
async def list_domains(org_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(TargetDomain).where(TargetDomain.org_id == org_id).order_by(TargetDomain.created_at)
    )
    return result.scalars().all()


@router.delete("/{org_id}/domains/{domain_id}", status_code=204)
async def remove_domain(org_id: uuid.UUID, domain_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(TargetDomain).where(TargetDomain.id == domain_id, TargetDomain.org_id == org_id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(404, "Domain not found")
    await db.delete(domain)
    await db.commit()
