"""CRUD for orgs and target domains."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
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


class DomainCreate(BaseModel):
    domain: str


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

    clean_domain = body.domain.strip().lower()

    # Return existing if already added
    result = await db.execute(
        select(TargetDomain).where(TargetDomain.org_id == org_id, TargetDomain.domain == clean_domain)
    )
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    domain = TargetDomain(org_id=org_id, domain=clean_domain)
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
