"""FastAPI entrypoint for hakuna-scanner."""

import logging

from fastapi import FastAPI

from app.api import assets, export, github_attribution, orgs, scans

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI(
    title="hakuna-scanner",
    description="External asset discovery and enrichment pipeline using ProjectDiscovery tools",
    version="1.0.0",
)

app.include_router(orgs.router)
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(export.router)
app.include_router(github_attribution.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
