# Agentic Feed — Remaining Work

Status as of the EASM-failure-visibility refactor. The agentic feed loop is wired end-to-end; this document tracks what's left to make it production-quality.

---

## Just landed (context for what's below)

- **Backend foundation**: `org_feed_entries` table (mig 067), `OrgFeedEntry` model, `post_feed_entry` tool, `agent_dispatcher` with lazy auto-create from `feed_agent_templates.json`, `event_bus.emit`, `feed_routes` (CRUD + bootstrap).
- **Events wired**: `scan_started`, `scan_batch_complete`, `scan_complete`, `asset_created`, `validated_chain`, `org_onboarded`. All carry `dedup_key` so concurrent scans/findings each fire their own narrator run.
- **Frontend**: `/feed` is the landing route. System-design components (`PageHeader`, `Card`, `EmptyState`, `Pill`, `SeverityBadge`). Sidebar unread badge polls every 30s + on tab focus. Auto-refresh every 60s + on tab focus.
- **Templates**: `chain_narrator`, `triage_scan_results` (event-aware: started/batch/complete), `triage_new_asset`, `daily_brief`, `welcome_narrator` (4-state: pending/running, failed, no-scan, no-domain).
- **Inline drafting**: `draft_campaign` tool creates Campaign(status='draft') + paired AgentApproval; approve in the feed flips it to active via `_activate_agent_draft`.
- **EASM failure visibility (this turn)**: `trigger_easm_for_new_org` now creates the `Scan` row up-front. All external failures land as `status='failed'` with a reason in `raw_metadata.error`. `POST /api/easm/scans/{id}/retry` reuses the existing row.

---

## P0 — finish the EASM-failure UX

These complete the loop the user just hit.

### 1. Frontend: surface failed EASM scans on the Scans page
**Where**: `frontend/src/components/settings/Scans.jsx` (or wherever the existing settings → Scans table lives).
**Change**: render `status='failed'` rows with the error from `raw_metadata.error`. Add a "Retry" button that calls `POST /api/easm/scans/{id}/retry` and refreshes the table.

API helper to add to `api.js`:
```js
export const retryEasmScan = (scanId) => request(`/easm/scans/${scanId}/retry`, { method: 'POST' })
```

### 2. Frontend: deep-link the retry from the welcome feed entry
**Where**: feed entry's `proposed_actions` already include `{kind: "navigate", href: "/settings?tab=scans&retry={easm_scan_id}"}` (added in the welcome_narrator prompt).
**Change**: `Scans.jsx` should read `?retry=<id>` from the URL on mount, auto-fire the retry, and clear the param. Alternative: implement a new `kind: "callback"` action that posts to a backend URL directly without navigation.

### 3. Backfill on backend startup
**Where**: `backend/app.py` startup hook (find the `@app.on_event("startup")` block — note the deprecation warning suggests migrating to `lifespan`, but keep the convention current code uses).
**Change**: query for `Scan.status='failed' AND source_type='easm' AND created_at > now - 24h` and call `retry_easm_scan` for each. Logs a summary line.

```python
# Pseudo-code
@app.on_event("startup")
async def backfill_failed_easm_scans():
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        candidates = db.query(Scan).filter(
            Scan.source_type == "easm",
            Scan.status == "failed",
            Scan.created_at >= cutoff,
        ).all()
        for scan in candidates:
            org = db.query(Organization).filter(Organization.id == scan.org_id).first()
            if org:
                try:
                    await retry_easm_scan(db, org, scan.id)
                except Exception:
                    logger.exception("startup backfill: retry failed for scan=%s", scan.id)
    finally:
        db.close()
```

### 4. Faster post-onboarding feed refresh
**Where**: `frontend/src/components/feed/Feed.jsx`.
**Why**: first-run cold-start LLM call (10–30s) + 60s auto-refresh = up to 90s of empty feed after wizard. Tighten to 5s polling for the first 2 min when feed is empty.

```jsx
// Inside Feed component, after the existing 60s interval setup:
const fastPollUntil = useRef(Date.now() + 2 * 60 * 1000)
useEffect(() => {
  const tick = setInterval(() => {
    if (Date.now() < fastPollUntil.current && entries.length === 0 && document.visibilityState === 'visible') {
      load()
    }
  }, 5000)
  return () => clearInterval(tick)
}, [entries.length, load])
```

---

## P1 — close visible gaps in the agentic loop

### 5. Plumb `_agent_run_id` through `_execute_tool`
**Where**: `backend/agents/agent_engine.py`. Search `_execute_tool` (line ~333) — currently injects `_agent_id` and `_org_id` into params via `enriched_input`. Add `_agent_run_id` from the `run` parameter.
**Caller change**: every `_run_*` and `_stream_*` function passes `run` to `_execute_tool`. Currently they pass `agent`, `db`, `tool_name`, `tool_input`, `step`, `trace`. Add `run` to the signature.
**Tool change**: `post_feed_entry` reads `_agent_run_id` and writes it to `OrgFeedEntry.agent_run_id` (currently always NULL).
**UI win**: feed entry click → "View trace" link to `/agents/{agent_id}/runs/{run_id}` for the agent's full reasoning.

### 6. Manual asset registration emit
**Where**: any path that creates an Asset outside the scan-ingest pipeline.
**Why**: today `asset_created` only fires from `finalize_scan`. UI-driven asset creation (e.g. POST /api/assets) doesn't fire the event, so the narrator misses the discovery.
**Search**: `grep -rn 'Asset(' backend/routes/ | grep -v test` to find creation sites. Add `event_bus.emit("asset_created", org_id, payload, dedup_key=asset.id)` after each commit.

### 7. Apply the `draft_*` pattern to more actions
The `draft_campaign` tool is the model. Each new draft tool follows the same shape:
- SOFT_WRITE in the action_registry (so the agent doesn't pause on its own call).
- Body creates the *target entity* with a "draft" or "pending" state, plus a paired `AgentApproval(source='agent_draft', tool_name='activate_X')`.
- `_activate_agent_draft` in `agent_routes.py` gains a branch on `tool_name` to flip the entity from draft → active.

Candidates, in order of user-visible impact:
- **`draft_finding_exception`** — agent identifies a false-positive cluster, drafts an exception with TTL. Approve = exception applies.
- **`draft_owner_notification`** — agent drafts a Slack/Teams/email message to the asset owner. Approve = sends. (Requires the integrations.py message helpers — already exist.)
- **`draft_jira_ticket`** — drafts a ticket with a templated body referencing the finding(s). Approve = creates the ticket.

For each: follow `draft_campaign`'s test shape (tool body, activation on approve, no-op on reject, action_registry SOFT_WRITE drift guard).

### 8. Fold `coordinator_pending_approvals` into `agent_approvals`
**Why**: two parallel approval queues today. The chain coordinator's HITL approvals (Phase 4 patterns like `cred_found`) live in `coordinator_pending_approvals`; everything else lives in `agent_approvals`. Drift means the unified approval queue UI can't show coordinator approvals, and the feed entry pattern (`approval_id` in `proposed_actions`) doesn't work for them.
**Change**: migration to add `source='coordinator'` rows to `agent_approvals` (mirroring mig 066 which added `source='mcp_external'`). Update `chain_coordinator._upsert_pending_approval` to write to `agent_approvals` instead of `coordinator_pending_approvals`. Keep the old table for now (deprecation later).

---

## P2 — operations + presence

### 9. "Agents working now" sidebar indicator
**Why**: trust + visibility into what's running. Right now the sidebar has the unread feed badge but no signal that work is in flight.
**Where**: `frontend/src/App.jsx` Sidebar component (already polls `getFeedUnreadCount` every 30s).
**Change**: extend the polling to also fetch active-run count from a new endpoint `/api/agents/runs/active-count` (count of `AgentRun.status IN ('pending', 'running')` for the user's accessible orgs). Render alongside the unread badge: a pulsing dot when active runs > 0.

### 10. Periodic retry for failed EASM scans (in addition to startup backfill)
**Why**: customers don't restart the backend often. A 24h-old failed scan should retry on its own.
**Where**: `backend/services/easm_scheduler.py` already runs APScheduler. Add a job that ticks every 30 minutes:
```python
# Every 30m: retry any failed EASM scan from the last 7 days
def _retry_failed_easm_scans_job():
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=7)
        for scan in db.query(Scan).filter(
            Scan.source_type == "easm",
            Scan.status == "failed",
            Scan.created_at >= cutoff,
        ).all():
            org = db.query(Organization).filter(Organization.id == scan.org_id).first()
            if org:
                asyncio.run(retry_easm_scan(db, org, scan.id))
    finally:
        db.close()
```
Beware double-retry storms — if both startup-backfill and periodic-retry fire, they might race. Mitigate by setting `scan.raw_metadata['last_retry_at']` and skipping recent retries (< 5 min).

### 11. Rename and split `chain_coordinator.py`
**Why**: 1,976 lines in one file. Patterns + scoring + dispatch + BFS + emission + approvals all braided. Phase 4 will make this worse.
**Change**: split into a `chain_coordinator/` package — `__init__.py` (just `tick`), `patterns.py` (the 7 functions + registry), `closures.py` (BFS + ClosedChain + emit), `dispatch.py` (gating + cooldown + approvals).

---

## P3 — nice-to-haves

### 12. Sidebar nav entry that lists auto-created agents
The bootstrap endpoint and lazy-create both populate `agents` rows. The existing `/agents` page (AgentBuilder) already lists them. But there's no "these are the system agents that will run automatically" affordance — they're mixed in with user-built agents.
**Change**: filter the agents list by name pattern (the magic names in `EVENT_TO_AGENT_NAME`) and render them in a "System agents" section at the top.

### 13. Templates loaded on every dispatch — add a TTL cache
**Where**: `services/agent_dispatcher.py` `load_templates_by_name()`. Currently re-reads the JSON file every dispatch.
**Why**: cheap (small file, OS page-cached) but unbounded. Add `functools.lru_cache(maxsize=1)` with a 60s TTL via `cachetools.TTLCache` or similar. Iteration on prompts becomes slightly slower (60s lag) but file IO drops to one-per-minute.

### 14. Per-batch scan_batch_complete: skip very-low-signal batches
**Where**: `services/post_ingest.py` `_emit_scan_batch_complete`. Currently emits whenever `(new_asset_ids or new_finding_ids)` is non-empty.
**Why**: EASM streaming emits many small batches, and the `triage_scan_results` prompt already has skip rules for low-signal batches — but the emit-and-then-LLM-decides path wastes an LLM call. Pre-filter at the emit site: if all new findings are info-severity AND fewer than 3 new assets, skip the emit entirely.

---

## Architecture notes worth preserving

- **`source` on `AgentApproval`** is the integration glue. `internal_agent` → paused agent run, resume on decision. `mcp_external` → no run, the decision IS the action. `agent_draft` → no run, the decision triggers `_activate_agent_draft` which performs a server-side action keyed on `tool_name`. New approval flavors should follow this pattern: pick a source value, branch in `decide_approval` on that source.

- **`dedup_key` in `event_bus.emit`** is the load-bearing part of the per-event-type debounce escape hatch. Without it, two scans completing within 90s collapse into one narrator run. With it, each scan_id (or asset_id, or finding_id) gets its own. Keep this in mind when adding new emit sites — pass a dedup_key whenever the event has a primary entity.

- **The `[event:NAME][key:V]` tag in `AgentRun.input`** is what `_is_debounced` LIKE-matches on. It must be added by `_build_user_input` and never stripped. Don't try to "clean up" the input prefix; it's load-bearing.

- **Lazy auto-create vs. bootstrap endpoint**: lazy-create on the dispatcher path means a fresh org never sees "configure an agent" — the first event creates the agent on the fly. Bootstrap exists for re-syncing prompts after iterating templates (`overwrite=true`). Both read from the same `load_templates_by_name()` to avoid drift.

- **EASM `Scan` row is the durable record of intent.** Pre-creating it (this turn's refactor) means any failure is visible in the Scans page with `raw_metadata.error`. Retry reuses the row. Don't regress this — if you add a new "I might create a scan" code path, the Scan row goes first, the external ops go second.
