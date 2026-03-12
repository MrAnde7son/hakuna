#!/usr/bin/env python3
"""Print a human-readable token optimization summary to stdout."""
import json
import os

REPORT_DIR = os.path.dirname(os.path.abspath(__file__))


def load(filename):
    with open(os.path.join(REPORT_DIR, filename)) as f:
        return json.load(f)


def main():
    final = load("token_optimization_final.json")
    s = final["summary"]
    b = final["breakdown_by_technique"]

    bar = "=" * 72
    print(bar)
    print("  HAKUNA TOKEN OPTIMIZATION REPORT — Nessus Remediation Pipeline")
    print(bar)
    print()
    print(f"  Generated: {final['generated_at']}")
    print()

    # ── Overall summary ──────────────────────────────────────────────
    print("┌─ OVERALL REDUCTION ─────────────────────────────────────────────┐")
    print(f"│  Baseline tokens  : {s['baseline_total_tokens']:>10,}                              │")
    print(f"│  Optimized tokens : {s['optimized_total_tokens']:>10,}  ({s['reduction_percentage']}% reduction)       │")
    print(f"│                                                                │")
    print(f"│  Baseline cost    :  ${s['baseline_estimated_cost_usd']:.5f} / run                        │")
    print(f"│  Optimized cost   :  ${s['optimized_estimated_cost_usd']:.5f} / run                        │")
    print(f"│  Savings / run    :  ${s['savings_per_run_usd']:.5f}                               │")
    print(f"│  Monthly savings  : ${s['projected_monthly_savings_usd']:>8.2f}  (@ 500 scans/month)        │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # ── Per-technique breakdown ──────────────────────────────────────
    print("┌─ SAVINGS BY TECHNIQUE ──────────────────────────────────────────┐")
    print("│  Technique                  │ Tokens Saved │ Cost Saved/run     │")
    print("│  ─────────────────────────── ─────────────  ─────────────────── │")

    ic = b["input_compression"]
    print(f"│  Input Compression          │ {ic['tokens_saved']:>12,} │ ${ic['cost_saved_usd']:.5f}           │")

    pc = b["prompt_caching"]
    print(f"│  Prompt Caching             │ {pc['tokens_saved_as_cache_reads']:>12,} │ ${pc['cache_read_cost_vs_full_input_savings_usd']:.5f}           │")

    sc = b["semantic_caching"]
    print(f"│  CVE Semantic Cache         │ {sc['calls_avoided']:>8} calls │ ${sc['cost_saved_usd']:.5f}           │")

    mr = b["model_routing"]
    print(f"│  Model Routing              │ {mr['tokens_same']:>12,} │ ${mr['cost_saved_usd']:.5f}           │")

    cm = b["context_management"]
    print(f"│  Context Management         │ {cm['tokens_saved']:>12,} │ ${cm['cost_saved_usd']:.5f}           │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # ── Per-agent highlights ─────────────────────────────────────────
    print("┌─ TOP 5 AGENTS BY REDUCTION % ───────────────────────────────────┐")
    agents = sorted(final["per_agent_breakdown"], key=lambda a: -a.get("reduction_pct", 0))[:5]
    for a in agents:
        name = a["agent"][:30].ljust(30)
        pct = a.get("reduction_pct", 0)
        baseline = a["baseline_tokens"]
        optimized = a["optimized_tokens"]
        print(f"│  {name}  {pct:5.1f}%  ({baseline:,} → {optimized:,} tokens)  │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # ── Files created ────────────────────────────────────────────────
    print("┌─ ARTIFACTS CREATED ─────────────────────────────────────────────┐")
    artifacts = [
        ("reports/token_audit_baseline.json",       "Phase 1: static analysis audit"),
        ("hakuna/utils/token_tracker.py",            "Phase 2: TokenTracker singleton + @track_tokens"),
        ("reports/token_audit_instrumented.json",    "Phase 2: instrumented baseline schema"),
        ("hakuna/preprocessing/nessus_compressor.py","Phase 3: compress_for_triage/remediation/reporting"),
        ("hakuna/cache/cve_cache.py",                "Phase 4: CVE semantic cache (24h/7d TTL)"),
        ("hakuna/routing/model_router.py",           "Phase 5: ModelRouter with full routing table"),
        ("hakuna/utils/context_manager.py",          "Phase 6: rolling_context(history, max_turns=5)"),
        ("hakuna/utils/scratchpad.py",               "Phase 6: CampaignScratchpad (<500 token state)"),
        ("reports/optimization_log.json",            "Phase delta measurements per technique"),
        ("reports/token_optimization_final.json",    "Phase 7: final report with full breakdown"),
    ]
    for path, desc in artifacts:
        print(f"│  {path:<42}  {desc:<28}│")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # ── Modified files ───────────────────────────────────────────────
    print("┌─ MODIFIED FILES ────────────────────────────────────────────────┐")
    modified = [
        ("backend/agent_engine.py",   "TokenTracker + prompt caching + rolling_context + ModelRouter fallback"),
        ("backend/agent_pipeline.py", "ModelRouter-backed get_model_for_tier()"),
        ("backend/agent_routes.py",   "ModelRouter SONNET constant for default model"),
        ("backend/integrations.py",   "TokenTracker + Haiku for connectivity test"),
    ]
    for path, desc in modified:
        print(f"│  {path:<30}  {desc:<40}│")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # ── Remaining opportunities ──────────────────────────────────────
    print("┌─ TOP REMAINING OPPORTUNITIES ───────────────────────────────────┐")
    for opp in final["remaining_opportunities"][:4]:
        # Wrap at 68 chars
        text = opp[:68]
        print(f"│  {text:<68}│")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()
    print(bar)
    print(f"  Net monthly impact: ${s['projected_monthly_savings_usd']:.2f} saved  |  {s['reduction_percentage']}% token reduction  |  All API calls tracked")
    print(bar)


if __name__ == "__main__":
    main()
