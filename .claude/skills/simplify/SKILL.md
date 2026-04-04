---
name: simplify
description: >
  Run an automated multi-agent code review on a git diff — checking for code reuse
  opportunities, quality issues, and efficiency problems — then apply fixes directly.
  Use this skill whenever the user runs /simplify, asks to review their git diff before
  committing, wants automated code review across reuse/quality/efficiency dimensions,
  or mentions "simplify focus on [area]". Always use this skill for pre-commit review
  workflows, not just when explicitly named.
---

# /simplify — Automated Code Review Skill

Run a parallel 3-agent code review on the current `git diff`, then apply fixes.

## Workflow

### Step 1: Get the diff

```bash
git diff HEAD
```

If the diff is empty, fall back to:

```bash
git diff HEAD~1
```

Save the full diff output — every agent needs it.

### Step 2: Launch 3 review agents in parallel

Spawn all three agents simultaneously using the Agent tool. Each agent receives the **full diff** and returns a structured list of findings.

#### Agent 1 — Reuse Review

> **Prompt to agent:**
> You are a code-reuse reviewer. Analyze this git diff and the surrounding codebase to find:
> - Duplicated logic that already exists elsewhere in the codebase (search for it)
> - Opportunities to extract shared helpers or utilities
> - Copy-pasted patterns that should use a common abstraction
>
> For each finding, return:
> - **File and line range** in the diff
> - **What's duplicated** and **where the existing code lives**
> - **Suggested fix** (use existing function, extract helper, etc.)
>
> Only flag real duplication — not superficial similarity. If nothing is found, say so.
>
> Diff:
> ```
> {diff}
> ```

#### Agent 2 — Quality Review

> **Prompt to agent:**
> You are a code-quality reviewer. Analyze this git diff for:
> - Bug risks (off-by-one, null/undefined, race conditions, missing error handling)
> - Security issues (injection, auth bypass, secrets in code, OWASP top 10)
> - Missing tenant isolation (`org_id` filtering) in database queries
> - Convention violations based on the project's CLAUDE.md standards
> - Dead code or unused imports introduced by the diff
>
> For each finding, return:
> - **File and line range**
> - **Issue description** and **severity** (critical / warning / info)
> - **Suggested fix**
>
> Be precise — only flag genuine issues, not style preferences. If nothing is found, say so.
>
> Diff:
> ```
> {diff}
> ```

#### Agent 3 — Efficiency Review

> **Prompt to agent:**
> You are a performance/efficiency reviewer. Analyze this git diff for:
> - N+1 query patterns or unnecessary DB round-trips
> - Missing database indexes for new query patterns
> - Inefficient loops that could use bulk operations
> - Unnecessary re-renders in React components (missing memo, unstable deps)
> - Large payloads or missing pagination
> - Redundant API calls or computations
>
> For each finding, return:
> - **File and line range**
> - **What's inefficient** and **estimated impact** (high / medium / low)
> - **Suggested optimization**
>
> Only flag measurable inefficiencies, not micro-optimizations. If nothing is found, say so.
>
> Diff:
> ```
> {diff}
> ```

### Step 3: Synthesize results

After all three agents complete:

1. Collect all findings into a unified list
2. Deduplicate — if multiple agents flagged the same issue, merge them
3. Sort by severity (critical > warning > info) then by file
4. Present a summary table to the user:

```
| # | File | Line(s) | Category | Severity | Issue |
|---|------|---------|----------|----------|-------|
```

### Step 4: Apply fixes

For each actionable finding (critical and warning severity):

1. Read the relevant file
2. Apply the fix using the Edit tool
3. Mark the finding as resolved

Skip info-level findings unless the user asks to fix everything.

### Step 5: Report

After applying fixes, show:
- How many issues were found per category (reuse / quality / efficiency)
- How many were auto-fixed vs. skipped
- Any remaining items that need manual attention

## Focus mode

If the user says `/simplify focus on [area]`, only run the relevant agent:
- `reuse` — only Agent 1
- `quality` — only Agent 2
- `efficiency` — only Agent 3
