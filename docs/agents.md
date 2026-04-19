# AI Agent System

The platform includes a built-in AI agent framework for security automation. Agents are LLM-powered assistants that can query your vulnerability data, generate reports, and automate triage workflows.

## Supported Providers

| Provider | Models |
|----------|--------|
| Anthropic | Claude (Sonnet, Opus, Haiku) |
| OpenAI | GPT-4, GPT-4o, GPT-5 |
| Google Gemini | Gemini 2.x Pro, Gemini Flash |
| Google Vertex AI | Claude, Gemini via Vertex |
| Groq | Llama 3, Mixtral |
| Ollama | Self-hosted open models (local or private network) |

Configure your API key in the agent builder (or in **Settings → Integrations → LLM Providers**). Keys are stored per-organization and resolved via a fallback chain: Anthropic → OpenAI → Vertex → Gemini → Groq → Ollama. The VM scanner's specialist agents reuse the same chain.

## Template Gallery

Pre-built agent templates for common security tasks:

### Daily Triage
Produces a prioritized summary of new findings with recommended actions. Runs best on a daily cron schedule.

### Weekly Summary
Week-over-week risk trend analysis with remediation progress metrics. Designed for weekly stakeholder updates.

### Incident Response
Guided investigation playbook that analyzes a specific CVE or finding across your environment, identifies affected assets, and suggests containment steps.

### Compliance Report
Regulatory compliance assessment against frameworks like PCI DSS, HIPAA, or SOC 2 based on your current vulnerability posture.

### Executive Dashboard
C-suite risk summary with business impact language, trend charts, and key risk indicators.

## Built-in Tools

Agents have access to 50+ security tools including:

- **Query findings** — Search and filter vulnerability data
- **Check SLA status** — Review SLA compliance across severities
- **Identify risk assets** — Find highest-risk assets
- **Find quick wins** — Surface low-effort, high-impact remediations
- **Lookup exploit data** — Check exploit availability and weaponization
- **Get inventory data** — Query attack surface inventory
- **Campaign analysis** — Review campaign progress and coverage
- **Threat intel lookup** — Query MITRE ATT&CK data

## Creating an Agent

1. Navigate to **Agents** in the sidebar
2. Click **New Agent**
3. Configure:
   - **Name** and **description**
   - **System prompt** — Instructions for the agent
   - **Tools** — Select which tools the agent can use
   - **Model** — Choose LLM provider and model
4. Save and run

## Scheduling

Agents can be scheduled to run automatically:

1. Open an agent's detail page
2. Click **Schedule**
3. Enter a cron expression (e.g., `0 8 * * 1-5` for weekday mornings)
4. The next scheduled run time is displayed

## Document Uploads

Attach reference documents to provide agents with additional context:
- Policy documents
- Compliance frameworks
- Runbooks
- Architecture diagrams (text-based)

## Agent Pipelines

Agents can be chained into multi-stage pipelines with:
- **Model routing** — Use different model tiers (reasoning, deterministic, balanced) per stage
- **Context handoff** — Structured data passing between pipeline stages
- **Error handling** — Graceful failure with structured error objects
- **Context compression** — Automatic output compression to manage token limits

## Run History

Every agent execution is logged with:
- Status (success, failure, running)
- Token usage
- Step count
- Full output transcript
- Timestamp and duration

## Copilot

In addition to scheduled and on-demand agents, the platform ships a Copilot assistant surfaced on every page:

- **Desktop** — Sliding right-side panel (resizable, default 480px)
- **Mobile** — Full-screen experience launched from the bottom tab bar
- **Context-aware prompts** — Suggested prompts change per page (e.g., on Findings: "Show me critical unresolved findings")
- **Rich blocks** — Markdown, structured data tables, clickable finding/asset cards
- **Autonomy levels** — Conservative (approve all actions), Standard (auto-approve low-risk), Autonomous (approve only external side effects)

Copilot shares the agent tool registry and LLM provider chain, so autonomy and audit trails are consistent with scheduled agents.

## Specialist VM Agents

Active VM scans can run specialist LLM agents alongside Nuclei via `POST /api/vm/scan` with `enable_agents: true`.

| Specialist | Targets |
|------------|---------|
| Injection | SQLi, NoSQLi, command injection, SSTI |
| XSS | Reflected, stored, DOM-based |
| SSRF | Server-side request forgery |
| AuthN | Session fixation, MFA bypass, weak auth |
| AuthZ | IDOR, privilege escalation, horizontal/vertical bypass |

Each specialist:
- Runs on a 60-second / 10-iteration budget per asset
- Uses a shared tool registry: `http_request`, `check_pattern`, `emit_finding`
- Skips assets that fail applicability filters (e.g., AuthZ needs parameterized endpoints, SSRF needs HTTP targets)
- Reuses session cookies from the auth profile session broker
- Gracefully degrades to `skipped` status if no LLM key is configured

Filter which specialists run via `agent_categories: ["injection", "xss"]`.

## Validation Framework

Findings can be validated automatically by the LLM validator:

- **Verdict** — `true_positive`, `false_positive`, `uncertain`
- **Confidence** — 0–1 score
- **Validated at** — timestamp

Verdicts feed back into prioritization — true positives receive score bonuses. The validator writes to `findings.llm_validation` and logs each call to the LLM feedback loop for auditing.

## Agent Pipelines

Pipelines chain agents into multi-stage flows:
- **Model routing** — Per-stage model tier (reasoning / balanced / deterministic)
- **Structured handoff** — Typed JSON context between stages
- **Automatic compression** — Long-stage output is summarized before the next stage
- **Error handling** — Failed stages return structured error objects instead of aborting

Manage pipelines via `/api/agents/pipelines` endpoints.

## LLM Feedback Loop

Every LLM call (agent run, validator, Copilot turn, scan planner) is persisted:

- **Inputs** — Provider, model, system prompt hash, messages, org context
- **Outputs** — Response, tool calls (name, args, result summary, ok flag, latency ms), tokens, latency
- **Outcome** — Async-linked score in [-1, +1]
- **Retrieval** — On Postgres, pgvector embeddings enable exemplar retrieval to condition future runs

This is how the platform learns which prompts and tool patterns work best in your environment over time.
