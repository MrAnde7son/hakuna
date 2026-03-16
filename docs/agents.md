# AI Agent System

The platform includes a built-in AI agent framework for security automation. Agents are LLM-powered assistants that can query your vulnerability data, generate reports, and automate triage workflows.

## Supported Providers

| Provider | Models |
|----------|--------|
| Anthropic | Claude (Sonnet, Opus, Haiku) |
| OpenAI | GPT-4, GPT-4o, GPT-3.5 |
| Google | Gemini Pro, Gemini Flash |
| Groq | Llama 3, Mixtral |

Configure your API key in the agent builder. Keys are stored per-organization.

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
