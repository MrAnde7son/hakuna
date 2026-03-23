"""
Multi-Agent Orchestrator — parallel execution, fan-out/fan-in, and result merging.

Provides:
- invoke_agent: Run a single agent by ID with custom input
- invoke_agents_parallel: Fan-out to N agents concurrently, fan-in results
- merge_results: Combine outputs from multiple agent runs
- OrchestratorPlan: Declarative multi-agent execution plan (sequential + parallel stages)

Design decisions:
- Reuses existing run_agent() from agent_engine — no new execution path
- Uses threading (not asyncio) for parallel execution since run_agent() is sync
- Each sub-agent gets its own DB session to avoid SQLAlchemy thread-safety issues
- Results are compressed before merging to stay within LLM context limits
"""
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from models.models import Agent, AgentRun
from agents.agent_context import AgentHandoff, compress_tool_result

logger = logging.getLogger(__name__)


# ── Core: invoke a single agent ──────────────────────────────────────

def invoke_agent_by_id(
    agent_id: int,
    user_input: str,
    db: Session,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Run an existing agent by ID and return its output.

    Returns dict with: agent_id, agent_name, status, output, steps_used, run_id.
    """
    from agents.agent_engine import run_agent

    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        return {"error": f"Agent {agent_id} not found", "status": "failed"}

    try:
        run = run_agent(agent, user_input, db)
        return {
            "agent_id": agent.id,
            "agent_name": agent.name,
            "status": run.status,
            "output": run.output,
            "steps_used": run.steps_used,
            "run_id": run.id,
        }
    except Exception as e:
        logger.exception("invoke_agent_by_id failed for agent %s", agent_id)
        return {
            "agent_id": agent_id,
            "status": "failed",
            "error": str(e),
        }


def invoke_agent_by_name(
    agent_name: str,
    org_id: int,
    user_input: str,
    db: Session,
) -> Dict[str, Any]:
    """Run an existing agent by name (within an org) and return its output."""
    agent = db.query(Agent).filter(
        Agent.name == agent_name,
        Agent.org_id == org_id,
    ).first()
    if not agent:
        return {"error": f"Agent '{agent_name}' not found in org {org_id}", "status": "failed"}

    return invoke_agent_by_id(agent.id, user_input, db)


# ── Parallel execution ───────────────────────────────────────────────

def _run_agent_in_thread(agent_id: int, user_input: str, db_factory) -> Dict[str, Any]:
    """Thread-safe agent execution with its own DB session."""
    from agents.agent_engine import run_agent

    db = db_factory()
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            return {"agent_id": agent_id, "status": "failed", "error": "Agent not found"}

        run = run_agent(agent, user_input, db)
        return {
            "agent_id": agent.id,
            "agent_name": agent.name,
            "status": run.status,
            "output": run.output,
            "steps_used": run.steps_used,
            "run_id": run.id,
        }
    except Exception as e:
        logger.exception("Parallel agent %s failed", agent_id)
        return {"agent_id": agent_id, "status": "failed", "error": str(e)}
    finally:
        db.close()


def invoke_agents_parallel(
    agent_configs: List[Dict[str, Any]],
    db_factory,
    max_workers: int = 4,
    timeout: int = 600,
) -> Dict[str, Any]:
    """Fan-out: run multiple agents in parallel, fan-in their results.

    Args:
        agent_configs: List of {"agent_id": int, "input": str} dicts.
        db_factory: Callable that returns a new SQLAlchemy Session (e.g. SessionLocal).
        max_workers: Max concurrent agents.
        timeout: Total timeout in seconds for all agents.

    Returns:
        {"results": [...], "all_succeeded": bool, "duration_ms": int}
    """
    start = datetime.utcnow()
    results = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(agent_configs))) as executor:
        futures = {}
        for cfg in agent_configs:
            future = executor.submit(
                _run_agent_in_thread,
                cfg["agent_id"],
                cfg["input"],
                db_factory,
            )
            futures[future] = cfg["agent_id"]

        for future in as_completed(futures, timeout=timeout):
            agent_id = futures[future]
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                logger.exception("Future for agent %s failed", agent_id)
                results.append({
                    "agent_id": agent_id,
                    "status": "failed",
                    "error": str(e),
                })

    duration_ms = int((datetime.utcnow() - start).total_seconds() * 1000)
    return {
        "results": results,
        "all_succeeded": all(r.get("status") == "done" for r in results),
        "agent_count": len(results),
        "duration_ms": duration_ms,
    }


# ── Result merging ───────────────────────────────────────────────────

class MergeStrategy(str, Enum):
    CONCATENATE = "concatenate"   # Join all outputs as sections
    SUMMARIZE = "summarize"       # Feed outputs to a summarizer agent
    STRUCTURED = "structured"     # Merge into a keyed dict by agent name


def merge_results(
    results: List[Dict[str, Any]],
    strategy: MergeStrategy = MergeStrategy.CONCATENATE,
) -> Dict[str, Any]:
    """Merge outputs from multiple agent runs into a single payload.

    - concatenate: Join outputs as markdown sections with agent name headers
    - structured: Dict keyed by agent name with output + metadata
    """
    if strategy == MergeStrategy.CONCATENATE:
        sections = []
        for r in results:
            name = r.get("agent_name", f"Agent {r.get('agent_id', '?')}")
            output = r.get("output", r.get("error", "No output"))
            # Truncate very long outputs
            if isinstance(output, str) and len(output) > 5000:
                output = output[:5000] + "\n\n[...truncated...]"
            sections.append(f"## {name}\n\n{output}")
        return {
            "merged_output": "\n\n---\n\n".join(sections),
            "agent_count": len(results),
            "all_succeeded": all(r.get("status") == "done" for r in results),
        }

    elif strategy == MergeStrategy.STRUCTURED:
        merged = {}
        for r in results:
            name = r.get("agent_name", f"agent_{r.get('agent_id', '?')}")
            merged[name] = {
                "output": r.get("output"),
                "status": r.get("status"),
                "steps_used": r.get("steps_used"),
                "run_id": r.get("run_id"),
            }
        return {
            "agents": merged,
            "agent_count": len(results),
            "all_succeeded": all(r.get("status") == "done" for r in results),
        }

    return {"results": results}


# ── Orchestrator Plan: declarative multi-agent DAG ───────────────────

class StepType(str, Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


@dataclass
class OrchestratorStep:
    """A single step in an orchestration plan.

    For SEQUENTIAL: runs agents one at a time, piping output forward.
    For PARALLEL: runs agents concurrently, merges results.
    """
    step_type: StepType
    agents: List[Dict[str, Any]]  # [{"agent_id": int, "input_template": str}]
    merge_strategy: MergeStrategy = MergeStrategy.CONCATENATE
    name: str = ""
    description: str = ""


@dataclass
class OrchestratorPlan:
    """Declarative execution plan: sequence of sequential/parallel steps.

    Example:
        plan = OrchestratorPlan("incident_response", [
            OrchestratorStep(PARALLEL, [
                {"agent_id": 1, "input_template": "Analyze findings: {input}"},
                {"agent_id": 2, "input_template": "Check threat intel: {input}"},
            ]),
            OrchestratorStep(SEQUENTIAL, [
                {"agent_id": 3, "input_template": "Create remediation plan from:\n{previous_output}"},
            ]),
        ])
    """
    name: str
    steps: List[OrchestratorStep]
    description: str = ""


def execute_plan(
    plan: OrchestratorPlan,
    initial_input: str,
    db: Session,
    db_factory=None,
) -> Dict[str, Any]:
    """Execute an orchestrator plan, passing outputs between steps.

    Args:
        plan: The execution plan with sequential/parallel steps.
        initial_input: The starting input text.
        db: DB session for sequential steps.
        db_factory: Session factory for parallel steps (required if any step is PARALLEL).

    Returns:
        {"plan": name, "steps": [...], "final_output": str, "success": bool}
    """
    step_results = []
    current_input = initial_input
    previous_output = ""

    for i, step in enumerate(plan.steps):
        step_start = datetime.utcnow()
        logger.info("Orchestrator '%s': executing step %d (%s) — %s",
                     plan.name, i, step.step_type.value, step.name)

        if step.step_type == StepType.PARALLEL:
            if not db_factory:
                from core.database import SessionLocal
                db_factory = SessionLocal

            # Build inputs from templates
            agent_configs = []
            for agent_cfg in step.agents:
                rendered_input = agent_cfg.get("input_template", "{input}").format(
                    input=current_input,
                    previous_output=previous_output,
                )
                agent_configs.append({
                    "agent_id": agent_cfg["agent_id"],
                    "input": rendered_input,
                })

            parallel_result = invoke_agents_parallel(agent_configs, db_factory)
            merged = merge_results(parallel_result["results"], step.merge_strategy)

            previous_output = merged.get("merged_output", json.dumps(merged, default=str))
            current_input = previous_output

            step_results.append({
                "step": i,
                "name": step.name,
                "type": "parallel",
                "agent_count": parallel_result["agent_count"],
                "all_succeeded": parallel_result["all_succeeded"],
                "duration_ms": parallel_result["duration_ms"],
                "results": parallel_result["results"],
            })

        else:  # SEQUENTIAL
            seq_results = []
            for agent_cfg in step.agents:
                rendered_input = agent_cfg.get("input_template", "{input}").format(
                    input=current_input,
                    previous_output=previous_output,
                )
                result = invoke_agent_by_id(
                    agent_cfg["agent_id"],
                    rendered_input,
                    db,
                )
                seq_results.append(result)

                if result.get("status") == "done" and result.get("output"):
                    previous_output = result["output"]
                    current_input = previous_output

            step_results.append({
                "step": i,
                "name": step.name,
                "type": "sequential",
                "results": seq_results,
                "all_succeeded": all(r.get("status") == "done" for r in seq_results),
            })

        duration_ms = int((datetime.utcnow() - step_start).total_seconds() * 1000)
        step_results[-1]["duration_ms"] = duration_ms

    success = all(s.get("all_succeeded", False) for s in step_results)
    return {
        "plan": plan.name,
        "steps": step_results,
        "final_output": previous_output,
        "success": success,
    }


# ── Pre-built Orchestration Plans ────────────────────────────────────

ORCHESTRATOR_TEMPLATES = {
    "parallel_triage": {
        "name": "Parallel Triage",
        "description": (
            "Fan-out to vulnerability analyst, threat intel analyst, and asset risk scorer "
            "in parallel, then merge results into a unified triage report."
        ),
        "steps": [
            {
                "type": "parallel",
                "name": "Multi-perspective analysis",
                "merge_strategy": "concatenate",
                "agents": [
                    {"role": "vulnerability_analyst", "input_template": "Analyze the latest scan findings for critical vulnerabilities and quick wins:\n{input}"},
                    {"role": "threat_intel_analyst", "input_template": "Correlate findings with active threat campaigns and known exploits:\n{input}"},
                    {"role": "asset_risk_scorer", "input_template": "Assess asset risk posture and identify internet-facing exposure:\n{input}"},
                ],
            },
            {
                "type": "sequential",
                "name": "Triage synthesis",
                "agents": [
                    {"role": "triage_synthesizer", "input_template": "Synthesize the following multi-perspective analysis into a prioritized triage report with recommended actions:\n\n{previous_output}"},
                ],
            },
        ],
    },
    "incident_response": {
        "name": "Incident Response",
        "description": (
            "Parallel investigation by vulnerability analyst and threat intel analyst, "
            "followed by sequential remediation planning and ticket creation."
        ),
        "steps": [
            {
                "type": "parallel",
                "name": "Investigation",
                "merge_strategy": "concatenate",
                "agents": [
                    {"role": "vulnerability_analyst", "input_template": "Investigate these findings for severity, exploitability, and blast radius:\n{input}"},
                    {"role": "threat_intel_analyst", "input_template": "Check if these vulnerabilities are linked to active threat campaigns or known exploit kits:\n{input}"},
                ],
            },
            {
                "type": "sequential",
                "name": "Remediation planning",
                "agents": [
                    {"role": "remediation_planner", "input_template": "Based on the investigation results, create a prioritized remediation plan with timelines and owners:\n\n{previous_output}"},
                ],
            },
        ],
    },
    "compliance_audit": {
        "name": "Compliance Audit",
        "description": (
            "Parallel SLA compliance check, exception review, and scan coverage audit, "
            "then synthesize into a compliance report."
        ),
        "steps": [
            {
                "type": "parallel",
                "name": "Parallel audits",
                "merge_strategy": "structured",
                "agents": [
                    {"role": "sla_watchdog", "input_template": "Check SLA compliance status across all findings:\n{input}"},
                    {"role": "exception_reviewer", "input_template": "Review all risk exceptions for expiry and validity:\n{input}"},
                    {"role": "scan_coverage_auditor", "input_template": "Audit scan coverage for gaps and credential failures:\n{input}"},
                ],
            },
            {
                "type": "sequential",
                "name": "Report generation",
                "agents": [
                    {"role": "executive_summary", "input_template": "Generate an executive compliance report from these audit results:\n\n{previous_output}"},
                ],
            },
        ],
    },
}


def get_orchestrator_templates() -> List[Dict[str, Any]]:
    """Return the list of available orchestration plan templates."""
    return [
        {"id": k, "name": v["name"], "description": v["description"], "steps": v["steps"]}
        for k, v in ORCHESTRATOR_TEMPLATES.items()
    ]
