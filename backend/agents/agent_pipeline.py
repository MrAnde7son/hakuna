"""
Agent Pipeline Architecture — decomposed multi-agent pipelines with typed handoffs,
error handling, and model routing.

Provides:
- Pipeline: ordered chain of agent stages with typed handoff validation
- Stage: single-responsibility agent execution unit
- Error handling: structured error objects for tool failures, ambiguous input, low confidence
- Model routing: use powerful models for reasoning, fast models for deterministic work
"""
import json
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from models.models import Agent, AgentRun
from agents.agent_context import AgentHandoff, validate_handoff

from hakuna.routing.model_router import ModelRouter as _ModelRouter

_model_router = _ModelRouter()

logger = logging.getLogger(__name__)


# ── Model Routing ────────────────────────────────────────────────────

class ModelTier(str, Enum):
    """Model tiers for routing different pipeline stages."""
    REASONING = "reasoning"      # Complex analysis: risk scoring, remediation planning, triage
    DETERMINISTIC = "deterministic"  # Field normalization, ticket formatting, data extraction
    BALANCED = "balanced"        # General-purpose, good for most stages


# Default model mapping per tier — now backed by ModelRouter for consistency
DEFAULT_MODEL_ROUTING = {
    ModelTier.REASONING: "claude-sonnet-4-6",
    ModelTier.DETERMINISTIC: "claude-haiku-4-5-20251001",
    ModelTier.BALANCED: "claude-sonnet-4-6",
}

# Tier → ModelRouter task_type mapping
_TIER_TO_TASK_TYPE = {
    ModelTier.REASONING: "remediation_planning",
    ModelTier.DETERMINISTIC: "normalization",
    ModelTier.BALANCED: "default",
}


def get_model_for_tier(tier: ModelTier, override: Optional[str] = None) -> str:
    """Get the model ID for a given tier via ModelRouter, with optional override."""
    if override:
        return override
    task_type = _TIER_TO_TASK_TYPE.get(tier, "default")
    return _model_router.select_model(task_type)


# ── Structured Error Objects ─────────────────────────────────────────

class AgentErrorType(str, Enum):
    TOOL_FAILURE = "tool_failure"
    AMBIGUOUS_INPUT = "ambiguous_input"
    LOW_CONFIDENCE = "low_confidence"
    VALIDATION_ERROR = "validation_error"
    MAX_STEPS_EXCEEDED = "max_steps_exceeded"
    PROVIDER_ERROR = "provider_error"


class AgentError:
    """Structured error object emitted by pipeline stages."""

    def __init__(
        self,
        error_type: AgentErrorType,
        message: str,
        stage_name: str,
        recoverable: bool = True,
        details: Optional[dict] = None,
        suggested_action: Optional[str] = None,
    ):
        self.error_type = error_type
        self.message = message
        self.stage_name = stage_name
        self.recoverable = recoverable
        self.details = details or {}
        self.suggested_action = suggested_action
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "error_type": self.error_type.value,
            "message": self.message,
            "stage": self.stage_name,
            "recoverable": self.recoverable,
            "details": self.details,
            "suggested_action": self.suggested_action,
            "timestamp": self.timestamp,
        }


# ── Pipeline Stage ───────────────────────────────────────────────────

class PipelineStage:
    """A single stage in an agent pipeline.

    Each stage has:
    - A name and description
    - A model tier (determines which model to use)
    - A system prompt focused on a single responsibility
    - A list of tools it's allowed to use
    - An input handoff type it expects
    - An output handoff type it produces
    - Error handling behavior
    """

    def __init__(
        self,
        name: str,
        description: str,
        system_prompt: str,
        tools: List[str],
        model_tier: ModelTier = ModelTier.BALANCED,
        input_type: Optional[str] = None,
        output_type: Optional[str] = None,
        max_steps: int = 10,
        on_error: str = "stop",  # "stop", "skip", "retry"
        retry_count: int = 1,
    ):
        self.name = name
        self.description = description
        self.system_prompt = system_prompt
        self.tools = tools
        self.model_tier = model_tier
        self.input_type = input_type
        self.output_type = output_type
        self.max_steps = max_steps
        self.on_error = on_error
        self.retry_count = retry_count


class StageResult:
    """Result of executing a pipeline stage."""

    def __init__(
        self,
        stage_name: str,
        success: bool,
        output: Optional[str] = None,
        handoff: Optional[AgentHandoff] = None,
        error: Optional[AgentError] = None,
        trace: Optional[list] = None,
        model_used: Optional[str] = None,
        steps_used: int = 0,
    ):
        self.stage_name = stage_name
        self.success = success
        self.output = output
        self.handoff = handoff
        self.error = error
        self.trace = trace or []
        self.model_used = model_used
        self.steps_used = steps_used

    def to_dict(self) -> dict:
        d = {
            "stage": self.stage_name,
            "success": self.success,
            "model_used": self.model_used,
            "steps_used": self.steps_used,
        }
        if self.output:
            d["output"] = self.output[:2000]
        if self.error:
            d["error"] = self.error.to_dict()
        if self.handoff:
            d["handoff"] = self.handoff.to_dict()
        return d


# ── Pipeline ─────────────────────────────────────────────────────────

class AgentPipeline:
    """Ordered chain of agent stages with typed handoffs and error handling.

    Usage:
        pipeline = AgentPipeline("vuln_triage", [
            PipelineStage("ingest", ..., output_type="normalized_findings"),
            PipelineStage("score", ..., input_type="normalized_findings", output_type="risk_scores"),
            PipelineStage("plan", ..., input_type="risk_scores", output_type="remediation_plan"),
        ])
        results = pipeline.execute(db, user_input, scan_id)
    """

    def __init__(self, name: str, stages: List[PipelineStage]):
        self.name = name
        self.stages = stages
        self._validate_pipeline()

    def _validate_pipeline(self):
        """Validate that handoff types chain correctly."""
        for i in range(1, len(self.stages)):
            prev_output = self.stages[i - 1].output_type
            curr_input = self.stages[i].input_type
            if curr_input and prev_output and curr_input != prev_output:
                logger.warning(
                    f"Pipeline '{self.name}': stage '{self.stages[i].name}' expects "
                    f"input type '{curr_input}' but previous stage '{self.stages[i-1].name}' "
                    f"outputs '{prev_output}'"
                )

    def execute(
        self,
        db: Session,
        user_input: str,
        model_overrides: Optional[Dict[str, str]] = None,
    ) -> List[StageResult]:
        """Execute the full pipeline, passing handoffs between stages.

        Returns list of StageResult objects (one per stage).
        """
        from agents.agent_engine import run_agent

        model_overrides = model_overrides or {}
        results: List[StageResult] = []
        current_input = user_input

        for stage in self.stages:
            logger.info(f"Pipeline '{self.name}': executing stage '{stage.name}'")

            # Build a transient Agent object for this stage
            model = get_model_for_tier(
                stage.model_tier,
                model_overrides.get(stage.name),
            )

            agent = Agent(
                name=f"{self.name}/{stage.name}",
                description=stage.description,
                system_prompt=stage.system_prompt,
                tools=stage.tools,
                guardrails={"max_steps": stage.max_steps, "read_only": stage.model_tier == ModelTier.DETERMINISTIC},
                model=model,
            )
            # Assign a temp ID so scratchpad works
            agent.id = hash(f"{self.name}_{stage.name}") % 100000

            # Execute with retry logic
            stage_result = self._execute_stage(agent, stage, current_input, db, model)
            results.append(stage_result)

            if not stage_result.success:
                if stage.on_error == "stop":
                    logger.error(f"Pipeline '{self.name}': stopping at stage '{stage.name}' due to error")
                    break
                elif stage.on_error == "skip":
                    logger.warning(f"Pipeline '{self.name}': skipping failed stage '{stage.name}'")
                    continue
                # "retry" is handled inside _execute_stage

            # Pass output to next stage
            if stage_result.handoff:
                current_input = (
                    f"Previous stage '{stage.name}' produced this handoff data. "
                    f"Process it according to your instructions.\n\n"
                    f"```json\n{stage_result.handoff.to_json()}\n```"
                )
            elif stage_result.output:
                current_input = (
                    f"Previous stage '{stage.name}' output:\n\n{stage_result.output}"
                )

        return results

    def _execute_stage(
        self,
        agent: Agent,
        stage: PipelineStage,
        user_input: str,
        db: Session,
        model: str,
    ) -> StageResult:
        """Execute a single stage with error handling and retry logic."""
        from agents.agent_engine import run_agent

        attempts = stage.retry_count + 1 if stage.on_error == "retry" else 1

        for attempt in range(attempts):
            try:
                run = run_agent(agent, user_input, db)

                if run.status == "failed":
                    error = AgentError(
                        error_type=AgentErrorType.PROVIDER_ERROR,
                        message=run.error or "Agent execution failed",
                        stage_name=stage.name,
                        recoverable=attempt < attempts - 1,
                        details={"attempt": attempt + 1, "max_attempts": attempts},
                        suggested_action="Check API key configuration and retry",
                    )
                    if attempt < attempts - 1:
                        logger.warning(f"Stage '{stage.name}' failed (attempt {attempt + 1}), retrying...")
                        continue
                    return StageResult(
                        stage_name=stage.name, success=False, error=error,
                        trace=run.trace, model_used=model,
                    )

                # Try to parse handoff from output
                handoff = self._extract_handoff(stage, run.output)

                return StageResult(
                    stage_name=stage.name,
                    success=True,
                    output=run.output,
                    handoff=handoff,
                    trace=run.trace,
                    model_used=model,
                    steps_used=run.steps_used or 0,
                )

            except Exception as e:
                logger.exception(f"Stage '{stage.name}' exception (attempt {attempt + 1})")
                if attempt < attempts - 1:
                    continue
                return StageResult(
                    stage_name=stage.name,
                    success=False,
                    error=AgentError(
                        error_type=AgentErrorType.PROVIDER_ERROR,
                        message=str(e),
                        stage_name=stage.name,
                        recoverable=False,
                    ),
                    model_used=model,
                )

        # Should not reach here
        return StageResult(stage_name=stage.name, success=False)

    def execute_with_parallel(
        self,
        db: Session,
        user_input: str,
        parallel_groups: Optional[Dict[str, List[str]]] = None,
        model_overrides: Optional[Dict[str, str]] = None,
        db_factory=None,
    ) -> List[StageResult]:
        """Execute pipeline with support for parallel stage groups.

        Args:
            parallel_groups: Dict mapping group name to list of stage names that
                             should run concurrently. E.g. {"analysis": ["risk_scoring", "threat_check"]}
            db_factory: Session factory for parallel execution (required for parallel groups).

        Stages not in any parallel group run sequentially as normal.
        """
        from agents.agent_engine import run_agent

        model_overrides = model_overrides or {}
        parallel_groups = parallel_groups or {}
        results: List[StageResult] = []
        current_input = user_input

        # Build reverse lookup: stage_name -> group_name
        stage_to_group = {}
        for group_name, stage_names in parallel_groups.items():
            for sn in stage_names:
                stage_to_group[sn] = group_name

        # Track which groups have been executed
        executed_groups = set()

        i = 0
        while i < len(self.stages):
            stage = self.stages[i]
            group = stage_to_group.get(stage.name)

            if group and group not in executed_groups:
                # Collect all stages in this parallel group
                group_stages = [s for s in self.stages if s.name in parallel_groups[group]]
                executed_groups.add(group)

                if not db_factory:
                    from core.database import SessionLocal
                    db_factory = SessionLocal

                group_results = self._execute_parallel_group(
                    group_stages, current_input, db_factory, model_overrides
                )
                results.extend(group_results)

                # Merge outputs from parallel group for the next stage
                outputs = [r.output for r in group_results if r.success and r.output]
                if outputs:
                    current_input = (
                        f"Results from parallel analysis ({', '.join(s.name for s in group_stages)}):\n\n"
                        + "\n\n---\n\n".join(outputs)
                    )

                # Skip past all stages in this group
                i += 1
                continue

            elif group and group in executed_groups:
                # Already executed as part of parallel group
                i += 1
                continue

            # Normal sequential execution
            logger.info(f"Pipeline '{self.name}': executing stage '{stage.name}'")
            model = get_model_for_tier(stage.model_tier, model_overrides.get(stage.name))
            agent = Agent(
                name=f"{self.name}/{stage.name}",
                description=stage.description,
                system_prompt=stage.system_prompt,
                tools=stage.tools,
                guardrails={"max_steps": stage.max_steps, "read_only": stage.model_tier == ModelTier.DETERMINISTIC},
                model=model,
            )
            agent.id = hash(f"{self.name}_{stage.name}") % 100000

            stage_result = self._execute_stage(agent, stage, current_input, db, model)
            results.append(stage_result)

            if not stage_result.success and stage.on_error == "stop":
                break

            if stage_result.handoff:
                current_input = (
                    f"Previous stage '{stage.name}' produced this handoff data. "
                    f"Process it according to your instructions.\n\n"
                    f"```json\n{stage_result.handoff.to_json()}\n```"
                )
            elif stage_result.output:
                current_input = f"Previous stage '{stage.name}' output:\n\n{stage_result.output}"

            i += 1

        return results

    def _execute_parallel_group(
        self,
        stages: List[PipelineStage],
        user_input: str,
        db_factory,
        model_overrides: Dict[str, str],
    ) -> List[StageResult]:
        """Execute a group of stages in parallel using threads."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from agents.agent_engine import run_agent

        def _run_stage(stage: PipelineStage) -> StageResult:
            db = db_factory()
            try:
                model = get_model_for_tier(stage.model_tier, model_overrides.get(stage.name))
                agent = Agent(
                    name=f"{self.name}/{stage.name}",
                    description=stage.description,
                    system_prompt=stage.system_prompt,
                    tools=stage.tools,
                    guardrails={"max_steps": stage.max_steps, "read_only": stage.model_tier == ModelTier.DETERMINISTIC},
                    model=model,
                )
                agent.id = hash(f"{self.name}_{stage.name}") % 100000

                run = run_agent(agent, user_input, db)

                if run.status == "failed":
                    return StageResult(
                        stage_name=stage.name, success=False,
                        error=AgentError(
                            error_type=AgentErrorType.PROVIDER_ERROR,
                            message=run.error or "Agent execution failed",
                            stage_name=stage.name,
                        ),
                        trace=run.trace, model_used=model,
                    )

                handoff = self._extract_handoff(stage, run.output)
                return StageResult(
                    stage_name=stage.name, success=True,
                    output=run.output, handoff=handoff,
                    trace=run.trace, model_used=model,
                    steps_used=run.steps_used or 0,
                )
            except Exception as e:
                logger.exception(f"Parallel stage '{stage.name}' failed")
                return StageResult(
                    stage_name=stage.name, success=False,
                    error=AgentError(
                        error_type=AgentErrorType.PROVIDER_ERROR,
                        message=str(e), stage_name=stage.name,
                    ),
                )
            finally:
                db.close()

        stage_names = [s.name for s in stages]
        logger.info(f"Pipeline '{self.name}': executing parallel group {stage_names}")

        results = []
        with ThreadPoolExecutor(max_workers=len(stages)) as executor:
            futures = {executor.submit(_run_stage, s): s.name for s in stages}
            for future in as_completed(futures):
                try:
                    results.append(future.result(timeout=300))
                except Exception as e:
                    stage_name = futures[future]
                    results.append(StageResult(
                        stage_name=stage_name, success=False,
                        error=AgentError(
                            error_type=AgentErrorType.PROVIDER_ERROR,
                            message=str(e), stage_name=stage_name,
                        ),
                    ))

        # Sort results back to original stage order
        order = {s.name: i for i, s in enumerate(stages)}
        results.sort(key=lambda r: order.get(r.stage_name, 999))
        return results

    def _extract_handoff(self, stage: PipelineStage, output: Optional[str]) -> Optional[AgentHandoff]:
        """Try to extract a structured handoff from agent output."""
        if not output or not stage.output_type:
            return None

        # Look for JSON block in output
        try:
            # Try parsing the whole output as JSON
            data = json.loads(output)
            if isinstance(data, dict) and "handoff" in data:
                return AgentHandoff.from_dict(data)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try to find a JSON code block
        import re
        json_match = re.search(r'```json\s*\n(.*?)\n```', output, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if isinstance(data, dict):
                    handoff = AgentHandoff(
                        source_agent=stage.name,
                        target_agent="next",
                        handoff_type=stage.output_type,
                        payload=data,
                    )
                    errors = validate_handoff(handoff)
                    if errors:
                        logger.warning(f"Handoff validation errors: {errors}")
                    return handoff
            except (json.JSONDecodeError, TypeError):
                pass

        return None


# ── Pre-built Pipeline Templates ─────────────────────────────────────

def build_triage_pipeline() -> AgentPipeline:
    """Pre-built pipeline: Scan Ingest → Risk Scoring → Triage Decisions."""
    return AgentPipeline("vulnerability_triage", [
        PipelineStage(
            name="ingest",
            description="Ingest and normalize scan data",
            system_prompt=(
                "You are a scan data normalization agent. Your ONLY job is to:\n"
                "1. Call list_scans to find the latest scan\n"
                "2. Call get_scan_summary to get the overview\n"
                "3. Call get_exploit_findings to identify weaponized vulns\n"
                "4. Output a structured JSON handoff with normalized data\n\n"
                "Output format (JSON code block):\n"
                "```json\n"
                '{"scan_id": N, "scan_name": "...", "total_findings": N, '
                '"severity_counts": {"critical": N, ...}, '
                '"exploit_findings_count": N, "top_families": [...]}\n'
                "```\n"
                "Do NOT analyze or score — just normalize and pass data."
            ),
            tools=["list_scans", "get_scan_summary", "get_exploit_findings", "get_plugin_family_stats"],
            model_tier=ModelTier.DETERMINISTIC,
            output_type="normalized_findings",
            max_steps=5,
        ),
        PipelineStage(
            name="risk_scoring",
            description="Score and rank findings by real-world risk",
            system_prompt=(
                "You are a risk scoring agent. You receive normalized scan data from the ingest stage.\n\n"
                "Your job:\n"
                "1. Use get_top_risky_assets to identify the highest-risk hosts\n"
                "2. Use get_exploit_findings to find weaponized vulnerabilities\n"
                "3. Use get_sla_status to check compliance deadlines\n"
                "4. Use get_internet_facing_risk to identify exposed assets\n\n"
                "Apply this reasoning chain for each critical finding:\n"
                "- Is it exploitable? (exploit_available, EPSS > 0.5)\n"
                "- Is the asset internet-facing?\n"
                "- Is the asset high-criticality (criticality >= 7)?\n"
                "- Is it SLA-breached or at-risk?\n"
                "- Are there compensating controls?\n\n"
                "Output a JSON handoff with scored findings:\n"
                "```json\n"
                '{"scored_findings": [...], "scoring_model": "multi-factor", '
                '"timestamp": "...", "risk_summary": {...}}\n'
                "```"
            ),
            tools=[
                "get_top_risky_assets", "get_exploit_findings", "get_sla_status",
                "get_internet_facing_risk", "get_finding_detail", "get_asset_profile",
            ],
            model_tier=ModelTier.REASONING,
            input_type="normalized_findings",
            output_type="risk_scores",
            max_steps=10,
        ),
        PipelineStage(
            name="triage_decisions",
            description="Make triage decisions and produce actionable plan",
            system_prompt=(
                "You are a triage decision agent. You receive risk-scored findings.\n\n"
                "For each high-risk item, decide:\n"
                "1. IMMEDIATE: Exploitable + internet-facing + no compensating control → ticket NOW\n"
                "2. URGENT: Exploitable OR SLA-breached → schedule this sprint\n"
                "3. PLANNED: High severity but not actively exploited → next maintenance window\n"
                "4. MONITOR: Medium with compensating controls → track, no immediate action\n"
                "5. ACCEPT: Low risk + compensating control → exception candidate\n\n"
                "Think step-by-step for each decision. Show your reasoning.\n\n"
                "Output a prioritized action plan in markdown with:\n"
                "- Immediate actions (today)\n"
                "- Sprint items (this week)\n"
                "- Planned items (next window)\n"
                "- Exception candidates\n\n"
                "Include specific finding IDs, asset IPs, and recommended owners for each item."
            ),
            tools=[
                "get_finding_detail", "get_asset_profile", "get_owner_workload",
                "get_remediation_grouping", "get_quick_wins",
            ],
            model_tier=ModelTier.REASONING,
            input_type="risk_scores",
            max_steps=10,
        ),
    ])


def build_patch_planning_pipeline() -> AgentPipeline:
    """Pre-built pipeline: Patch Gap Analysis → Impact Assessment → Patch Plan."""
    return AgentPipeline("patch_planning", [
        PipelineStage(
            name="patch_gap_analysis",
            description="Identify missing patches and their scope",
            system_prompt=(
                "You are a patch gap analysis agent. Your job:\n"
                "1. List all scans and pick the latest\n"
                "2. Get missing patches sorted by vuln count\n"
                "3. Get OS breakdown to understand the fleet\n"
                "4. Get exploit findings to identify weaponized patch gaps\n\n"
                "Output a JSON handoff with patch gap data:\n"
                "```json\n"
                '{"scan_id": N, "missing_patches": [...], "os_breakdown": [...], '
                '"exploitable_gaps": [...]}\n'
                "```"
            ),
            tools=["list_scans", "get_scan_summary", "get_missing_patches", "get_os_breakdown", "get_exploit_findings"],
            model_tier=ModelTier.DETERMINISTIC,
            output_type="normalized_findings",
            max_steps=6,
        ),
        PipelineStage(
            name="impact_assessment",
            description="Assess impact and prioritize patches",
            system_prompt=(
                "You are a patch impact assessment agent. You receive patch gap data.\n\n"
                "For each patch/KB:\n"
                "1. How many assets does it affect?\n"
                "2. Are any affected assets internet-facing or high-criticality?\n"
                "3. Does the patch fix an actively exploited vulnerability?\n"
                "4. Does the patch require a reboot?\n"
                "5. What's the blast radius if the patch causes issues?\n\n"
                "Think step-by-step. Rank patches by: exploit risk > asset count > severity.\n\n"
                "Output a prioritized patch list with reasoning."
            ),
            tools=[
                "get_internet_facing_risk", "get_top_risky_assets",
                "get_remediation_grouping", "query_findings", "get_finding_detail",
            ],
            model_tier=ModelTier.REASONING,
            input_type="normalized_findings",
            output_type="remediation_plan",
            max_steps=10,
        ),
        PipelineStage(
            name="patch_plan",
            description="Produce the final patch deployment plan",
            system_prompt=(
                "You are a patch deployment planner. You receive prioritized patch data.\n\n"
                "Create a phased deployment plan:\n"
                "- **Wave 1 (Emergency)**: Internet-facing + exploitable. Deploy within 24h.\n"
                "- **Wave 2 (Critical)**: High-criticality internal. Deploy within 72h.\n"
                "- **Wave 3 (Standard)**: Remaining high/medium. Next maintenance window.\n"
                "- **Wave 4 (Low priority)**: Low-risk patches. Monthly cycle.\n\n"
                "For each wave, specify:\n"
                "- Patches (KB IDs)\n"
                "- Target asset count and OS types\n"
                "- Reboot requirement\n"
                "- Recommended change window\n"
                "- Rollback plan\n\n"
                "Format as a clear markdown table."
            ),
            tools=["get_os_breakdown", "get_owner_workload", "query_assets"],
            model_tier=ModelTier.REASONING,
            input_type="remediation_plan",
            max_steps=8,
        ),
    ])


def build_ticket_pipeline() -> AgentPipeline:
    """Pre-built pipeline: Finding Analysis → Ticket Drafting → Ticket Creation."""
    return AgentPipeline("auto_ticketing", [
        PipelineStage(
            name="finding_analysis",
            description="Analyze findings and group for ticketing",
            system_prompt=(
                "You are a finding analysis agent preparing data for ticket creation.\n\n"
                "1. Get exploit findings (highest urgency)\n"
                "2. Group by solution (remediation grouping) to minimize ticket count\n"
                "3. For each group, gather: affected asset IPs, severity range, exploit status\n\n"
                "Output a JSON handoff:\n"
                "```json\n"
                '{"tickets": [{"title": "...", "priority": "...", "finding_ids": [...], '
                '"asset_count": N, "severity": "...", "solution_summary": "..."}], '
                '"ticketing_system": "jira", "requires_confirmation": true}\n'
                "```"
            ),
            tools=[
                "get_exploit_findings", "get_remediation_grouping", "query_findings",
                "get_finding_detail", "get_internet_facing_risk",
            ],
            model_tier=ModelTier.DETERMINISTIC,
            output_type="ticket_batch",
            max_steps=8,
        ),
        PipelineStage(
            name="ticket_review",
            description="Review and present tickets for user approval",
            system_prompt=(
                "You are a ticket review agent. You receive a batch of draft tickets.\n\n"
                "For each ticket:\n"
                "1. Verify the title is clear and specific (not generic)\n"
                "2. Verify the priority matches the severity and exploit status\n"
                "3. Verify the description includes affected assets and remediation steps\n"
                "4. Flag any tickets that seem like duplicates\n\n"
                "Present the ticket batch to the user in a clear table format.\n"
                "Ask the user to confirm before proceeding.\n\n"
                "IMPORTANT: Do NOT create tickets. Only present them for review.\n"
                "End your output with: 'Reply YES to create these tickets, or specify changes.'"
            ),
            tools=["get_finding_detail", "get_asset_profile"],
            model_tier=ModelTier.REASONING,
            input_type="ticket_batch",
            max_steps=6,
        ),
    ])


# ── Exception Review Pipeline ────────────────────────────────────────

def build_exception_review_pipeline() -> AgentPipeline:
    """Pre-built pipeline: Expiry Scan → Risk Reassessment → Recertification/Revocation."""
    return AgentPipeline("exception_review", [
        PipelineStage(
            name="expiry_scan",
            description="Find expiring and overdue risk exceptions",
            system_prompt=(
                "You are an exception expiry scanner. Your job:\n"
                "1. Query all active exceptions and check their expiry/review dates\n"
                "2. Bucket them into: EXPIRED (past expires_at), EXPIRING_SOON (within 14 days),\n"
                "   REVIEW_OVERDUE (past review_by), and HEALTHY\n"
                "3. For each non-healthy exception, pull the underlying finding details\n"
                "4. Check if the original risk context has changed (asset still exists? severity changed?)\n\n"
                "Output a JSON handoff:\n"
                "```json\n"
                '{"expired": [...], "expiring_soon": [...], "review_overdue": [...],\n'
                ' "total_active": N, "total_needing_action": N,\n'
                ' "finding_details": {exception_id: {finding_id, severity, asset_ip, ...}}}\n'
                "```\n"
                "Be thorough — check every active exception."
            ),
            tools=["query_findings", "get_finding_detail", "get_asset_profile", "get_sla_status"],
            model_tier=ModelTier.DETERMINISTIC,
            output_type="exception_audit",
            max_steps=8,
        ),
        PipelineStage(
            name="risk_reassessment",
            description="Reassess whether exception justifications still apply",
            system_prompt=(
                "You are a risk reassessment agent. You receive exception audit data.\n\n"
                "For each exception needing action, assess:\n"
                "1. Has the threat landscape changed? (new exploits for the CVE? added to CISA KEV?)\n"
                "2. Has the asset exposure changed? (became internet-facing? criticality increased?)\n"
                "3. Is the compensating control still in place? (check security controls inventory)\n"
                "4. Has the finding severity been updated by the scanner?\n"
                "5. Are there similar findings on other assets that are NOT excepted?\n\n"
                "For each exception, assign a reassessment verdict:\n"
                "- RENEW: Original justification still valid, risk level unchanged\n"
                "- REVOKE: Risk has materially increased, exception should be removed\n"
                "- MODIFY: Conditions changed, exception needs updated scope/justification\n"
                "- ESCALATE: Uncertain, requires human review with additional context\n\n"
                "Think step-by-step for each verdict. Show your reasoning.\n\n"
                "Output a JSON handoff:\n"
                "```json\n"
                '{"verdicts": [{"exception_id": N, "verdict": "...", "reasoning": "...",\n'
                '  "risk_change": "increased/decreased/unchanged", "evidence": [...]}]}\n'
                "```"
            ),
            tools=[
                "get_finding_detail", "get_asset_profile", "get_exploit_findings",
                "get_internet_facing_risk", "query_findings",
            ],
            model_tier=ModelTier.REASONING,
            input_type="exception_audit",
            output_type="reassessment_verdicts",
            max_steps=12,
        ),
        PipelineStage(
            name="recertification_report",
            description="Produce recertification actions and summary report",
            system_prompt=(
                "You are a recertification report agent. You receive reassessment verdicts.\n\n"
                "Produce a clear, actionable recertification report:\n\n"
                "For RENEW verdicts:\n"
                "- Draft a renewal note with updated justification\n"
                "- Suggest new expiry date (typically +90 days or +180 days)\n\n"
                "For REVOKE verdicts:\n"
                "- List the findings that will return to active remediation\n"
                "- Estimate SLA impact (when will they breach?)\n"
                "- Suggest immediate owner assignment\n\n"
                "For MODIFY verdicts:\n"
                "- Specify what needs to change (scope, justification, severity override)\n"
                "- Draft updated exception parameters\n\n"
                "For ESCALATE verdicts:\n"
                "- Summarize the uncertainty and what additional information is needed\n"
                "- Suggest who should make the decision (CISO, risk committee, etc.)\n\n"
                "Format as a markdown report with clear action items and owners."
            ),
            tools=["get_finding_detail", "get_owner_workload", "get_sla_status"],
            model_tier=ModelTier.REASONING,
            input_type="reassessment_verdicts",
            max_steps=8,
        ),
    ])


# ── Compliance Posture Pipeline ──────────────────────────────────────

def build_compliance_posture_pipeline() -> AgentPipeline:
    """Pre-built pipeline: SLA Audit → Owner Accountability → Board Report."""
    return AgentPipeline("compliance_posture", [
        PipelineStage(
            name="sla_audit",
            description="Full SLA compliance snapshot across all severities",
            system_prompt=(
                "You are an SLA audit agent. Your job:\n"
                "1. Call `get_sla_status` to get the full SLA compliance picture\n"
                "2. Break down compliance by severity: critical, high, medium, low\n"
                "3. Calculate compliance rate per severity (resolved on time / total)\n"
                "4. Identify the worst-performing severity tier\n"
                "5. Get remediation velocity data to understand trending\n"
                "6. Check for any findings breached > 30 days — these are extreme outliers\n\n"
                "Output a JSON handoff:\n"
                "```json\n"
                '{"sla_snapshot": {"critical": {"total": N, "compliant": N, "breached": N, "at_risk": N},\n'
                '  "high": {...}, "medium": {...}, "low": {...}},\n'
                ' "overall_compliance_pct": N, "extreme_outliers": [...],\n'
                ' "velocity": {"trend": "improving/declining/stable", "data": [...]}}\n'
                "```"
            ),
            tools=["get_sla_status", "query_findings", "get_scan_summary", "list_scans"],
            model_tier=ModelTier.DETERMINISTIC,
            output_type="sla_audit",
            max_steps=8,
        ),
        PipelineStage(
            name="owner_accountability",
            description="Group breaches by owner/team and compute per-team metrics",
            system_prompt=(
                "You are an owner accountability analyst. You receive SLA audit data.\n\n"
                "Your job:\n"
                "1. Call `get_owner_workload` to get per-owner finding distribution\n"
                "2. For each owner with breached findings, calculate:\n"
                "   - Total assigned findings\n"
                "   - Resolved on time (count and %)\n"
                "   - Currently breached (count)\n"
                "   - Average days overdue for breached items\n"
                "   - Remediation velocity (findings resolved per week)\n"
                "3. Identify repeat offenders (owners with breaches in 3+ consecutive periods)\n"
                "4. Rank owners by accountability score: A (< 5% breach) through F (> 50% breach)\n"
                "5. Identify teams with no owner assigned — these are governance gaps\n\n"
                "Think step-by-step. Use actual data, not estimates.\n\n"
                "Output a JSON handoff:\n"
                "```json\n"
                '{"owner_scores": [{"owner": "...", "grade": "A-F", "total": N,\n'
                '  "resolved_on_time": N, "breached": N, "avg_days_overdue": N,\n'
                '  "velocity": N, "repeat_offender": true/false}],\n'
                ' "unowned_findings": N, "governance_gaps": [...]}\n'
                "```"
            ),
            tools=[
                "get_owner_workload", "query_findings", "get_finding_detail",
                "get_top_risky_assets",
            ],
            model_tier=ModelTier.REASONING,
            input_type="sla_audit",
            output_type="accountability_report",
            max_steps=10,
        ),
        PipelineStage(
            name="board_report",
            description="Generate board-ready compliance posture report",
            system_prompt=(
                "You are an executive communications specialist. You receive SLA audit data\n"
                "and owner accountability data. Produce a board-ready compliance posture report.\n\n"
                "Rules for board communication:\n"
                "- NO technical jargon (no CVEs, plugin IDs, IP addresses)\n"
                "- Use business language: 'risk exposure', 'compliance rate', 'remediation velocity'\n"
                "- Use trend arrows: improving ↑, declining ↓, stable →\n"
                "- Use letter grades and traffic light colors (Red/Amber/Green)\n"
                "- Compare to previous period where data allows\n"
                "- Highlight top 3 risks and top 3 improvements\n\n"
                "Report structure:\n"
                "1. **Risk Posture Summary** — one paragraph, overall health\n"
                "2. **Compliance Scorecard** — table with severity tiers and RAG status\n"
                "3. **Trending** — are we getting better or worse? By how much?\n"
                "4. **Team Performance** — top performers and underperformers (by grade)\n"
                "5. **Key Risks** — top 3 business risks from unresolved vulnerabilities\n"
                "6. **Recommendations** — 3 strategic actions for leadership\n\n"
                "Format as clean markdown suitable for a slide deck or PDF export."
            ),
            tools=["get_scan_summary", "get_top_risky_assets"],
            model_tier=ModelTier.REASONING,
            input_type="accountability_report",
            max_steps=8,
        ),
    ])


# ── Threat-Driven Prioritization Pipeline ────────────────────────────

def build_threat_driven_pipeline() -> AgentPipeline:
    """Pre-built pipeline: Threat Intel Match → Exposure Mapping → Response Plan."""
    return AgentPipeline("threat_driven_prioritization", [
        PipelineStage(
            name="threat_intel_match",
            description="Match active threat campaigns against CVE inventory",
            system_prompt=(
                "You are a threat intelligence correlation agent. Your job:\n"
                "1. Get the latest scan findings with CVE data\n"
                "2. Cross-reference CVEs against known threat actor toolkits and active campaigns\n"
                "3. Check for CISA KEV entries (actively exploited in the wild)\n"
                "4. Check EPSS scores for exploit probability\n"
                "5. Identify findings linked to ransomware families\n"
                "6. Flag any zero-day or trending vulnerabilities\n\n"
                "For each match, record:\n"
                "- The threat actor(s) or campaign(s) that use this CVE\n"
                "- The ATT&CK technique(s) enabled by this vulnerability\n"
                "- Whether it's actively exploited (KEV) or high-probability (EPSS > 0.5)\n"
                "- The kill chain stage it enables (initial access, lateral movement, etc.)\n\n"
                "Output a JSON handoff:\n"
                "```json\n"
                '{"threat_matches": [{"cve": "...", "finding_ids": [...], "asset_count": N,\n'
                '  "threat_actors": [...], "attack_techniques": [...], "kev": true/false,\n'
                '  "epss": 0.X, "ransomware_linked": true/false, "kill_chain_stage": "..."}],\n'
                ' "total_threat_linked_findings": N, "total_threat_linked_assets": N}\n'
                "```"
            ),
            tools=[
                "get_exploit_findings", "query_findings", "get_finding_detail",
                "get_scan_summary", "list_scans",
            ],
            model_tier=ModelTier.DETERMINISTIC,
            output_type="threat_matches",
            max_steps=8,
        ),
        PipelineStage(
            name="exposure_mapping",
            description="Map threat matches to actual exposure based on asset context",
            system_prompt=(
                "You are an exposure mapping agent. You receive threat-matched findings.\n\n"
                "For each threat match, assess the ACTUAL exposure:\n"
                "1. Is the vulnerable asset internet-facing? (Check reachability context)\n"
                "2. Does the asset host privileged accounts? (Check inventory for admin users)\n"
                "3. Are there compensating controls? (Check security controls inventory)\n"
                "4. What's the asset criticality? (Business impact if compromised)\n"
                "5. Can this vulnerability enable lateral movement to higher-value targets?\n\n"
                "Score each threat-finding combination on a 1-10 exposure scale:\n"
                "- 9-10: Internet-facing + exploitable + no compensating control + high-value asset\n"
                "- 7-8: Exploitable + high-value asset OR internet-facing + any severity\n"
                "- 5-6: Internal + exploitable + standard asset\n"
                "- 3-4: Internal + theoretical exploit + compensating controls exist\n"
                "- 1-2: Air-gapped or fully mitigated by compensating controls\n\n"
                "Think step-by-step for each scoring decision.\n\n"
                "Output a JSON handoff:\n"
                "```json\n"
                '{"exposure_map": [{"cve": "...", "finding_ids": [...], "exposure_score": N,\n'
                '  "internet_facing": true/false, "privileged_access": true/false,\n'
                '  "compensating_controls": "...", "lateral_movement_risk": "high/medium/low",\n'
                '  "reasoning": "..."}],\n'
                ' "critical_exposures": [...], "mitigated_threats": [...]}\n'
                "```"
            ),
            tools=[
                "get_asset_profile", "get_internet_facing_risk", "get_top_risky_assets",
                "get_finding_detail", "query_assets",
            ],
            model_tier=ModelTier.REASONING,
            input_type="threat_matches",
            output_type="exposure_map",
            max_steps=12,
        ),
        PipelineStage(
            name="response_plan",
            description="Produce a threat-specific response plan with kill chain coverage",
            system_prompt=(
                "You are a threat response planner. You receive exposure-mapped threat data.\n\n"
                "Produce a threat-specific response plan organized by urgency:\n\n"
                "**Tier 1 — Immediate (24h)**: Exposure score 9-10\n"
                "- Specific patch/mitigation for each finding\n"
                "- Emergency change request details\n"
                "- Compensating control if patch isn't immediately available\n\n"
                "**Tier 2 — Urgent (72h)**: Exposure score 7-8\n"
                "- Patch deployment plan\n"
                "- Network segmentation recommendations\n"
                "- Detection rule suggestions (what to monitor)\n\n"
                "**Tier 3 — Planned (next maintenance window)**: Exposure score 5-6\n"
                "- Standard remediation in next patch cycle\n"
                "- Monitoring recommendations\n\n"
                "**Tier 4 — Monitor**: Exposure score 1-4\n"
                "- Track but no immediate action needed\n"
                "- Document compensating controls\n\n"
                "Also produce a kill chain coverage analysis:\n"
                "- Which ATT&CK stages are currently exposed?\n"
                "- Which stages would be covered after remediation?\n"
                "- Where are the remaining gaps?\n\n"
                "Format as a clear markdown report with tables and action items.\n"
                "Include specific finding IDs, asset IPs, and recommended owners."
            ),
            tools=[
                "get_finding_detail", "get_remediation_grouping", "get_owner_workload",
                "get_quick_wins",
            ],
            model_tier=ModelTier.REASONING,
            input_type="exposure_map",
            max_steps=10,
        ),
    ])


# ── Pipeline Registry ────────────────────────────────────────────────

PIPELINE_REGISTRY = {
    "vulnerability_triage": build_triage_pipeline,
    "patch_planning": build_patch_planning_pipeline,
    "auto_ticketing": build_ticket_pipeline,
    "exception_review": build_exception_review_pipeline,
    "compliance_posture": build_compliance_posture_pipeline,
    "threat_driven_prioritization": build_threat_driven_pipeline,
}


def get_available_pipelines() -> List[dict]:
    """List available pipeline templates."""
    return [
        {
            "id": pid,
            "name": factory().name,
            "stages": [
                {
                    "name": s.name,
                    "description": s.description,
                    "model_tier": s.model_tier.value,
                    "tools": s.tools,
                }
                for s in factory().stages
            ],
        }
        for pid, factory in PIPELINE_REGISTRY.items()
    ]
