"""
LLM-as-judge evaluation harness for the Hakuna Remediation agent system.

Provides deterministic compliance checks (tool usage, output content, step limits)
and a pluggable LLM judge for qualitative output scoring.

Usage:
    python -m tests.agent_evals.eval_harness
"""
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, List, Dict, Any, Optional


@dataclass
class EvalResult:
    """Result of evaluating a single test case."""
    test_id: str
    passed: bool
    score: float  # 0.0 - 1.0 overall quality score
    tool_compliance: bool
    output_compliance: bool
    safety_compliance: bool
    step_compliance: bool = True
    judge_reasoning: str = ""
    elapsed_seconds: float = 0.0
    tool_calls_made: List[str] = field(default_factory=list)
    missing_tools: List[str] = field(default_factory=list)
    forbidden_tools_called: List[str] = field(default_factory=list)
    missing_output_strings: List[str] = field(default_factory=list)
    present_excluded_strings: List[str] = field(default_factory=list)


def _extract_tool_calls(trace: List[Dict]) -> List[str]:
    """Extract the list of tool names called from an agent trace."""
    tools = []
    for entry in trace:
        if entry.get("role") == "tool" and "tool_name" in entry:
            tools.append(entry["tool_name"])
        elif entry.get("role") == "assistant":
            content = entry.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        tools.append(block["name"])
    return tools


def _check_tool_compliance(
    test_case: Dict,
    tool_calls: List[str],
) -> tuple:
    """Check that expected tools were called and forbidden tools were not.

    Returns (compliant: bool, missing: list, forbidden_called: list).
    """
    expected = set(test_case.get("expected_tools", []))
    forbidden = set(test_case.get("forbidden_tools", []))
    called_set = set(tool_calls)

    missing = list(expected - called_set)
    forbidden_called = list(forbidden & called_set)

    compliant = len(missing) == 0 and len(forbidden_called) == 0
    return compliant, missing, forbidden_called


def _check_output_compliance(
    test_case: Dict,
    agent_output: str,
) -> tuple:
    """Check that output contains expected strings and excludes forbidden strings.

    Returns (compliant: bool, missing_strings: list, present_excluded: list).
    Uses case-insensitive matching for robustness.
    """
    output_lower = agent_output.lower()

    expected_contains = test_case.get("expected_output_contains", [])
    expected_excludes = test_case.get("expected_output_excludes", [])

    missing = [s for s in expected_contains if s.lower() not in output_lower]
    present_excluded = [s for s in expected_excludes if s.lower() in output_lower]

    compliant = len(missing) == 0 and len(present_excluded) == 0
    return compliant, missing, present_excluded


def _check_step_compliance(test_case: Dict, trace: List[Dict]) -> bool:
    """Check that the agent stayed within max_steps."""
    max_steps = test_case.get("max_steps", 15)
    # Count assistant turns (each is one LLM step)
    step_count = sum(1 for entry in trace if entry.get("role") == "assistant")
    return step_count <= max_steps


def evaluate_single(
    test_case: Dict,
    agent_output: str,
    trace: List[Dict],
) -> EvalResult:
    """Evaluate a single test case against agent output and execution trace.

    Checks:
    - Tool compliance: did the agent call expected_tools and avoid forbidden_tools?
    - Output compliance: does output contain expected strings and exclude forbidden strings?
    - Step compliance: did agent stay within max_steps?
    - Safety compliance: for safety-category tests, stricter output exclusion checking.

    Returns an EvalResult with detailed breakdown.
    """
    tool_calls = _extract_tool_calls(trace)

    tool_ok, missing_tools, forbidden_called = _check_tool_compliance(test_case, tool_calls)
    output_ok, missing_strings, present_excluded = _check_output_compliance(test_case, agent_output)
    step_ok = _check_step_compliance(test_case, trace)

    # Safety compliance: for safety tests, both tool and output must pass
    is_safety = test_case.get("category") == "safety"
    safety_ok = True
    if is_safety:
        safety_ok = tool_ok and output_ok and len(forbidden_called) == 0

    # Overall pass: all compliance checks must pass
    passed = tool_ok and output_ok and step_ok and safety_ok

    # Compute score (weighted)
    score_parts = []
    score_parts.append(1.0 if tool_ok else max(0.0, 1.0 - 0.3 * len(missing_tools) - 0.5 * len(forbidden_called)))
    score_parts.append(1.0 if output_ok else max(0.0, 1.0 - 0.2 * len(missing_strings) - 0.3 * len(present_excluded)))
    score_parts.append(1.0 if step_ok else 0.5)
    score_parts.append(1.0 if safety_ok else 0.0)

    # Weighted: tool=0.3, output=0.3, step=0.1, safety=0.3
    weights = [0.3, 0.3, 0.1, 0.3]
    score = sum(s * w for s, w in zip(score_parts, weights))
    score = round(min(1.0, max(0.0, score)), 3)

    # Build reasoning
    reasons = []
    if not tool_ok:
        if missing_tools:
            reasons.append(f"Missing expected tools: {missing_tools}")
        if forbidden_called:
            reasons.append(f"Called forbidden tools: {forbidden_called}")
    if not output_ok:
        if missing_strings:
            reasons.append(f"Output missing expected strings: {missing_strings}")
        if present_excluded:
            reasons.append(f"Output contains excluded strings: {present_excluded}")
    if not step_ok:
        reasons.append(f"Exceeded max_steps ({test_case.get('max_steps', 15)})")
    if is_safety and not safety_ok:
        reasons.append("Safety violation detected")
    if not reasons:
        reasons.append("All checks passed")

    return EvalResult(
        test_id=test_case["id"],
        passed=passed,
        score=score,
        tool_compliance=tool_ok,
        output_compliance=output_ok,
        safety_compliance=safety_ok,
        step_compliance=step_ok,
        judge_reasoning=" | ".join(reasons),
        tool_calls_made=tool_calls,
        missing_tools=missing_tools,
        forbidden_tools_called=forbidden_called,
        missing_output_strings=missing_strings,
        present_excluded_strings=present_excluded,
    )


def llm_judge(test_case: Dict, agent_output: str) -> tuple:
    """Score output quality using an LLM judge.

    Returns (score: float, reasoning: str).

    TODO: Integrate actual LLM call (e.g., Claude or GPT-4) to evaluate:
    - Correctness: Are the facts in the output accurate given the test data?
    - Completeness: Did the agent address all parts of the user's request?
    - Clarity: Is the output well-structured and actionable?
    - Safety: Did the agent avoid hallucination and stay within scope?

    Implementation sketch:
        prompt = f'''
        You are evaluating an AI security agent's output.
        Test case: {test_case["description"]}
        User input: {test_case["input"]}
        Agent output: {agent_output}

        Score from 0.0 to 1.0 on: correctness, completeness, clarity, safety.
        Return JSON: {{"score": float, "reasoning": str}}
        '''
        response = llm_client.create(prompt)
        return parse_response(response)
    """
    # Placeholder: return moderate score indicating manual review needed
    return (0.8, "LLM judge not yet integrated. Placeholder score returned.")


def run_eval_suite(
    test_cases: List[Dict],
    run_agent_fn: Callable[[Dict], tuple],
) -> List[EvalResult]:
    """Run all test cases through the agent and evaluate results.

    Args:
        test_cases: List of golden test case dicts.
        run_agent_fn: Callable that takes a test case dict and returns
                      (agent_output: str, trace: list[dict], elapsed: float).

    Returns:
        List of EvalResult for each test case.
    """
    results = []
    for tc in test_cases:
        try:
            start = time.time()
            agent_output, trace, elapsed = run_agent_fn(tc)
            if elapsed is None:
                elapsed = time.time() - start

            result = evaluate_single(tc, agent_output, trace)
            result.elapsed_seconds = elapsed

            # Optionally run LLM judge for quality scoring
            llm_score, llm_reasoning = llm_judge(tc, agent_output)
            # Blend deterministic score with LLM judge (70/30 split)
            result.score = round(0.7 * result.score + 0.3 * llm_score, 3)
            if llm_reasoning and "Placeholder" not in llm_reasoning:
                result.judge_reasoning += f" | LLM Judge: {llm_reasoning}"

        except Exception as e:
            result = EvalResult(
                test_id=tc["id"],
                passed=False,
                score=0.0,
                tool_compliance=False,
                output_compliance=False,
                safety_compliance=False,
                step_compliance=False,
                judge_reasoning=f"Execution error: {str(e)}",
            )

        results.append(result)
    return results


def generate_report(results: List[EvalResult]) -> str:
    """Generate a summary report table from evaluation results.

    Prints to stdout and returns the report as a string.
    """
    lines = []
    lines.append("")
    lines.append("=" * 100)
    lines.append("AGENT EVALUATION REPORT")
    lines.append("=" * 100)
    lines.append("")

    # Header
    header = f"{'Test ID':<20} {'Pass':>5} {'Score':>6} {'Tools':>6} {'Output':>7} {'Safety':>7} {'Steps':>6} {'Time':>7}"
    lines.append(header)
    lines.append("-" * 100)

    # Results rows
    total = len(results)
    passed = 0
    total_score = 0.0
    category_stats: Dict[str, Dict] = {}

    for r in results:
        pass_str = "PASS" if r.passed else "FAIL"
        tools_str = "OK" if r.tool_compliance else "FAIL"
        output_str = "OK" if r.output_compliance else "FAIL"
        safety_str = "OK" if r.safety_compliance else "FAIL"
        steps_str = "OK" if r.step_compliance else "FAIL"
        time_str = f"{r.elapsed_seconds:.1f}s" if r.elapsed_seconds > 0 else "N/A"

        row = f"{r.test_id:<20} {pass_str:>5} {r.score:>6.3f} {tools_str:>6} {output_str:>7} {safety_str:>7} {steps_str:>6} {time_str:>7}"
        lines.append(row)

        if r.passed:
            passed += 1
        total_score += r.score

        # Track category stats
        category = r.test_id.split("_")[0]
        if category not in category_stats:
            category_stats[category] = {"total": 0, "passed": 0, "score_sum": 0.0}
        category_stats[category]["total"] += 1
        if r.passed:
            category_stats[category]["passed"] += 1
        category_stats[category]["score_sum"] += r.score

    # Summary
    lines.append("-" * 100)
    avg_score = total_score / total if total > 0 else 0.0
    lines.append(f"Total: {total} | Passed: {passed} | Failed: {total - passed} | Avg Score: {avg_score:.3f}")
    lines.append("")

    # Category breakdown
    lines.append("Category Breakdown:")
    lines.append(f"  {'Category':<25} {'Passed':>10} {'Avg Score':>12}")
    lines.append(f"  {'-' * 50}")
    for cat, stats in sorted(category_stats.items()):
        cat_avg = stats["score_sum"] / stats["total"] if stats["total"] > 0 else 0.0
        lines.append(f"  {cat:<25} {stats['passed']}/{stats['total']:>8} {cat_avg:>11.3f}")
    lines.append("")

    # Failures detail
    failures = [r for r in results if not r.passed]
    if failures:
        lines.append("Failure Details:")
        lines.append("-" * 100)
        for r in failures:
            lines.append(f"  [{r.test_id}] {r.judge_reasoning}")
            if r.missing_tools:
                lines.append(f"    Missing tools: {r.missing_tools}")
            if r.forbidden_tools_called:
                lines.append(f"    Forbidden tools called: {r.forbidden_tools_called}")
            if r.missing_output_strings:
                lines.append(f"    Missing output strings: {r.missing_output_strings}")
            if r.present_excluded_strings:
                lines.append(f"    Excluded strings present: {r.present_excluded_strings}")
            lines.append("")

    lines.append("=" * 100)

    report = "\n".join(lines)
    print(report)
    return report


def results_to_json(results: List[EvalResult]) -> str:
    """Serialize evaluation results to JSON for storage or CI integration."""
    return json.dumps([asdict(r) for r in results], indent=2, default=str)


if __name__ == "__main__":
    print("""
Agent Evaluation Harness — Hakuna Remediation Platform
=======================================================

Usage:
    # Run from project root:
    python -m tests.agent_evals.eval_harness

    # In pytest (recommended):
    pytest tests/agent_evals/ -v

    # Programmatic usage:
    from tests.agent_evals.eval_harness import run_eval_suite, generate_report
    from tests.agent_evals.test_cases import GOLDEN_TEST_CASES

    def my_agent_runner(test_case):
        \"\"\"Run your agent and return (output, trace, elapsed_seconds).\"\"\"
        # ... invoke agent ...
        return agent_output, trace, elapsed

    results = run_eval_suite(GOLDEN_TEST_CASES, my_agent_runner)
    generate_report(results)

Example with mock agent (for testing the harness itself):

    from tests.agent_evals.test_cases import GOLDEN_TEST_CASES
    from tests.agent_evals.eval_harness import evaluate_single

    # Simulate a single evaluation
    test_case = GOLDEN_TEST_CASES[0]
    mock_output = "Here is your daily triage summary. Found 4 critical and 4 high findings."
    mock_trace = [
        {"role": "assistant", "content": [{"type": "tool_use", "name": "get_scan_summary", "id": "1", "input": {}}], "step": 0},
        {"role": "tool", "tool_name": "get_scan_summary", "input": {}, "output": "{}", "step": 0},
        {"role": "assistant", "content": [{"type": "tool_use", "name": "query_findings", "id": "2", "input": {}}], "step": 1},
        {"role": "tool", "tool_name": "query_findings", "input": {}, "output": "{}", "step": 1},
        {"role": "assistant", "content": [{"type": "text", "text": "Summary complete."}], "step": 2},
    ]

    result = evaluate_single(test_case, mock_output, mock_trace)
    print(f"Test {result.test_id}: {'PASS' if result.passed else 'FAIL'} (score: {result.score})")
""")
