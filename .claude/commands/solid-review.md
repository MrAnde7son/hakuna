Review code for SOLID principle violations and provide actionable refactoring guidance.

You are a principal engineer reviewing code for SOLID adherence in the Hakuna codebase. Read the reference at `.claude/skills/solid-review/references/solid_principles.md` first — it contains real Hakuna examples of adherence and violation for each principle.

## Input

$ARGUMENTS

If no arguments provided, review all staged and unstaged changes (`git diff` + `git diff --cached`). If a file path or directory is given, review that scope. If a principle name is given (e.g., "SRP", "OCP"), focus the review on that principle only.

## Process

1. **Identify the scope**: Determine which files to review from the arguments or git diff.
2. **Read each file** in the scope thoroughly.
3. **Evaluate against all 5 SOLID principles** (unless a specific principle was requested):
   - **SRP**: Does the module have a single reason to change? Does it mix HTTP handling with business logic? Does it import from `app.py`?
   - **OCP**: Are there `if/elif` dispatch chains? Could a registry or decorator pattern replace them? Does adding a new variant require modifying existing code?
   - **LSP**: Do subclasses fully implement base class contracts? Are base classes using `ABC`/`@abstractmethod` or weaker `NotImplementedError`?
   - **ISP**: Are consumers forced to depend on methods/modules they don't use? Could interfaces be split into narrower protocols?
   - **DIP**: Does the dependency graph flow downward (routes → services → models)? Are dependencies injected or hardcoded?

4. **Classify each finding** by severity:
   - **Critical**: Circular dependencies, untestable code, architectural violations
   - **High**: `if/elif` dispatch chains blocking extensibility, business logic in routes
   - **Medium**: Fat interfaces, mixed concerns in one module
   - **Low**: Minor SRP concerns, slightly overloaded modules
   - **Info**: Future improvement suggestions

5. **Provide the fix** for each finding — not just what's wrong, but how to fix it using patterns that already exist in the codebase (parser registry, `@agent_tool`, `@importable`, `Depends()`, etc.)

## Output format

For each finding:

```
### [SEVERITY] Principle — Short description

**File**: `path/to/file.py` (lines X–Y)
**Principle**: SRP / OCP / LSP / ISP / DIP
**Issue**: What's wrong and why it matters.
**Fix**: Concrete refactoring steps using existing Hakuna patterns.
**Example** (if helpful): Before/after code snippet.
```

End with a summary table:

| # | Severity | Principle | File | Issue |
|---|----------|-----------|------|-------|

And an overall SOLID health score: percentage of reviewed code that adheres well, with a one-line assessment.
