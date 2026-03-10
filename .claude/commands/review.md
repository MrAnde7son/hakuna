Review recent code changes for bugs, security issues, and improvements.

Steps:
1. Run `git diff` to see all unstaged changes
2. Run `git diff --cached` to see staged changes
3. For each changed file, review for:
   - **Security**: SQL injection, XSS, command injection, path traversal, exposed secrets
   - **Bugs**: null/undefined access, off-by-one errors, missing error handling at boundaries
   - **API consistency**: response format matches frontend expectations
   - **Data integrity**: proper DB session handling, missing commits/rollbacks
4. Present findings organized by severity (critical → minor)
5. Offer to fix any issues found
