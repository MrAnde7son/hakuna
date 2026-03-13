Tag a new release version and prepare for deployment.

User description: $ARGUMENTS

Steps:
1. Run `git log --oneline $(git describe --tags --abbrev=0 2>/dev/null || git rev-list --max-parents=0 HEAD)..HEAD` to see commits since last tag
2. Determine the next version from user arguments or by bumping the latest tag (semver: major.minor.patch)
3. Generate a changelog summary from the commit log
4. Create an annotated git tag: `git tag -a v<version> -m "<changelog summary>"`
5. Ask the user to confirm before pushing: `git push origin main --tags`
6. After push, remind about Render auto-deploy (if autoDeploy: true in render.yaml)
7. Report the release: version, tag, key changes included
