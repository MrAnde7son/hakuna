# @hakuna/ui — Deployment & Migration Guide

## Package Distribution Strategy

`@hakuna/ui` has no build step — it ships raw JSX + CSS, and each consuming project's bundler (Vite) handles transpilation. This keeps the design system simple and avoids maintaining a separate build pipeline.

### Recommended: Git-based dependency

Since all four repos live on the same machine and are private, the simplest approach is a local file reference. No registry needed.

```bash
# In each project's frontend/package.json:
npm install --save ../hakuna-ui

# This creates a symlink in node_modules/@hakuna/ui
# Vite resolves it automatically — no config changes needed.
```

The resulting `package.json` entry:

```json
{
  "dependencies": {
    "@hakuna/ui": "file:../../hakuna-ui"
  }
}
```

### Alternative: npm workspaces (monorepo)

If you consolidate repos under one parent folder:

```json
// /Users/itamar/Documents/Git/package.json
{
  "private": true,
  "workspaces": [
    "hakuna-ui",
    "hakuna/frontend",
    "hakuna-fundraiser/frontend",
    "hakuna-outbound/frontend"
  ]
}
```

Then `npm install` from the root hoists `@hakuna/ui` for all projects.

### Production: Private npm registry (later)

When the team grows or CI/CD needs hermetic builds:

```bash
# Publish to GitHub Packages or GCP Artifact Registry
npm publish --registry https://npm.pkg.github.com
# or
npm publish --registry https://us-npm.pkg.dev/YOUR_PROJECT/hakuna-npm/
```

---

## Local Development Setup

### Step 1: Link the package

```bash
cd ~/Documents/Git/hakuna-ui
npm link

# Then in each consuming project:
cd ~/Documents/Git/hakuna/frontend && npm link @hakuna/ui
cd ~/Documents/Git/hakuna-fundraiser/frontend && npm link @hakuna/ui
cd ~/Documents/Git/hakuna-outbound/frontend && npm link @hakuna/ui
```

Vite hot-reloads when you edit `hakuna-ui` files — changes appear instantly in whichever dev server is running.

### Step 2: Vite config (if needed)

Most cases work out of the box. If Vite doesn't resolve the symlink, add:

```js
// vite.config.js
export default defineConfig({
  resolve: {
    preserveSymlinks: true,
  },
  optimizeDeps: {
    // Ensure hakuna-ui isn't pre-bundled (so edits hot-reload)
    exclude: ['@hakuna/ui'],
  },
})
```

### Step 3: Verify

```bash
cd hakuna/frontend && npm run dev
# Open localhost:3000
# Edit hakuna-ui/tokens/colors.css → colors change live
# Edit hakuna-ui/components/Button.jsx → component updates live
```

---

## Migration Plan Per Project

### hakuna (main platform)

**Complexity: Medium** — large codebase, 2000+ line `shared/ui.jsx`, CSS vars already in use but unprefixed.

```
Phase 1: Tokens (low risk, immediate)
├── Import colors.css + base.css in frontend/index.html
├── Add backward-compat aliases (--bg: var(--hk-bg), etc.)
├── Verify dark mode still works
└── Time: ~30 min

Phase 2: Components (incremental, per-page)
├── Replace imports from shared/ui.jsx → @hakuna/ui one component at a time
├── Start with leaf components: Button, Badge, Pill, Spinner
├── Then composite: Card, StatCard, Table, Toast
├── Keep shared/ui.jsx as a shim that re-exports from @hakuna/ui
│   (so existing imports don't break)
└── Time: ~2-4 hours across multiple PRs

Phase 3: Cleanup
├── Remove old CSS variable definitions from index.html
├── Delete shared/ui.jsx once all imports migrated
├── Replace --bg/--text/--primary with --hk-bg/--hk-text/--hk-primary
└── Time: ~1 hour
```

**Shim pattern** (keeps existing code working during migration):

```jsx
// frontend/src/components/shared/ui.jsx (during migration)
export { Button, Card, StatCard, SeverityBadge, StatusBadge } from '@hakuna/ui'
export { Table, Pill, ScoreBar, PageHeader, EmptyState } from '@hakuna/ui'
export { Toast, Spinner, FilterBar } from '@hakuna/ui'
// ... keep any app-specific components that aren't in @hakuna/ui
```

### hakuna-fundraiser

**Complexity: Low** — Tailwind project, straightforward preset swap.

```
1. npm install ../../hakuna-ui (or npm link)
2. Replace tailwind.config.js colors/fonts/shadows → presets: [hakunaPreset]
3. Import tokens CSS in src/main.jsx
4. Replace local StatusBadge → import { StatusBadge } from '@hakuna/ui'
5. Replace local StatCard, ScoreBar, etc.
6. Delete local component files as they're replaced
Time: ~1 hour
```

### hakuna-outbound

**Complexity: Low** — Same as fundraiser, Tailwind + React.

```
1. npm install ../../hakuna-ui
2. Replace tailwind.config.js → presets: [hakunaPreset]
3. Import token CSS
4. Replace ScoreBar, StatCard, etc.
5. Verify Zustand/TanStack integrations unaffected (they will be — UI layer is separate)
Time: ~1 hour
```

### hakuna-signal

**Complexity: Minimal** — Static HTML, no build step.

```
1. Add <link rel="stylesheet" href="../hakuna-ui/tokens/colors.css"> to dashboard.html
2. Find-replace CSS variables:
   --bg       → --hk-bg
   --text     → --hk-text
   --accent   → --hk-primary
   --border   → --hk-border
   --surface  → --hk-surface
3. Dark mode toggle already uses [data-theme="dark"] → works automatically
Time: ~20 min
```

---

## Production Deployment (GCP)

All three React projects deploy the same way: `npm run build` → `dist/` → GCS bucket → Cloud CDN.

### Current flow (from deploy.sh):

```
npm ci → npm run build → gsutil rsync dist/ gs://bucket/ → Cloud CDN invalidation
```

### With @hakuna/ui, only one thing changes:

The `npm ci` step must resolve `@hakuna/ui`. Three approaches:

#### Option A: Copy hakuna-ui into the build context (simplest)

```bash
# deploy.sh (modified)
# Copy hakuna-ui alongside the project before build
cp -r ~/Documents/Git/hakuna-ui /tmp/build-context/hakuna-ui

cd /tmp/build-context/hakuna/frontend
# package.json has: "@hakuna/ui": "file:../../hakuna-ui"
npm ci
npm run build
gsutil -m rsync -r -d dist/ gs://$BUCKET/
```

#### Option B: Docker multi-stage (cleaner)

```dockerfile
# Dockerfile.frontend
FROM node:20-slim AS build

# Copy design system first
COPY hakuna-ui/ /app/hakuna-ui/

# Copy project
COPY hakuna/frontend/ /app/frontend/
WORKDIR /app/frontend

RUN npm ci && npm run build

# Serve
FROM nginx:alpine
COPY --from=build /app/frontend/dist /usr/share/nginx/html
```

#### Option C: Private npm registry (scalable)

```bash
# CI step 1: Publish @hakuna/ui
cd hakuna-ui
npm publish --registry https://us-npm.pkg.dev/$PROJECT_ID/hakuna-npm/

# CI step 2: Build each frontend
cd hakuna/frontend
echo "@hakuna:registry=https://us-npm.pkg.dev/$PROJECT_ID/hakuna-npm/" > .npmrc
npm ci && npm run build
```

### Recommended path:

Start with **Option A** (copy into build context) — it works today with zero infrastructure changes. Move to **Option C** (Artifact Registry) when you set up proper CI/CD or onboard more developers.

### GCS + CDN cache strategy (unchanged):

```bash
# Hashed assets: immutable, long cache
gsutil -m rsync -r -d \
  -h "Cache-Control:public, max-age=31536000, immutable" \
  dist/assets/ gs://$BUCKET/assets/

# index.html: no cache (always fresh)
gsutil -h "Cache-Control:no-cache, no-store" \
  cp dist/index.html gs://$BUCKET/

# Invalidate CDN edge cache
gcloud compute url-maps invalidate-cdn-cache $URL_MAP --path="/*"
```

This works exactly the same with `@hakuna/ui` — Vite tree-shakes and bundles everything into hashed chunks, so the design system components end up inside `dist/assets/*.js` just like any other dependency.

---

## CI/CD Considerations

### When @hakuna/ui changes, which projects need a rebuild?

All of them, potentially. But in practice:

- **Token changes** (colors, fonts, radii) → rebuild everything
- **Component changes** → rebuild only projects that import that component
- **New component** → no rebuilds needed until someone imports it

### Suggested GitHub Actions workflow:

```yaml
# .github/workflows/ui-changed.yml
on:
  push:
    paths: ['hakuna-ui/**']

jobs:
  rebuild:
    strategy:
      matrix:
        project: [hakuna, hakuna-fundraiser, hakuna-outbound]
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
        working-directory: ${{ matrix.project }}/frontend
      - run: npm run build
        working-directory: ${{ matrix.project }}/frontend
      - run: gsutil -m rsync -r -d dist/ gs://${{ matrix.project }}-frontend/
        working-directory: ${{ matrix.project }}/frontend
```

---

## Quick Reference

| Project | Install | Config Change | Migration Time |
|---------|---------|---------------|----------------|
| hakuna | `npm link @hakuna/ui` | Add CSS imports + shim ui.jsx | 2-4 hours (incremental) |
| hakuna-fundraiser | `npm link @hakuna/ui` | Swap tailwind.config.js preset | ~1 hour |
| hakuna-outbound | `npm link @hakuna/ui` | Swap tailwind.config.js preset | ~1 hour |
| hakuna-signal | `<link>` tag | Find-replace CSS vars | ~20 min |
| **Production deploy** | Copy into build context | None (Vite handles it) | 0 changes |
