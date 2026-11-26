---
name: publish-finding
description: >-
  Safely add, update, or validate a publicly cleared security finding on weehog.ai
  (brucesdad13.github.io). Use whenever modifying curated findings in index.html
  or preparing changes for deployment to GitHub Pages.
---

# Publish a Cleared Security Finding (`weehog.ai`)

Follow this procedure whenever adding or updating a finding in `index.html`. Never bypass the clearance gate in [AGENTS.md](../../../AGENTS.md).

## Step 1: Verify Public Disclosure Clearance

Confirm with the user (if not already explicitly stated in the request):
1. Vendor fix / security advisory is publicly released.
2. Canonical write-up or minimal reproducer is already public on GitHub (`https://github.com/brucesdad13/<repo>`).

Never inspect sibling/parent workspaces to gather details; rely strictly on user-supplied public metadata and the already-public GitHub repository.

## Step 2: Update the Curated Index in `index.html`

1. Locate `<!-- BEGIN CURATED FINDINGS -->` and `<!-- END CURATED FINDINGS -->` in [index.html](../../../index.html).
2. When adding the **first** cleared finding:
   - Remove `<div class="findings-empty" role="status">...</div>`.
   - Create `<ul class="finding-list">...</ul>` above `<template id="finding-entry-template">` (keep `<template>` intact for future reference).
3. Prepend newest findings at the top of `<ul class="finding-list">` using the exact pre-styled card markup:

```html
<li class="finding-item">
  <div class="finding-meta">
    <time datetime="YYYY-MM">YYYY-MM</time>
    <span class="badge">CVE-YYYY-NNNNN</span>
    <span class="subsystem">XNU / VFS</span>
  </div>
  <h3 class="finding-title">
    <a href="https://github.com/brucesdad13/REPO_NAME">Concise public advisory title ↗</a>
  </h3>
  <p class="finding-summary">One-to-two sentence post-patch summary of the root cause and affected macOS versions.</p>
</li>
```

## Step 3: Run the Guardrail Verifier

Run [verify_public_ready.py](./scripts/verify_public_ready.py) to check the file allowlist, leak patterns, static privacy constraints, JSON-LD / `rel="me"` entity graph, and unauthenticated `HTTP 200` reachability of every linked finding:

```sh
python3 .agents/skills/publish-finding/scripts/verify_public_ready.py --online
```

Do not commit or push if any check fails.
