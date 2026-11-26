# Agent Maintenance & Disclosure Guardrails (`weehog.ai`)

This repository (`brucesdad13/brucesdad13.github.io`) serves `https://weehog.ai` via GitHub Pages. Everything committed to `main` is **immediately public**.

`weehog.ai` is a quiet, low-maintenance **curated routing layer**—never a primary archive, blog engine, or staging area for active vulnerability research. Every finding listed here routes directly to its canonical public repository or advisory on GitHub.

---

## 1. Hard Scope & Privacy Boundaries

1. **Zero Cross-Directory Scraping:** Never read, search, index, summarize, or copy files from parent or sibling directories outside this repository (such as private research workspaces, kernel panic logs, `.ips`/`.crash` dumps, local triage notes, embargoed vendor reports, or unredacted reproducers).
2. **Explicit Input Only:** Only add or update a finding when the user explicitly provides the public GitHub URL and confirms coordinated disclosure clearance. Never infer or auto-import unpublished work.
3. **No Raw Artifacts in Repo:** Never commit source code reproducers (`.c`, `.m`, `.cpp`, `.swift`, `.sh`), binary payloads, crash/panic logs, packet captures, screenshots of unreleased builds, or draft markdown notes to this repository.

---

## 2. Coordinated Disclosure Clearance Gate

Before adding or modifying any entry inside `<!-- BEGIN CURATED FINDINGS --> ... <!-- END CURATED FINDINGS -->` in `index.html`, verify **all four** conditions:

1. **Clearance Confirmed:** The user has explicitly confirmed that the vendor patch/advisory has shipped (or the coordinated disclosure window has formally concluded).
2. **Public Destination Live (`HTTP 200`):** Every linked repository or advisory URL (`https://github.com/brucesdad13/...`) resolves publicly with `HTTP 200` **without authentication** (confirming the target GitHub repository is not still set to Private).
3. **Redaction Cleanliness:** Entry metadata contains **zero** internal vendor ticket IDs (e.g., Apple Feedback IDs `FB...` or `OEI...`), non-public vendor emails, local filesystem paths, or unreleased build identifiers.
4. **Routing-Only Format:** Entries contain only the publication `YYYY-MM`, public CVE or advisory label, subsystem tag, concise title linked to GitHub, and a 1–2 sentence post-patch root-cause summary.

---

## 3. Architectural & Entity-Graph Invariants

- **Zero Build / Zero Tracking:** Keep `index.html` a standalone static HTML/CSS document. Never add build tooling, JavaScript frameworks, analytics scripts, tracking pixels, or external font/stylesheet CDNs.
- **Unified Entity Graph:** Always preserve:
  - `<script type="application/ld+json">` `schema.org/Person` block (`name: "Charles Stevenson"`, `url: "https://weehog.ai"`, `sameAs` including GitHub and LinkedIn).
  - `rel="me"` attributes on outbound links to `https://github.com/brucesdad13` and `https://www.linkedin.com/in/charliestevenson/`.
- **Repository File Allowlist:** Only the expected site and guardrail files belong in this repository (`index.html`, `favicon.svg`, `CNAME`, `.nojekyll`, `.gitignore`, `README.md`, `AGENTS.md`, and `.agents/skills/publish-finding/**`).

---

## 4. Mandatory Pre-Commit Check

Before staging, committing, or pushing any change, run the zero-dependency guardrail verifier:

```sh
python3 .agents/skills/publish-finding/scripts/verify_public_ready.py --online
```

*(Omit `--online` only when running inside an offline sandbox; run with `--online` before pushing so outbound GitHub URLs are verified as publicly reachable.)*
