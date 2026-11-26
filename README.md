# weehog.ai 🍏🦔

Minimal static front door for [`https://weehog.ai`](https://weehog.ai), served via GitHub Pages from `brucesdad13/brucesdad13.github.io`.

- **Scope:** Curated routing index for macOS kernel memory safety, filesystem edge cases, and low-level internals research by Charles Stevenson (`@brucesdad13`).
- **Architecture:** Single-file `index.html` + `favicon.svg` — zero build steps, zero frameworks, zero external requests or analytics.
- **Canonical Source:** Every listed finding routes directly to its public repository or advisory on [GitHub](https://github.com/brucesdad13).
- **Maintenance Guardrails:** See [`AGENTS.md`](./AGENTS.md) and run `python3 .agents/skills/publish-finding/scripts/verify_public_ready.py --online` before committing updates.
