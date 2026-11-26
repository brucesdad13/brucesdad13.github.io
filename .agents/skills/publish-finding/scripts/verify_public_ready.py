#!/usr/bin/env python3
"""Pre-publish disclosure & static-site guardrail verifier for weehog.ai."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parents[4]

ALLOWED_FILES = {
    "index.html",
    "favicon.svg",
    "CNAME",
    ".nojekyll",
    ".gitignore",
    "README.md",
    "AGENTS.md",
    ".agents/skills/publish-finding/SKILL.md",
    ".agents/skills/publish-finding/scripts/verify_public_ready.py",
}

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Apple Feedback Assistant ID", re.compile(r"\bFB\d{6,}\b")),
    ("Vendor tracking ID (OEI)", re.compile(r"\bOEI[-_ ]?\d{4,}\b")),
    ("Embargo / confidential marker", re.compile(r"\b(EMBARGOED|DO NOT DISTRIBUTE|CONFIDENTIAL|UNREDACTED)\b", re.I)),
    ("macOS kernel panic dump signature", re.compile(r"(panicString|Kernel Extensions in backtrace|Debugger message:\s*panic)")),
    ("Local workstation path leak", re.compile(r"(/Users/[A-Za-z0-9._-]+|file:///Users/)")),
    ("Private key or token header", re.compile(r"(BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
]

ALLOWED_FINDING_HOSTS = {
    "github.com",
    "www.github.com",
    "support.apple.com",
    "www.cve.org",
    "cve.org",
    "nvd.nist.gov",
}

EXPECTED_SAME_AS = {
    "https://github.com/brucesdad13",
    "https://www.linkedin.com/in/charliestevenson/",
}


class IndexInspector(HTMLParser):
    """Inspects index.html for external resources, entity links, JSON-LD, and findings."""

    def __init__(self) -> None:
        super().__init__()
        self.external_resources: list[str] = []
        self.rel_me_hrefs: set[str] = set()
        self.anchor_rel_me_hrefs: set[str] = set()
        self.json_ld_blocks: list[str] = []
        self.in_json_ld = False
        self._json_buf: list[str] = []
        self.template_depth = 0
        self.in_findings_section = False
        self.finding_links: list[str] = []

    def handle_comment(self, data: str) -> None:
        stripped = data.strip()
        if stripped == "BEGIN CURATED FINDINGS":
            self.in_findings_section = True
        elif stripped == "END CURATED FINDINGS":
            self.in_findings_section = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag == "template":
            self.template_depth += 1

        if tag == "script":
            src = attr_map.get("src", "").strip()
            stype = attr_map.get("type", "").strip().lower()
            if src:
                self.external_resources.append(f"<script src='{src}'>")
            elif stype == "application/ld+json":
                self.in_json_ld = True
                self._json_buf = []
            else:
                self.external_resources.append("<script> (inline executable script disallowed)")

        if tag in {"img", "iframe", "audio", "video", "source"}:
            src = attr_map.get("src", "").strip()
            if src.startswith(("http://", "https://", "//")):
                self.external_resources.append(f"<{tag} src='{src}'>")

        if tag == "link":
            rel_tokens = set(attr_map.get("rel", "").lower().split())
            href = attr_map.get("href", "").strip()
            if "me" in rel_tokens and href:
                self.rel_me_hrefs.add(href)
            if rel_tokens & {"stylesheet", "preconnect", "dns-prefetch", "preload"}:
                if href.startswith(("http://", "https://", "//")):
                    self.external_resources.append(f"<link rel='{' '.join(sorted(rel_tokens))}' href='{href}'>")

        if tag == "a":
            href = attr_map.get("href", "").strip()
            rel_tokens = set(attr_map.get("rel", "").lower().split())
            if "me" in rel_tokens and href:
                self.anchor_rel_me_hrefs.add(href)
            if self.in_findings_section and self.template_depth == 0 and href:
                self.finding_links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "template" and self.template_depth > 0:
            self.template_depth -= 1
        elif tag == "script" and self.in_json_ld:
            self.in_json_ld = False
            self.json_ld_blocks.append("".join(self._json_buf))

    def handle_data(self, data: str) -> None:
        if self.in_json_ld:
            self._json_buf.append(data)


def check_file_allowlist(errors: list[str]) -> list[Path]:
    present: list[Path] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        rel_parts = path.relative_to(REPO_ROOT).parts
        if rel_parts and rel_parts[0] == ".git":
            continue
        if path.is_dir():
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        present.append(path)
        if rel not in ALLOWED_FILES:
            errors.append(
                f"Unallowlisted file in repository: '{rel}'. "
                "Never stage notes, reproducers, or crash artifacts in brucesdad13.github.io."
            )
    for required in ("index.html", "favicon.svg", "CNAME", ".nojekyll", "AGENTS.md"):
        if not (REPO_ROOT / required).exists():
            errors.append(f"Missing required repository file: '{required}'.")
    return present


def check_sensitive_patterns(files: list[Path], errors: list[str]) -> None:
    self_path = Path(__file__).resolve()
    for path in files:
        if path.resolve() == self_path:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        if rel == "AGENTS.md":
            # AGENTS.md documents policy rules generically; still scan for concrete IDs/paths.
            patterns = [p for p in SENSITIVE_PATTERNS if "marker" not in p[0].lower() and "panic" not in p[0].lower()]
        else:
            patterns = SENSITIVE_PATTERNS
        for label, regex in patterns:
            match = regex.search(text)
            if match:
                errors.append(f"Sensitive pattern ({label}) matched in '{rel}': '{match.group(0)}'")


def check_cname_and_svg(errors: list[str]) -> None:
    cname_path = REPO_ROOT / "CNAME"
    if cname_path.exists():
        cname = cname_path.read_text(encoding="utf-8").strip()
        if cname != "weehog.ai":
            errors.append(f"CNAME must be 'weehog.ai', found '{cname}'.")

    svg_path = REPO_ROOT / "favicon.svg"
    if svg_path.exists():
        try:
            root = ET.fromstring(svg_path.read_text(encoding="utf-8"))
            if not root.tag.endswith("svg"):
                errors.append("favicon.svg root element is not <svg>.")
        except ET.ParseError as exc:
            errors.append(f"favicon.svg is not well-formed XML: {exc}")


def check_index_html(online: bool, errors: list[str]) -> tuple[int, int]:
    index_path = REPO_ROOT / "index.html"
    if not index_path.exists():
        return (0, 0)
    html = index_path.read_text(encoding="utf-8")

    if "<!-- BEGIN CURATED FINDINGS -->" not in html or "<!-- END CURATED FINDINGS -->" not in html:
        errors.append("index.html is missing BEGIN/END CURATED FINDINGS guardrail markers.")

    if re.search(r"@import\s+url\(", html, re.I):
        errors.append("index.html contains external CSS @import.")

    inspector = IndexInspector()
    inspector.feed(html)

    for ext in inspector.external_resources:
        errors.append(f"Disallowed script or external network resource in index.html: {ext}")

    missing_me = EXPECTED_SAME_AS - inspector.anchor_rel_me_hrefs
    if missing_me:
        errors.append(f"Missing visible <a rel='me'> entity link(s): {sorted(missing_me)}")

    if len(inspector.json_ld_blocks) != 1:
        errors.append(f"Expected exactly 1 JSON-LD block in index.html, found {len(inspector.json_ld_blocks)}.")
    else:
        try:
            ld = json.loads(inspector.json_ld_blocks[0])
            if ld.get("@type") != "Person":
                errors.append(f"JSON-LD @type must be 'Person', found {ld.get('@type')!r}.")
            if ld.get("name") != "Charles Stevenson":
                errors.append(f"JSON-LD name must be 'Charles Stevenson', found {ld.get('name')!r}.")
            if ld.get("url") != "https://weehog.ai":
                errors.append(f"JSON-LD url must be 'https://weehog.ai', found {ld.get('url')!r}.")
            same_as = set(ld.get("sameAs") or [])
            if not EXPECTED_SAME_AS.issubset(same_as):
                errors.append(f"JSON-LD sameAs missing required profile URLs: {sorted(EXPECTED_SAME_AS - same_as)}")
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON-LD in index.html: {exc}")

    checked_online = 0
    for href in inspector.finding_links:
        if not href.startswith("https://"):
            errors.append(f"Finding link must use https://: '{href}'")
            continue
        host = href.split("/")[2].lower()
        if host not in ALLOWED_FINDING_HOSTS:
            errors.append(
                f"Finding link '{href}' points to non-allowlisted host '{host}'. "
                "Findings must route to GitHub or official advisory records."
            )
            continue
        if online:
            req = urllib.request.Request(
                href,
                method="GET",
                headers={"User-Agent": "weehog-public-readiness-check/1.0"},
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status >= 400:
                        errors.append(f"Finding URL '{href}' returned HTTP {resp.status} (must be public HTTP 200).")
                    checked_online += 1
            except urllib.error.HTTPError as exc:
                errors.append(
                    f"Finding URL '{href}' returned HTTP {exc.code} — target repo/advisory may still be private!"
                )
            except urllib.error.URLError as exc:
                errors.append(f"Could not verify finding URL '{href}' online: {exc.reason}")

    return (len(inspector.finding_links), checked_online)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--online",
        action="store_true",
        help="Verify unauthenticated HTTP 200 reachability of outbound finding URLs.",
    )
    args = parser.parse_args()

    errors: list[str] = []
    files = check_file_allowlist(errors)
    check_sensitive_patterns(files, errors)
    check_cname_and_svg(errors)
    total_links, checked_online = check_index_html(args.online, errors)

    if errors:
        print("FAIL: weehog.ai public-disclosure guardrail check failed:\n", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    mode = f"online ({checked_online}/{total_links} finding URLs verified HTTP 200)" if args.online else "offline"
    print(
        f"OK: weehog.ai verified public-ready [{mode}] — "
        f"{len(files)} allowlisted files, JSON-LD + rel=me intact, zero external trackers or leaks."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
