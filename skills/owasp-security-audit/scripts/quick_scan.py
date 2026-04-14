#!/usr/bin/env python3
"""Fast regex pre-scan for obvious OWASP patterns.

This is a *priming* tool for the owasp-security-audit skill. It flags
candidate issues with high precision on a narrow set of patterns so
the auditor can focus attention. It does not replace reading the code.

Design rules:
- Only patterns with low false-positive rate. If a pattern is ambiguous
  it lives in the reference files, not here.
- Every hit cites an OWASP category code so the reviewer can jump to
  the relevant reference.
- Output is JSON to stdout. Human-readable summary to stderr.
- Single-file dependency-free (stdlib only) so it runs anywhere Python
  3 is installed.

Usage:
    python quick_scan.py <path>
    python quick_scan.py <path> --format text
    python quick_scan.py <path> --include '*.py,*.js,*.yaml'
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


# Files larger than this are skipped to keep scans fast. Minified
# bundles, lockfiles, and vendor trees are the usual offenders.
MAX_FILE_BYTES = 500_000

DEFAULT_INCLUDES = (
    "*.py", "*.js", "*.jsx", "*.ts", "*.tsx",
    "*.yaml", "*.yml", "*.html", "*.htm",
    "*.rb", "*.go", "*.java", "*.kt", "*.swift", "*.php",
    "Dockerfile", "dockerfile",
)

# Directories we never descend into.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv",
    "__pycache__", "dist", "build", "target", ".next",
    "vendor", "bower_components",
}


@dataclass
class Finding:
    file: str
    line: int
    standard: str       # e.g. "Top10:A02"
    pattern: str        # short id like "hardcoded-openai-key"
    excerpt: str        # the matched line, trimmed
    note: str           # one-line human explanation


# Patterns. Each is (id, owasp_code, compiled_regex, note).
# Regexes must be anchored or strict enough to keep false positives low.
PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    # --- A02 Cryptographic Failures ---
    ("hardcoded-openai-key", "Top10:A02",
     re.compile(r"sk-[A-Za-z0-9]{20,}"),
     "looks like an OpenAI-style secret key in source"),
    ("hardcoded-aws-access-key", "Top10:A02",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS access key ID present in source"),
    ("hardcoded-aws-secret", "Top10:A02",
     re.compile(r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{30,}['\"]",
                re.IGNORECASE),
     "AWS secret access key assigned inline"),
    ("hardcoded-jwt-secret", "Top10:A02",
     re.compile(r"(?:jwt_secret|JWT_SECRET)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
     "JWT secret assigned inline — should come from env/secret store"),
    ("md5-or-sha1-password", "Top10:A02",
     re.compile(r"(?:md5|sha1)\s*\(\s*.*password", re.IGNORECASE),
     "password hashed with md5/sha1 — use bcrypt/argon2"),
    ("aes-ecb", "Top10:A02",
     re.compile(r"AES\.new\([^)]*MODE_ECB|AES/ECB/|kCCOptionECBMode"),
     "AES ECB mode — use an authenticated mode (GCM/CCM)"),
    ("tls-verify-disabled", "Top10:A02",
     re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false",
                re.IGNORECASE),
     "TLS certificate verification disabled"),

    # --- A03 Injection ---
    ("shell-true", "Top10:A03",
     re.compile(r"\bsubprocess\.(?:run|Popen|call)\([^)]*shell\s*=\s*True"),
     "subprocess with shell=True — pass argv list instead"),
    ("os-system", "Top10:A03",
     re.compile(r"\bos\.system\s*\("),
     "os.system builds a shell string — prefer subprocess with argv"),
    ("sql-fstring", "Top10:A03",
     re.compile(r"(?:execute|query)\s*\(\s*[fF]['\"][^'\"]*\{[^}]+\}"),
     "SQL built from f-string — use parameterized query"),
    ("sql-concat", "Top10:A03",
     re.compile(r"(?:execute|query)\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+"),
     "SQL built from string concatenation — use parameterized query"),
    ("innerhtml-assignment", "Top10:A03",
     re.compile(r"\.innerHTML\s*=\s*(?!['\"](?:\s*)['\"])[A-Za-z_$`]"),
     "innerHTML assigned a non-empty value — use textContent or sanitize"),
    ("eval-call", "Top10:A03",
     re.compile(r"(?<![A-Za-z_])eval\s*\("),
     "eval() call — rarely safe; audit the input"),

    # --- A05 Security Misconfiguration ---
    ("flask-debug-true", "Top10:A05",
     re.compile(r"(?:app\.debug\s*=\s*True|debug\s*=\s*True)"),
     "debug mode enabled — off in production"),
    ("django-debug-true", "Top10:A05",
     re.compile(r"DEBUG\s*=\s*True"),
     "DEBUG=True in settings — must be False in production"),
    ("cors-wildcard-with-credentials", "Top10:A05",
     re.compile(
         r"(origin\s*:\s*['\"]\*['\"][^}]*credentials\s*:\s*true)",
         re.DOTALL | re.IGNORECASE),
     "CORS wildcard paired with credentials — incompatible security"),
    ("express-cors-wildcard", "Top10:A05",
     re.compile(r"cors\(\s*\{\s*origin\s*:\s*['\"]\*['\"]"),
     "CORS origin set to '*'"),

    # --- A07 Authentication ---
    ("jwt-decode-without-verify", "Top10:A07",
     re.compile(
         r"(?:JSON\.parse\s*\(\s*Buffer\.from|atob)\s*\([^)]*token",
         re.IGNORECASE),
     "JWT payload parsed without signature verification"),
    ("jwt-alg-none", "Top10:A07",
     re.compile(r"['\"]alg['\"]\s*:\s*['\"]none['\"]"),
     "JWT algorithm 'none' — always insecure"),

    # --- A10 / API7 SSRF ---
    ("requests-get-no-timeout", "Top10:A10",
     re.compile(r"\brequests\.get\([^)]*\)"),
     "requests.get without timeout — risks hangs; also check for SSRF"),

    # --- Kubernetes ---
    ("k8s-privileged-true", "K8s:K01",
     re.compile(r"privileged\s*:\s*true"),
     "container runs privileged — near-equivalent to root on node"),
    ("k8s-runasroot", "K8s:K01",
     re.compile(r"runAsUser\s*:\s*0\b"),
     "container runs as UID 0 — set runAsNonRoot: true"),
    ("k8s-hostpath", "K8s:K01",
     re.compile(r"hostPath\s*:"),
     "hostPath volume — container can access node filesystem"),
    ("k8s-hostnetwork", "K8s:K01",
     re.compile(r"hostNetwork\s*:\s*true"),
     "hostNetwork: true — container shares node network namespace"),
    ("k8s-latest-tag", "K8s:K10",
     re.compile(r"image\s*:\s*[^\s]+:latest\b"),
     "image pinned to :latest — use digest or explicit version"),
    ("k8s-wildcard-rbac", "K8s:K03",
     re.compile(r"(?:verbs|resources|apiGroups)\s*:\s*\[\s*['\"]\*['\"]\s*\]"),
     "wildcard RBAC rule — almost never least-privilege"),
    ("k8s-automount-sa-true", "K8s:K06",
     re.compile(r"automountServiceAccountToken\s*:\s*true"),
     "automountServiceAccountToken: true — only on pods that call the API"),
    ("k8s-secret-plaintext", "K8s:K08",
     re.compile(r"stringData\s*:\s*\n[^\n]*(?:password|token|secret|key)",
                re.IGNORECASE),
     "secret manifest contains plaintext — use external store + CSI"),

    # --- LLM / Agentic ---
    ("llm-prompt-fstring", "LLM01",
     re.compile(
         r"(?:\.generate|\.complete|\.invoke)\s*\(\s*[fF]['\"][^'\"]*\{.*user",
         re.IGNORECASE),
     "LLM call uses f-string prompt with user input — role-separate instead"),
    ("llm-exec-on-output", "LLM05",
     re.compile(r"(?:exec|eval)\s*\([^)]*(?:response|completion|llm_out)",
                re.IGNORECASE),
     "exec/eval on LLM output — never safe; validate with schema first"),
]


def iter_files(root: Path, includes: Iterable[str]) -> Iterable[Path]:
    include_list = list(includes)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not any(fnmatch.fnmatch(name, pat) for pat in include_list):
                continue
            path = Path(dirpath) / name
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[Finding] = []
    lines = text.splitlines()
    for pat_id, code, regex, note in PATTERNS:
        for match in regex.finditer(text):
            # Map match start to line number.
            line_no = text.count("\n", 0, match.start()) + 1
            excerpt = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
            if len(excerpt) > 180:
                excerpt = excerpt[:177] + "..."
            findings.append(Finding(
                file=str(path),
                line=line_no,
                standard=code,
                pattern=pat_id,
                excerpt=excerpt,
                note=note,
            ))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regex pre-scan for obvious OWASP patterns.",
    )
    parser.add_argument("path", help="File or directory to scan.")
    parser.add_argument(
        "--format", choices=("json", "text"), default="json",
        help="Output format. JSON (default) is easier for the skill to consume; "
             "text is for humans reading the terminal.",
    )
    parser.add_argument(
        "--include", default=",".join(DEFAULT_INCLUDES),
        help="Comma-separated glob patterns to include.",
    )
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    includes = [s.strip() for s in args.include.split(",") if s.strip()]
    findings: list[Finding] = []
    scanned = 0
    for path in iter_files(root, includes):
        scanned += 1
        findings.extend(scan_file(path))

    if args.format == "json":
        json.dump(
            {
                "scanned_files": scanned,
                "findings": [asdict(f) for f in findings],
                "notes": [
                    "Hits are candidates, not verdicts. Read the surrounding",
                    "code before treating any match as a real finding.",
                    "Absent controls (no auth middleware, no rate limit, no",
                    "NetworkPolicy) are NOT detected by this scanner.",
                ],
            },
            sys.stdout,
            indent=2,
        )
        print()
    else:
        print(f"Scanned {scanned} files; {len(findings)} candidate hits.")
        for f in findings:
            print(f"  [{f.standard}] {f.file}:{f.line} — {f.pattern}")
            print(f"      {f.excerpt}")
            print(f"      why: {f.note}")
        if not findings:
            print("  (no regex matches — this does NOT mean the code is secure;")
            print("   many real issues are absent-control patterns this scanner cannot see)")

    print(
        f"quick_scan: scanned {scanned} files, {len(findings)} candidate hits",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
