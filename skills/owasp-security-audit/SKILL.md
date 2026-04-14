---
name: owasp-security-audit
description: Perform OWASP-aligned security audits of source code, API handlers, mobile apps, Kubernetes manifests, LLM/agent code, and deployment configuration. Covers the OWASP Top 10 (2021), ASVS 5.0, MASVS, API Security Top 10 (2023), Kubernetes Top 10 (2022), and the OWASP LLM Top 10 (2025) plus Agentic Applications Top 10 (2026). Use this skill whenever the user asks for a security review, vulnerability audit, threat assessment, compliance check, or hardening guidance — including indirect phrasings like "is this login flow secure?", "review this endpoint", "audit my pod spec", "what could go wrong with this prompt?", or when the user pastes auth, crypto, SQL, RBAC, or LLM-tool-calling code without explicitly asking for security review.
---

# OWASP Security Audit

This skill turns Claude into a rigorous security auditor that applies the
right OWASP standard to the code in front of it, grounds every finding in
observable evidence, and produces a structured, actionable report.

## When this skill applies

Any request that asks Claude to evaluate the security of code,
configuration, or a design: audits, reviews, compliance checks,
hardening, threat analysis, "is this safe?" questions. Also trigger
when the user pastes security-sensitive code — auth handlers,
database queries, Kubernetes manifests, LLM wrappers, Keychain/Keystore
calls, crypto primitives — without saying "security". That's when the
value is highest.

## How to route

Start by skimming `references/top10.md`; its patterns (broken access
control, injection, crypto misuse, misconfiguration, logging gaps)
recur under every other standard. Then load additional references
from the table below based on what the code shows.

| If you see…                                                               | Also load                               |
| ------------------------------------------------------------------------- | --------------------------------------- |
| HTTP handlers, form input, SQL, cookies, CSRF, XSS, HTML templates        | `references/top10.md` (primary)         |
| REST / GraphQL endpoints, JWT, OAuth, rate limiting, API gateways         | `references/api-top10.md`               |
| iOS (Swift/Obj-C), Android (Kotlin/Java), Keychain, Keystore, biometrics  | `references/masvs.md`                   |
| `kind: Pod`, `ClusterRole`, `NetworkPolicy`, Helm charts, Dockerfile      | `references/kubernetes-top10.md`        |
| LLM SDK calls, system prompts, tool/function calling, RAG, agent loops    | `references/llm-agentic.md`             |
| Explicit compliance question: "what ASVS L2 requires…", "is this MASVS…" | `references/asvs.md` and/or `masvs.md`  |

For a standard-by-standard compliance review ("check this against
ASVS Level 2"), read the reference file end-to-end and walk through
each relevant requirement. Otherwise, treat the reference as a lookup
index — grep for the categories the code triggers.

`references/vulnerable-patterns.md` holds paired vulnerable/secure
snippets by language and category; open it when a reference file
points there or when you need a concrete fix template.

## Audit workflow

Run these steps in order. Skipping ahead means you missed context.

### 1. Scope the review

Pin down four things before reading any code:

- **Target:** snippet, file, directory, or repo? A 30-line paste and an
  audit of `backend/` need different shapes. Ask if unclear.
- **Stack:** language, framework, runtime. An SQL-injection fix in
  Django ORM reads different from one in raw `psycopg2`.
- **Threat model cues:** internet-facing, internal, or library? Public
  endpoints get stricter controls than cron jobs.
- **Goal:** iterating on a fix, pre-release audit, or compliance check?
  Tailor depth accordingly.

Ask one targeted clarifying question if ambiguity would change the
findings. Don't interrogate.

### 2. Run the quick scan (for files or directories)

For any review over a file tree, run the bundled scanner first:

```bash
python scripts/quick_scan.py <path>
```

It catches obvious regex-findable patterns — hardcoded credentials,
`debug=True`, `innerHTML` with variables, `privileged: true`, wildcard
RBAC, shell strings built from input, unverified JWTs. Hits are
**leads, not verdicts**; read each in context. Absent-control findings
(no auth middleware, no rate limit, no NetworkPolicy) will never
appear here — those come from step 3.

Skip the scanner for pasted snippets; read them directly.

### 3. Read the code the way an attacker would

For each route, handler, query, or tool call:

- **Who can reach this?** Any user, authenticated, or admin-only? Is
  that enforced server-side, or assumed from the client?
- **What input crosses a trust boundary?** URL params, headers,
  bodies, uploads, env, third-party API responses, LLM outputs,
  database rows written by lower-privilege tenants.
- **What sinks does that input reach?** SQL, shell, filesystem paths,
  templating, URL fetches, deserialization, code execution, LLM
  prompts, authorization decisions.
- **What's missing?** Authorization check, ownership verification,
  rate limit, audit log, output encoding, a non-leaking error handler.
  Absent controls are the finding just as often as broken ones.

Cross-reference each suspicion against detection signals in the
relevant reference file.

### 4. Ground every finding in evidence

A security finding without an exact file:line and a quoted code pattern
is a guess, not a finding. For each issue, collect:

- File path and line number (or exact snippet for pasted code).
- The vulnerable code, quoted verbatim.
- **Why it's vulnerable.** Three things, not one: (a) the pattern,
  named — trust-boundary confusion, missing object-level authorization,
  ORM-as-DTO, plaintext-at-rest, time-of-check/time-of-use, etc.;
  (b) the specific boundary crossed or primitive misused; (c) the
  assumption the original author made that no longer holds. Phrase
  positively — describe what the code does, not what it fails to do.
  A one-line "why" is a signal you haven't engaged the finding.
- A concrete exploit scenario (not "an attacker could theoretically…"
  but "sending `?id=5` as user 3 reveals user 5's order").
- **A fix with code *and* the tradeoff it commits to.** Name one
  alternative considered and why it was rejected. If the fix shifts
  complexity elsewhere (to the DB, the client, operations, or a
  downstream service), name where it lands. Library swap? Name the
  library and why it wins over the obvious alternatives.
- **Pattern and blast radius.** Where else in the codebase does the
  same pattern live? A grep hint is good; `[?]` on unsearched areas
  is honest. Which teams or services inherit the risk? When the
  pattern recurs three or more times, the finding *is* the pattern —
  escalate it to Next Steps → Systemic instead of filing duplicates.

  **For directory/repo reviews**, spawn a focused subagent per
  finding to enumerate call sites: pass the grep pattern and the
  repo path, get back a list of `file:line` hits to paste in. This
  keeps the main context clean and lets blast-radius work proceed
  in parallel with the next finding's analysis. Skip for pasted
  snippets — you can see everything already.
- The standard and code, emitted as a **markdown link** to the
  canonical OWASP page (see "Link every code you cite" below).

If you can't satisfy that bar, read more or drop the finding. Noise
erodes the report.

### 5. Assign severity — and argue it

Four levels, picked by impact × exploitability (not by which standard
the issue falls under):

- **Critical** — direct takeover, account compromise, arbitrary code
  execution, secret disclosure to unauthenticated users, or full data
  loss. Exploit reachable without special conditions.
- **High** — authenticated user escalates privileges, accesses other
  users' data, bypasses billing/rate limits, or causes broad DoS.
  Minimal attacker effort.
- **Medium** — low-sensitivity disclosure, flaws that need chaining,
  or defense-in-depth gaps that aren't immediately exploitable.
- **Low** — hardening gaps, logging omissions, version disclosure,
  cosmetic header issues.

**Every finding carries a one-sentence severity rationale** shaped as
`<who is exploited> + <what they gain> + <precondition chain>`.
"Critical because any authenticated user can read every other user's
order by incrementing the ID; no precondition beyond a valid login"
is a rationale. "Critical" is a label pretending to be one. No
intensifier adjectives without a quantified consequence: write
"Critical: full customer database readable in O(n) requests from
any free-tier account", not "catastrophic".

When in doubt, downgrade and name the mitigating precondition you
relied on (WAF blocks the path, endpoint behind SSO, attacker already
has admin). Over-grading trains readers to skim; under-grading
without naming the precondition lets a real exposure slip.

### Link every code you cite

When you reference a standard code — `A01`, `API2:2023`, `LLM05:2025`,
`K08`, `ASI03`, and so on — emit it as a markdown link to the canonical
OWASP page. The URL map lives at `references/owasp-urls.json`. Read it
once at the start of a review; for each code you use, resolve the
entry and format the citation as:

```
[A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
```

If a code isn't in the map, fetch the project index URL listed under
`_indexes` (for example `https://owasp.org/API-Security/editions/2023/en/0x11-t10/`
for the API Top 10), find the canonical per-risk URL, and append the
new entry to `references/owasp-urls.json` so the next review inherits
it. Entries marked `"confidence": "pattern"` or `"index-fallback"` are
leads — if WebFetch returns 404, fall back to the `_indexes` page and
re-link. Unlinked codes are a missing-citation finding against
yourself; don't ship a report with them.

### 6. Produce the report

Use this structure unless the user asks for a different format.

```markdown
# Security Review: <target>

## Summary
<N findings: X critical, Y high, Z medium, W low>
<One-paragraph framing: what was reviewed, which standards applied,
top concerns named without adjectives.>

## Standards applied
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- <…others — always linked>

## Findings

### [CRITICAL] [A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) — missing ownership check
**File:** `app/routes/orders.py:42`

**Evidence:**
```python
@app.get("/orders/<int:order_id>")
def get_order(order_id):
    return jsonify(db.get_order(order_id))
```

**Why it's vulnerable.** Missing-object-level-authorization pattern —
the classic IDOR. The handler treats possession of an ID as permission
to read the resource behind it. The original author assumed a URL
parameter would only reach this code path if the caller were authorized
by something upstream; no such upstream check exists. Any authenticated
user can walk the integer ID space and read every order in the system.

**Severity rationale.** Critical because any authenticated user,
including a free-tier account, can read every other user's orders with
`curl $BASE/orders/1`, `/orders/2`, `…`; no special tooling, no social
engineering, no race condition. The only precondition is a valid login.

**Fix:**
```python
@app.get("/orders/<int:order_id>")
@require_auth
def get_order(order_id):
    order = db.get_order(order_id)
    if order is None or (order.user_id != g.user.id and not g.user.is_admin):
        abort(403)
    return jsonify(order)
```
*Tradeoff.* Enforces authorization in application code after the row
has loaded. The alternative — scoping the query itself with
`... WHERE id = %s AND user_id = %s` — never loads the row for a
non-owner and closes existence-leak paths (403 vs 404 timing). I chose
the application-layer check for readability and to keep the admin
branch legible; if admin cross-user access weren't required, the
query-layer fix would be strictly better.

**Pattern and blast radius.** Likely present on every handler in
`app/routes/` that takes an `<int:...>` URL param — grep
`def \w+\(\w*_id:` and audit each. Downstream services that import
these routes as a library inherit the risk. See Next Steps →
Systemic; filing ten near-identical findings would hide the real
problem, which is that the route decorator doesn't carry a policy.

**Validated when.**
- A request-level test asserts user A fetching user B's order returns
  403; the test fails on the pre-fix code and passes on the post-fix
  code. Green CI alone isn't validation.
- A log line `auth.denied {user_id, target_resource, handler}` is
  emitted on every 403 and ships to the SIEM. Alert fires on `>N`
  denials from one user in 5 minutes.
- Manual check: admin user can fetch the order (positive case) and
  the handler logs `auth.admin_access`.

### [HIGH] …

## Next steps

### Ships this week (single-engineer, reversible)
<Findings an owner can land via PR with no coordination. One-line
scope estimate per item: ~30 min, ~half day, one day.>

### Requires cross-team coordination
<Findings touching shared infra, contracts, or SLAs. Name the teams,
not just the files. "Needs platform to enable encryption-at-rest in
etcd" is more actionable than "encryption missing".>

### Triggers incident response (do NOT ship as a PR first)
<Live-secret exposure, evidence of active exploitation, auth-bypass on
production traffic. Required actions in order: rotate credentials,
preserve audit logs for the exposure window, review access logs to
scope impact, file the incident, *then* land the code fix. A PR is
the last step here, not the first. If a report contains one of these,
the ordering of the other sections is wrong until this is done.>

### Systemic / preventative
<Linter rules, pre-commit hooks, ADRs, architectural guidance, or
deprecations that prevent the *class* of finding from recurring. One
preventative beats ten individual fixes. When the same root cause
appears three or more times in the report, file it here once — not
three times in the main list.>

### Validated when
<Per category of change, what "done" looks like beyond green CI:
detection in place, runbook updated, rollback tested, rotation
confirmed and entries invalidated, alert fires on regression test.>

## Not covered / needs more context
<Areas you couldn't assess — e.g., "infrastructure config, CI/CD, and
runtime secrets were out of scope"; "didn't read the auth middleware
so assumed it sets `g.user.id` correctly". Be honest about gaps and
mark assumptions with `[?]` so a reviewer can challenge them.>
```

Prioritize critical findings at the top; within a severity, group by
file for reviewer ergonomics. If the report contains an
incident-response item, surface it in the Summary so nobody misses it
while scrolling through findings.

### 7. Second pass — read your draft before you ship it

Re-read what you wrote, one finding at a time, against the rubric
below. Revise in place when a rule fails, then re-check. This is
cheap in context and cheap in latency; skipping it is how
surface-level reports ship.

**Per finding:**
- "Why it's vulnerable" names a pattern, not just the instance.
- Severity carries a one-sentence `<who, gain, precondition>`
  rationale. No bare `[CRITICAL]` labels.
- Fix names one tradeoff and one alternative considered.
- Pattern-and-blast-radius is present (`[?]` when unsearched; silence
  isn't).
- Validated-when lists something beyond "tests pass" — detection,
  rotation, alert, runbook update.
- Every OWASP code is a markdown link resolved via
  `references/owasp-urls.json`.

**Across the report:**
- Next Steps has all four subsections; empties say "None", not
  omitted.
- If a live secret or active-exploit signal is anywhere in the
  report, the Summary says so and Incident-response appears before
  the findings list.
- Uncertain claims marked `[?]` or dropped.
- No real secrets or PII quoted verbatim.

Before re-reading, put yourself in the recipient's seat: an engineer
on the team that owns this code, reading the report Monday morning.
If a finding wouldn't change what they do Monday, cut it or move it
to Next Steps → Systemic / preventative.

### 8. When the user iterates

The user will paste a revised version or ask "how do I fix #3?". Read
the revised code fully — a fix that introduces a TOCTOU race or a new
injection sink is worse than the original bug. Trust the diff, verify
the diff.

## What not to do

- **Don't invent vulnerabilities.** If the code is fine for the
  category, say so. Speculative findings train the reader to skim.
- **Don't cite CVEs or CVSS scores you haven't seen.** Describe the
  class; don't attach a number.
- **Don't confuse style with security.** Naming, formatting, "I'd
  have written this differently" are not findings.
- **Don't flag "use a WAF" or "do a pentest" as a finding.** Those
  are program-level recommendations; they belong in Next Steps, not
  in the findings list.
- **Don't lecture.** Code-first beats essay-length background.
- **Don't trust a function name.** `requireAuth` might check only for
  a token, not a role. Read the implementation.
- **Don't miss absent controls.** Many real findings are what the
  code *doesn't* do — no rate limit, no CSRF token on state-changing
  GETs, no ownership check.
- **Don't let severity be a label.** If you can't argue severity in
  one `<who, gain, precondition>` sentence, you haven't understood
  the finding or it isn't the severity you picked.
- **Don't file the same finding three times.** When a root cause
  recurs, the finding is the pattern. File it once under Next Steps →
  Systemic with call sites as evidence.
- **Don't conflate "fixed" with "validated".** A patch on main is not
  remediation. A removed secret is still compromised until rotated,
  logs reviewed, detection deployed. Name the post-merge work.

## Reference file index

- `references/top10.md` — OWASP Top 10 (2021): A01–A10 with detection
  cues and mitigations. Default starting point.
- `references/api-top10.md` — OWASP API Security Top 10 (2023): BOLA,
  broken auth, property-level auth, resource consumption, SSRF, and
  more. Load for REST/GraphQL code.
- `references/masvs.md` — OWASP MASVS v2.1.0: mobile controls across
  eight groups (Storage, Crypto, Auth, Network, Platform, Code,
  Resilience, Privacy).
- `references/kubernetes-top10.md` — OWASP Kubernetes Top 10 (2022
  edition): pod hardening, RBAC, secrets, network segmentation, policy
  enforcement, cluster component configuration.
- `references/llm-agentic.md` — OWASP LLM Top 10 (2025) and Agentic
  Applications Top 10 (2026): prompt injection, improper output
  handling, excessive agency, supply chain, goal hijack, tool misuse,
  cascading failures.
- `references/asvs.md` — OWASP ASVS 5.0: L1/L2/L3 verification
  requirements across authentication, access control, cryptography,
  input validation, session management.
- `references/vulnerable-patterns.md` — paired vulnerable/secure
  snippets by language (Python, JavaScript, YAML, Swift, Kotlin) and
  category.
- `references/owasp-urls.json` — canonical URL map for every OWASP
  code. Read once at the start of a review; resolve each citation to
  a markdown link. Append new entries when you discover them.
- `assets/examples/` — nine complete example files with vulnerable
  and secure variants side-by-side.

## Scripts

- `scripts/quick_scan.py` — fast regex pre-scan.
  `python scripts/quick_scan.py <path>` emits JSON with candidate
  issues (file:line, pattern name, one-line explanation). Leads, not
  verdicts — always read the surrounding code before flagging.
