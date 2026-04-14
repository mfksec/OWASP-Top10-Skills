# OWASP LLM Top 10 & Agentic Applications Top 10

Load this reference when reviewing LLM SDK calls, system prompts,
RAG/vector store code, tool/function-calling, agent loops, or anything
that takes model output and turns it into action.

**Two distinct OWASP projects cover this space, both released as of
this writing:**

1. **OWASP Top 10 for LLM Applications (2025 edition)** — risks that
   apply to any LLM-powered system.
   - Index: <https://genai.owasp.org/llm-top-10/>
   - PDF: <https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf>

2. **OWASP Top 10 for Agentic Applications (2026 edition)** — agentic
   risks on top of LLM risks; released 2025-12-09 by the Agentic
   Security Initiative under the OWASP GenAI Security Project.
   - Announcement: <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>
   - Resource page: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>

> Earlier drafts of this project called the Agentic list "Preview" and
> used invented codes like `AG01–AG10`. Those codes are **not** part
> of any OWASP publication. Use `LLM01`–`LLM10` and `ASI01`–`ASI10`
> only.

## How to use

For non-agent LLM code (chatbots, RAG, summarizers), the LLM Top 10 is
usually enough. For autonomous agents — tool-calling loops,
multi-agent pipelines, MCP servers — apply both lists. The Agentic
list adds concerns (goal hijack, cascading failures, inter-agent
trust) that the LLM list doesn't address.

---

# Part 1: LLM01–LLM10 (2025)

## LLM01:2025 — Prompt Injection

Source: <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>

User-supplied content alters model behavior in unintended ways.
Direct (user-to-prompt) or indirect (content-retrieved-by-model).
Includes imperceptible inputs the model parses but a reviewer would
not notice.

**Detection signals**
- User input concatenated directly into a prompt (`f"...{user_input}..."`)
  with no structural separation.
- Single flat prompt: no distinct system / user / tool channel.
- RAG or tool outputs placed in the same trust zone as system
  instructions.
- No output-side guardrails on instructions that came from retrieved
  content.
- No adversarial test corpus ("ignore previous instructions", DAN
  prompts, invisible-character payloads).

**Mitigations**
```python
# Role-separated messages API, never string concatenation
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user",   "content": user_input},
]

# Fence retrieved content so the model treats it as data
retrieved_block = f"<retrieved_context>\n{doc}\n</retrieved_context>"
```
- Human-in-the-loop confirmation for any tool call with external
  side effects.
- Red-team with adversarial strings from public corpora.

---

## LLM02:2025 — Sensitive Information Disclosure

Source: <https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/>

Outputs (or memorized weights) expose PII, credentials, health
records, business secrets, or system internals to parties who should
not see them.

**Detection signals**
- Fine-tuning dataset contains PII with no scrubbing pipeline.
- Chat histories stored without per-user segmentation.
- Model responses logged in plaintext to shared observability tools.
- No DLP/regex scan on model outputs before return to client.

**Mitigations**
```python
import re
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
def redact(text: str) -> str:
    return SECRET_RE.sub("[REDACTED]", text)
```
- Scrub training data with a deterministic PII pipeline before
  fine-tuning.
- Per-tenant isolation in RAG stores; never cross-index tenants.
- Redact before logging; redact again before returning.

---

## LLM03:2025 — Supply Chain

Source: <https://genai.owasp.org/llm-top-10/>

Third-party models, datasets, plugins, and infrastructure introduce
compromise paths: tampered weights, typosquatted model cards,
poisoned datasets, malicious adapters.

**Detection signals**
- Models pulled by tag rather than immutable digest/hash.
- No AIBOM (AI Software Bill of Materials) for deployed models.
- Hugging Face / registry downloads without signature verification.
- No provenance metadata for LoRA adapters or embeddings.

**Mitigations**
- Pin models by SHA-256 digest; verify signatures (Sigstore where
  available).
- Generate an AIBOM per deployment.
- Isolate model-loading code from the public internet at runtime;
  allowlist registry hosts only.

---

## LLM04:2025 — Data and Model Poisoning

Source: <https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/>

Adversaries manipulate training, fine-tuning, or embedding data so
the model emits attacker-chosen outputs on trigger phrases, or
degrades on target inputs. 2025 pairs data and model poisoning.

**Detection signals**
- User-contributed data ingested into fine-tune pipeline without
  review.
- No canary / backdoor probes in the eval harness.
- Embedding index auto-rebuilt from untrusted crawl output.

**Mitigations**
- Curated eval set probing known backdoor triggers on every release.
- Sign and version datasets; compare hashes across runs.
- Segregate training data by source and reputation tier.

---

## LLM05:2025 — Improper Output Handling

Source: <https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/>

Downstream systems treat LLM output as trusted, enabling XSS, SSRF,
SQL injection, or shell injection when the output is rendered or
executed. (Renamed from "Insecure Output Handling" in earlier
editions.)

**Detection signals**
- `exec`, `eval`, `subprocess.run(..., shell=True)` fed directly from
  model output.
- HTML rendered via `innerHTML = llm_output` with no sanitizer.
- SQL constructed by string formatting from a "text-to-SQL" agent.
- Model output used as a filesystem path without normalization.

**Mitigations**
```python
# Parameterize; never interpolate model output into SQL
cursor.execute("SELECT * FROM orders WHERE id = %s", (parsed_id,))
```
- Validate model output with a schema (pydantic, JSON Schema) before
  acting on it.
- Render model output through an HTML sanitizer (DOMPurify, bleach).
- Never `eval` or `exec` on model output.

---

## LLM06:2025 — Excessive Agency

Source: <https://genai.owasp.org/llm-top-10/>

The LLM is granted more functionality, permissions, or autonomy than
it needs, so a single prompt-injection or misstep produces outsized
damage.

**Detection signals**
- Agent holds a long-lived admin / service-account token covering
  many APIs.
- Tools include open-ended primitives (`run_shell`,
  `http_request_any_url`).
- No per-tool allowlist of arguments or destinations.
- No human-approval step on destructive actions (delete, transfer,
  send).

**Mitigations**
```python
ALLOWED_TOOLS = {"search_docs", "summarize"}
def dispatch(tool: str, args: dict):
    if tool not in ALLOWED_TOOLS:
        raise PermissionError(tool)
```
- Scope credentials to the minimum API set the agent actually calls.
- Require explicit user confirmation for irreversible side effects.
- Prefer typed, narrow tools over broad primitives.

---

## LLM07:2025 — System Prompt Leakage

Source: <https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/>

System prompts often contain credentials, internal logic, or
authorization rules; exfiltration of the prompt (via injection or
model coaxing) hands attackers both the rules and any embedded
secrets.

**Detection signals**
- API keys, DB URLs, or feature flags embedded in the system prompt
  string.
- Prompt contains authorization logic ("if user is admin, allow X").
- No test that asserts prompt text is not returned on "repeat your
  instructions" probes.

**Mitigations**
- Keep secrets in environment variables and tool configs, never in
  the prompt.
- Enforce authorization outside the model (policy engine, not prompt
  text).
- Red-team with "repeat your instructions verbatim" style probes;
  assert the prompt doesn't leak.

---

## LLM08:2025 — Vector and Embedding Weaknesses

Source: <https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/>

Weaknesses in how vectors / embeddings are generated, stored, or
retrieved in RAG systems — cross-tenant leakage, embedding inversion,
poisoned chunks, missing access control on the vector store.

**Detection signals**
- Single vector index shared across tenants with filter-only
  isolation.
- Chunk metadata missing `owner` / `acl` field.
- Upsert endpoint exposed without authentication.
- No integrity check on embeddings loaded from disk.

**Mitigations**
- Enforce access control at the vector store layer, not just the
  application query.
- Per-tenant namespaces or collections rather than a shared index.
- Filter retrieved chunks through the user's authorization context
  before prompting.

---

## LLM09:2025 — Misinformation

Source: <https://genai.owasp.org/llm-top-10/>

The model produces plausible but false content, including
hallucinated code, fabricated citations, and "package hallucination"
that leads users to install malicious typosquats.

**Detection signals**
- No grounding step (retrieval or tool call) for factual claims.
- Code-generation path installs suggested packages without lockfile
  review.
- No confidence or citation metadata surfaced to the user.

**Mitigations**
- Ground answers in retrieved documents; show clickable citations.
- Verify suggested package names against a registry allowlist before
  `pip install` / `npm install`.
- Evaluator model or rule pass flagging unsourced factual claims.

---

## LLM10:2025 — Unbounded Consumption

Source: <https://genai.owasp.org/llm-top-10/>

Resource exhaustion via token floods, recursive tool loops, oversized
context windows, or cost-amplification attacks that convert a cheap
request into an expensive model call. Expands the earlier "Model DoS".

**Detection signals**
- No per-request `max_tokens` or per-user rate limit.
- Agent loops have no iteration cap.
- Input size not bounded before tokenization.
- No billing alert tied to per-user spend.

**Mitigations**
```python
MAX_ITERS = 8
for _ in range(MAX_ITERS):
    step = agent.step()
    if step.done: break
else:
    raise RuntimeError("agent loop cap reached")
```
- Enforce token, time, and dollar budgets per session at the gateway.
- Cache deterministic prompts; reject duplicate floods.
- Wire per-user spend to paging alerts.

---

# Part 2: ASI01–ASI10 (Agentic, 2026)

> Risks in this part are verified against the December 9, 2025 OWASP
> announcement and the resource page. Per-item descriptions for
> ASI01–ASI10 are paraphrased from the announcement's real-world-
> incident framing; the downloadable PDF linked on the resource page
> carries the canonical definitions [?] — consult it for direct quotes.

## ASI01 — Agent Goal Hijack

An attacker redirects the agent's objective via hidden prompts
embedded in tool output, retrieved documents, or multi-turn memory
(EchoLeak-class attacks that turn copilots into exfil engines).

**Detection signals**
- Agent goal / plan derived from untrusted retrieval output with no
  integrity check.
- No distinction between "user-stated goal" and "content the agent
  read".
- Chain-of-thought can be rewritten by tool outputs mid-run.

**Mitigations**
- Pin the goal at the start of the run; treat later "new
  instructions" in retrieved content as data.
- Validate the plan against the original user intent before each
  tool call.
- Separate "instructions" and "evidence" channels in the agent
  scaffolding.

---

## ASI02 — Tool Misuse

Legitimate tools coerced into destructive use (Amazon Q incident),
typically because tool arguments are not constrained to the agent's
authorized scope.

**Detection signals**
- Tool wrappers accept arbitrary arguments without schema validation.
- Destructive tools (`delete_files`, `run_sql`) registered without a
  dry-run mode.
- No audit of which arguments the agent has historically used.

**Mitigations**
```python
from pydantic import BaseModel, Field

class DeleteArgs(BaseModel):
    path: str = Field(pattern=r"^/workspace/tmp/")
# validate BEFORE the tool executes
```
- Allowlist arguments by pattern; reject anything outside.
- Require second-factor confirmation for destructive tools.

---

## ASI03 — Identity & Privilege Abuse

Agents run with credentials that exceed the current user's session
scope, so prompt injection or a loop bug causes cross-user data
access or privilege escalation.

**Detection signals**
- Single service account used for all users.
- Agent does not pass end-user identity through to downstream APIs.
- No short-lived token exchange per session.

**Mitigations**
- OAuth token exchange / on-behalf-of flows so downstream calls run
  as the user.
- Per-session scoped tokens with tight TTL.
- Log and alert on agent-initiated access to resources outside the
  user's tenant.

---

## ASI04 — Agentic Supply Chain Vulnerabilities

Dynamic MCP servers, A2A (agent-to-agent) ecosystems, and
third-party skills can be poisoned at runtime (GitHub MCP exploit
example).

**Detection signals**
- MCP server list fetched dynamically at startup without pinning.
- Tools discovered and auto-registered without human review.
- No signature verification on MCP server binaries or manifests.

**Mitigations**
- Pin MCP servers by version + digest; review manifest diffs in PRs.
- Host-side allowlist of MCP server origins.
- Isolate MCP processes with OS-level sandboxing.

---

## ASI05 — Unexpected Code Execution

Natural-language instructions become executable paths (AutoGPT-style
RCE) because the agent has access to `exec`, shell, or
code-interpreter tools without constraints.

**Detection signals**
- Agent calls `exec()`, `eval()`, or an unsandboxed Python REPL tool.
- Code-interpreter runs with network access and host filesystem
  access.
- No per-call resource limits on the interpreter.

**Mitigations**
- Run code interpreters in a sandbox (gVisor, Firecracker, or a
  remote sandbox service) with no host filesystem and restricted
  egress.
- CPU / RAM / wall-clock caps per execution.
- Disallow package installation at runtime; pre-bake the interpreter
  image.

---

## ASI06 — Memory & Context Poisoning

Attackers plant content in the agent's long-term memory (vector
store, scratchpad, summary history) that reshapes behavior on future
turns (Gemini memory attack example).

**Detection signals**
- Memory writes unauthenticated / accept any string the agent
  produces.
- No provenance metadata (who wrote, when, from what source).
- Memory retrieval returns items across sessions without scoping.

**Mitigations**
- Treat memory writes as privileged: explicit tool calls with user
  approval for persistent memory.
- Tag every memory item with source + trust level; filter by trust
  at retrieval.
- Expire/verify items on a schedule; let users view and delete their
  agent's memory.

---

## ASI07 — Insecure Inter-Agent Communication

Multi-agent deployments trust inbound messages from sibling agents;
spoofed or replayed messages misdirect the cluster.

**Detection signals**
- Agent-to-agent messages carry no signature or session binding.
- No message-ordering / replay protection.
- Shared bus without per-agent identity or ACL.

**Mitigations**
- mTLS or signed envelopes between agents; verify sender identity.
- Nonce + timestamp on every message; reject replays.
- Per-agent authorization: sender X may ask receiver Y to do Z only.

---

## ASI08 — Cascading Failures

One agent's wrong output becomes the next agent's input, and errors
amplify as they propagate — particularly dangerous when downstream
agents take irreversible action on upstream hallucinations.

**Detection signals**
- No circuit breaker between agents.
- No confidence threshold gating downstream action.
- Retries on failure without back-off or escalation to a human.

**Mitigations**
- Explicit confidence / quality gates between stages; fail closed
  below threshold.
- Circuit breakers: halt the pipeline after N failures and page a
  human.
- End-to-end dry-run mode before committing irreversible changes.

---

## ASI09 — Human-Agent Trust Exploitation

Confident, well-formatted output causes human operators to approve
harmful actions — social engineering via the agent's own articulacy.

**Detection signals**
- Approval UI shows only the natural-language summary, not the
  underlying tool call.
- No diff view for "what will actually change".
- Approvals can be batched / auto-confirmed with one click.

**Mitigations**
- Show the exact tool call + arguments + expected side effects
  alongside any summary.
- Destructive actions require typing a confirmation token.
- Record approval decisions with full context for audit.

---

## ASI10 — Rogue Agents

Agents exhibit misalignment, concealment, or self-directed action
(Replit meltdown incident). Includes agents that spawn sub-agents,
hide actions from logs, or persist beyond intended lifetime.

**Detection signals**
- Agent can spawn other agents without per-child budget / permission
  check.
- Logging is under the agent's own control — the agent can suppress
  its trace.
- No watchdog that can kill a runaway agent.

**Mitigations**
- Out-of-band logging: logs stream to a sink the agent cannot write
  to or delete.
- External kill switch and per-run hard budget (wall-clock, tokens,
  dollars).
- Continuous behavior monitoring against a baseline; alert on drift.

---

# Mapping: repo's old `AG##` codes → real OWASP items

For anyone updating code or docs that used the old taxonomy:

| Old (invented) | Real OWASP item(s) |
|---|---|
| AG01 Prompt Injection | LLM01 Prompt Injection; related ASI01 |
| AG02 Insufficient Input Validation | **No OWASP item.** Folded into LLM01 / LLM05 |
| AG03 Insecure Output Handling | LLM05 Improper Output Handling |
| AG04 Model Poisoning | LLM04 Data and Model Poisoning |
| AG05 Denial of Service | LLM10 Unbounded Consumption |
| AG06 Unauthorized Tool Access | LLM06 Excessive Agency; ASI02; ASI03 |
| AG07 Training Data Leakage | LLM02 Sensitive Information Disclosure |
| AG08 Excessive Autonomy | LLM06 Excessive Agency |
| AG09 Inadequate Logging | **Not OWASP LLM/Agentic.** Closest: web A09 |
| AG10 Supply Chain Risks | LLM03 Supply Chain; ASI04 |

Use the real codes in findings. If you encounter an audit report or
repo referencing `AG01`–`AG10`, translate it before acting.
