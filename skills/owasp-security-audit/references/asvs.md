# OWASP ASVS — Application Security Verification Standard

Load this reference when a user asks a compliance-shaped question:
"does this meet ASVS L2?", "which requirements apply to session
management?", "what's the bar for a regulated environment?" ASVS is
a **verification** standard — a list of testable requirements, not
a narrative standard like the Top 10.

**Source:** OWASP Application Security Verification Standard —
<https://owasp.org/www-project-application-security-verification-standard/>.
Version 5.0 is the current release as of this writing.

## Verification levels

ASVS defines three cumulative levels:

- **L1** — baseline. All applications should meet this.
- **L2** — applications handling sensitive data (PII, financial,
  health). Most production apps belong here.
- **L3** — critical applications (national infrastructure, payment
  networks, life-safety). Adds cryptographic agility, HSM backing,
  comprehensive audit.

When the user asks "does this meet Ln", the answer is "for each
applicable chapter, here's the L1/L2/L3 requirements and which are
met / partially met / missing". Don't treat "pass" or "fail" as a
single number.

## Mapping to code review

ASVS isn't a replacement for the Top 10 — the Top 10 tells you what
classes of bugs exist; ASVS tells you what controls a verified app
must have in place. Use the Top 10 for offense ("what can go wrong
here?") and ASVS for defense ("what must be true for this to be
secure?").

When a user pastes an auth flow and asks for an ASVS check, walk
through the chapter's requirements and say which are satisfied, which
are violated, and which can't be determined from the snippet.

---

## Chapter 2: Authentication

**L1**
- Passwords min 8 chars; verified over HTTPS.
- Default credentials rotated; no shipped defaults in production.
- Failed login responses don't reveal whether account exists.
- Password reset uses time-limited, single-use tokens.

**L2**
- Password hashing: bcrypt / scrypt / argon2 with appropriate cost.
- MFA available; required for privileged operations.
- Account lockout or progressive delay on repeated failures.
- Passwords checked against a breached-password list (HIBP API).

**L3**
- Adaptive authentication (risk score drives friction).
- Hardware-backed cryptography for credentials.
- Step-up auth required for every sensitive operation.
- Comprehensive audit logging of auth events (success + failure,
  MFA challenges, password changes).

---

## Chapter 4: Access Control

**L1**
- Access control enforced on every sensitive operation.
- Default deny: unspecified access is denied.
- Roles and permissions documented.

**L2**
- Object-level controls enforced server-side: ownership checked at
  query layer or immediately after.
- Property-level controls: response schemas and write allowlists per
  role (see OWASP API3).
- Privilege escalation detection (anomalies in role transitions
  logged).

**L3**
- Policy-based (PBAC) or attribute-based (ABAC) access control.
- Cryptographic verification of authorization claims (signed tokens
  with per-object scopes).
- Real-time enforcement with audit trail per decision.

---

## Chapter 6: Cryptography

**L1**
- AES-256 or equivalent for data at rest.
- TLS 1.2+ for data in transit.
- Authenticated encryption modes only (GCM, CCM, ChaCha20-Poly1305).
- Keys stored separately from encrypted data.

**L2**
- Documented key-rotation schedule, enforced.
- Industry-standard crypto libraries; no DIY primitives.
- CSPRNG used for all security-sensitive randomness.
- Proper KDF for password-derived keys (argon2id, PBKDF2-SHA256
  with ≥ 310,000 iterations).

**L3**
- HSM or cloud KMS integration for high-value keys.
- Cryptographic agility: algorithm can be swapped without code
  changes.
- Perfect forward secrecy on all TLS endpoints.
- Key escrow / recovery with separation of duties.

---

## Chapter 5: Input Validation & Encoding

**L1**
- Validation performed server-side; client checks are UX, not
  security.
- Whitelist validation on structured fields (numeric ranges, known
  enums).
- SQL injection protection via parameterized queries.
- Output encoding in the context where data lands (HTML attr, JS
  string, URL, CSS).

**L2**
- Parameterized queries everywhere; no dynamic SQL.
- Type and length validation on every input.
- Context-aware output encoding via framework or vetted library.
- XSS defenses: Content-Security-Policy set; template engines
  auto-escape.

**L3**
- Semantic validation (business rules checked alongside syntactic).
- XXE and XML-bomb protection; external entity resolution off.
- Comprehensive injection defense across all sinks (SQL, shell,
  LDAP, template, deserialization).
- Cryptographic signing of inbound payloads where provenance
  matters.

---

## Chapter 3: Session Management

**L1**
- Session IDs from CSPRNG, ≥ 128 bits entropy.
- `HttpOnly` + `Secure` + `SameSite=Lax`/`Strict` cookies.
- Session expiration after idle + absolute timeout.
- Logout invalidates the session on the server.

**L2**
- Session token regenerated on authentication (defeats fixation).
- Concurrent session limits per user.
- Encrypted server-side session storage.
- Distinct idle and absolute timeouts, configurable.

**L3**
- Cryptographic token binding (e.g., bound to TLS channel or device
  key).
- Session fixation protection at framework layer.
- Behavioral anomaly monitoring (geo, device fingerprint changes).
- Tamper-evident session tokens (signed or encrypted server-side).

---

## Chapter 8: Data Protection

**L1**
- Sensitive data (PII, credentials, payment data) classified and
  inventoried.
- Encryption of sensitive data at rest.
- Backups encrypted with keys separate from production.

**L2**
- Data retention and deletion policies implemented in code.
- Memory handling: sensitive values zeroed / held in secure allocators
  where language permits.
- No sensitive data in URLs (logs capture URLs, URLs leak via
  referrer).

**L3**
- Separation of duties for access to production data.
- Bulk-export alerting with human approval for large queries.
- Privacy-by-design reviews during feature design.

---

## Chapter 7: Error Handling & Logging

**L1**
- Generic error responses to clients; no stack traces or SQL errors
  in production output.
- Security events logged (login, logout, access denial, privilege
  change, config change).

**L2**
- Correlation IDs across request, log, and downstream call.
- Logs centralized to a separate system with integrity protection.
- Retention matches policy; rotation and archival automated.

**L3**
- Tamper-evident logs (hash chain, signed batches).
- Real-time alerting on anomaly patterns (brute force, impossible
  travel, mass export).
- Independent review of log-handling code.

---

## Chapter 10: Malicious Code

**L1**
- No known malware in dependencies (SCA scanner blocks criticals).
- CI/CD pipeline integrity (signed commits, protected branches).

**L2**
- SBOM generated at build.
- Signed release artifacts; verification before deployment.

**L3**
- Reproducible builds.
- Runtime integrity checks (HIDS / attestation).

---

## Using this chapter-by-chapter

When reviewing against ASVS:

1. Identify which chapters apply. A login flow triggers Ch. 2, 3, 7.
   A data-export endpoint triggers Ch. 4, 5, 7, 8.
2. Walk through that chapter's L1 requirements first. Each is a
   testable yes/no.
3. Escalate to L2 for any sensitive-data app; L3 only when the user
   asks for it or the domain is regulated.
4. In the report, cite the chapter + level: "Ch. 2 L2 — requirement
   V2.1.5 (MFA for sensitive operations) — not met; no MFA step in
   `/admin/users/delete`".

The OWASP ASVS checklist is published as a spreadsheet/CSV; pull it
down and map findings to specific requirement IDs for a real
compliance deliverable. This reference is a summary to guide
conversation, not a substitute for the canonical requirement IDs.
