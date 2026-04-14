# OWASP Top 10 — Web Application Risks

This is the default reference for any code that speaks HTTP, renders HTML,
persists data, or handles user credentials. Its ten categories recur in
the API, Kubernetes, and LLM standards under different names; reading
through this list first will speed up every later reference.

**Source:** OWASP Top 10 project — <https://owasp.org/www-project-top-ten/>.
Category codes below use the 2021 edition (A01–A10), which remains the
currently published OWASP Top 10 as of this writing [?]. If a newer
edition has been released, verify the category codes before citing.

## How to use this file

For each suspected category, read the matching section, apply the
**detection signals** to the code in front of you, then use the
**mitigation** column to phrase the fix. The **code example** shows the
vulnerable/secure pair in one language; look in
`../assets/examples/` for fuller paired examples or in
`vulnerable-patterns.md` for other languages.

---

## A01: Broken Access Control

The most common real-world finding. Covers missing authorization checks,
IDOR, privilege escalation, and relying on client-side enforcement.

**Detection signals**
- Handlers that read or mutate resources keyed by a URL parameter
  (`/users/:id`, `/orders/:id`) with no check that the authenticated user
  owns or may access that resource.
- Authorization checked only in the UI (hidden fields, disabled buttons)
  while the server endpoint is wide open.
- Role checks done with "blacklist" logic (`if not is_guest` → treat as
  admin) instead of explicit allowlists.
- Functions that update privileged state (billing, roles, feature flags)
  with no explicit role check.
- Direct database lookups by primary key without a `WHERE user_id = ?`
  ownership clause.

**Mitigations**
- Default-deny: every handler requires explicit allow. A missing
  `@require_auth` or `requireRole(...)` is a finding.
- Enforce ownership at the data layer: `WHERE id = ? AND user_id = ?`
  beats a post-query check because a successful query itself is now the
  authorization.
- Use opaque / unguessable IDs for resources whose enumeration matters
  (UUIDs, signed tokens) — but never as the *only* control.
- Log every denial; repeated 403s on sequential IDs are the classic IDOR
  signature.

**Code example**
```python
# VULNERABLE
@app.get("/orders/<int:order_id>")
def get_order(order_id):
    return jsonify(db.get_order(order_id))

# SECURE
@app.get("/orders/<int:order_id>")
@require_auth
def get_order(order_id):
    order = db.get_order(order_id)
    if order is None or (order.user_id != g.user.id and not g.user.is_admin):
        abort(403)
    return jsonify(order)
```

**Checklist**
- [ ] Every sensitive handler has explicit auth + authorization.
- [ ] Ownership is enforced at the query layer or immediately after.
- [ ] Admin-only functions check role, not presence of a token.
- [ ] Access denials are logged with user id and resource id.

---

## A02: Cryptographic Failures

Sensitive data transmitted or stored without appropriate protection.

**Detection signals**
- Plaintext secrets in source (`api_key = "sk-..."`, `password =`).
- Weak hashes for passwords (`md5`, `sha1`, unsalted `sha256`). Only
  `bcrypt`, `scrypt`, `argon2`, or `pbkdf2` with an appropriate cost
  factor belong here.
- DIY crypto or ECB-mode AES (`AES.new(key, AES.MODE_ECB)`). Look for
  GCM or authenticated modes; ECB leaks patterns.
- `http://` URLs for anything authenticated, or `verify=False` on TLS
  clients.
- Keys derived from passwords with a single hash iteration.
- Secrets logged (`logger.info(f"token={token}")`).

**Mitigations**
- Passwords: `bcrypt` / `argon2id`. Never store reversible.
- Symmetric encryption: AES-256-GCM, with random IV per message.
- Secrets from env vars, vault, or KMS. Never in source.
- TLS 1.2+ everywhere, including service-to-service.
- Mask sensitive fields in logs; implement log filters that redact
  patterns like `Bearer [A-Za-z0-9._\-]+`.

**Code example**
```javascript
// VULNERABLE
const bcrypt = require('bcrypt');
const hash = crypto.createHash('md5').update(password).digest('hex');

// SECURE
const hash = await bcrypt.hash(password, 12);
const ok = await bcrypt.compare(candidate, hash);
```

**Checklist**
- [ ] Password hashes use bcrypt/argon2 with cost ≥ 10/12.
- [ ] No secrets in source or CI config.
- [ ] TLS enforced everywhere; no `verify=False` in production.
- [ ] Encryption uses an authenticated mode (GCM/CCM/ChaCha20-Poly1305).
- [ ] Logs pass through a redactor that removes tokens/keys/PANs.

---

## A03: Injection

SQL, NoSQL, command, LDAP, XPath, template, and header injection.
Whenever untrusted input reaches a parser, treat it as a possible sink.

**Detection signals**
- String-built SQL: `f"SELECT ... WHERE id = {id}"` or `query + userInput`.
- `exec`, `eval`, `subprocess.Popen(..., shell=True)`, `os.system` with
  arguments built from input.
- `innerHTML = …`, `document.write(...)`, `$("<div>" + x + "</div>")`
  (see also A03 → XSS subset, historically A07 in earlier editions).
- Template engines rendered with user-controlled strings (`render_template_string(x)`
  where `x` comes from a request) — Jinja/EJS/Handlebars SSTI.
- MongoDB queries built from raw request JSON without sanitizing
  `$`-prefixed operators.

**Mitigations**
- Parameterized queries / prepared statements. Every language has them.
- For shell, pass argv arrays, never a shell string: `subprocess.run(["tar", ...])`.
- Render HTML through an encoder (`escape`, `htmlspecialchars`) or a
  framework that auto-escapes (React JSX, Jinja2 autoescape).
- Validate input with a positive allowlist where possible — "numeric, 1–8
  digits" is better than "no semicolons".

**Code example**
```python
# VULNERABLE
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")

# SECURE
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```

**Checklist**
- [ ] No SQL built from string concatenation or f-strings.
- [ ] No `shell=True` on subprocess with untrusted input.
- [ ] Template rendering is auto-escaped or inputs are explicitly
      escaped.
- [ ] Input validated with allowlists at the boundary.

---

## A04: Insecure Design

A flaw in the design, not the implementation. You can't linter-fix this
— you have to think about it.

**Detection signals**
- Password reset flows that reveal whether an email is registered.
- Rate limits that only protect against accidents, not attackers
  (per-IP limit on a flow attackers would distribute).
- Trust boundaries that aren't drawn at all — e.g., a SPA backend that
  trusts a cookie the SPA itself sets.
- Single-factor auth for sensitive financial or admin actions.
- "Security by obscurity": relying on unguessable URLs rather than auth.

**Mitigations**
- Threat-model new features before they ship. Ask: who can call this?
  What happens when they lie about who they are?
- Adopt known-good patterns (OWASP ASVS, OAuth 2.1) rather than invent.
- Design for misuse: for every "user does X" flow, consider the
  "attacker does X at scale" version.

**Checklist**
- [ ] Threat model exists for the feature and names the adversaries.
- [ ] Sensitive actions require step-up auth.
- [ ] Rate limits consider distributed abuse, not just per-IP.
- [ ] Error responses don't leak existence of accounts/resources.

---

## A05: Security Misconfiguration

Defaults that were safe in dev and got shipped to production.

**Detection signals**
- `DEBUG = True`, `app.debug = True`, `NODE_ENV !== 'production'`.
- Stack traces or framework pages returned to clients on error.
- Default credentials (`admin` / `admin`) still present.
- Missing security headers: no `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options` / CSP `frame-ancestors`, `Referrer-Policy`.
- Overly permissive CORS: `Access-Control-Allow-Origin: *` combined
  with `Access-Control-Allow-Credentials: true`.
- Cloud buckets, message queues, admin consoles with public ACLs.
- `X-Powered-By`, `Server:`, framework version headers leaking stack.

**Mitigations**
- Use `helmet` (Express), `SecureHeaders` middleware (Python), or the
  framework's production preset.
- Centralize error handling; return a generic error to clients and log
  the stack internally.
- Pin CORS origins to an allowlist; never pair `*` with credentials.
- Infrastructure-as-code linters (`trivy config`, `checkov`,
  `kube-linter`) on every PR.

**Code example**
```python
# VULNERABLE
app.debug = True
app.config["SECRET_KEY"] = "dev"

# SECURE
app.debug = False
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # fail fast if unset
app.after_request(lambda r: (r.headers.update({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
}), r)[1])
```

**Checklist**
- [ ] Debug flags off; generic error page returned to clients.
- [ ] Defaults rotated; no `admin/admin`-style credentials.
- [ ] Security headers set on every response.
- [ ] CORS uses a specific origin allowlist.
- [ ] IaC scanner runs on every PR.

---

## A06: Vulnerable & Outdated Components

Using a dependency with a known vulnerability, or a version so old
that it no longer receives patches.

**Detection signals**
- `package.json`, `requirements.txt`, `pom.xml`, `go.mod` with versions
  you can google and find CVEs on. Unpinned ranges (`^1.2.3`, `~1.2`)
  that have silently moved to a vulnerable release.
- No SCA / dependency scanning in CI. `npm audit`, `pip-audit`,
  `cargo audit`, GitHub Dependabot, Snyk, Trivy.
- Abandoned packages (last publish > 2 years on a security-sensitive
  library).
- Custom forks of upstream projects that don't track the upstream
  security feed.

**Mitigations**
- SCA in CI: `npm audit`, `pip-audit`, `trivy`, Dependabot. Break the
  build on criticals; open issues on the rest.
- Pin by lockfile (`package-lock.json`, `poetry.lock`, `Pipfile.lock`);
  upgrade deliberately, not implicitly.
- Remove unused dependencies — they all count as attack surface.
- Track upstream security feeds for anything embedded in your product.

**Checklist**
- [ ] SCA scanner runs in CI and blocks on critical findings.
- [ ] Lockfile is committed and up to date.
- [ ] Unused dependencies removed from manifests.
- [ ] Team subscribes to security advisories for core frameworks.

---

## A07: Identification & Authentication Failures

Weaknesses in proving who the user is.

**Detection signals**
- Custom auth code where a library would do. 90% of DIY auth has bugs.
- No rate limiting on login, password reset, or MFA verification.
- Weak password policies (no min length, no breached-password check).
- Predictable session IDs; tokens that don't expire or aren't
  invalidated on logout.
- Password reset that accepts short, non-expiring tokens, or reveals
  whether the email existed.
- JWT tokens with `alg: none`, unverified signatures, or secrets
  committed to git.

**Mitigations**
- Use well-reviewed auth: Passport, Devise, django.contrib.auth,
  NextAuth, Auth0/Okta/Ory/Supabase. Never roll your own token format.
- Rate-limit login + reset + MFA; lock accounts after repeated failures.
- Enforce password strength (length, breach check via HIBP API, not
  complexity rules).
- MFA: TOTP or WebAuthn, gated on sensitive actions.
- Session tokens: ≥128 bits of entropy, HttpOnly + Secure cookies,
  regenerate on login, invalidate on logout and password change.

**Code example**
```javascript
// VULNERABLE
const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64'));
const userId = payload.user_id;  // never verified!

// SECURE
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],   // explicit, defeats alg:none tricks
  issuer: 'api.example.com',
  audience: 'web',
});
```

**Checklist**
- [ ] Auth via a vetted library, not hand-rolled.
- [ ] Login, reset, and MFA endpoints rate-limited.
- [ ] Passwords hashed with bcrypt/argon2 and checked against breached
      lists.
- [ ] JWTs verified with an explicit algorithm allowlist.
- [ ] Sessions invalidated on logout and password change.

---

## A08: Software & Data Integrity Failures

Code, updates, and data consumed without integrity checks.

**Detection signals**
- `pickle.loads`, `yaml.load` (without `SafeLoader`), Java
  `ObjectInputStream`, PHP `unserialize` on untrusted input.
- Auto-updaters that fetch code from the network without signature
  verification.
- CI/CD pipelines that install from the public internet without lock
  files, pin, or SHA check.
- CDN / script tags loaded without Subresource Integrity (`integrity=`).
- Webhooks accepted without signature verification.

**Mitigations**
- Prefer JSON (or a schema-validated format) over native serialization.
- Sign artifacts; verify signatures before installation
  (Sigstore/cosign for containers, Sigstore for packages).
- Pin dependencies by hash where the ecosystem supports it
  (`pip install --require-hashes`, `npm ci` with lockfile).
- Verify webhook signatures using constant-time comparison.

**Checklist**
- [ ] No unsafe deserialization of user-supplied data.
- [ ] Artifacts signed; signatures verified in deployment.
- [ ] Dependencies pinned by version + hash.
- [ ] Webhook handlers verify signatures with a constant-time compare.

---

## A09: Security Logging & Monitoring Failures

Not logging the right things, or not noticing when something's wrong.

**Detection signals**
- No logs around auth success/failure, privilege changes, admin actions,
  data exports.
- Logs contain secrets (tokens, PANs, passwords).
- No centralized log aggregation; logs on the box that got owned.
- Alerts trigger only on infra (CPU/disk), not on security events.

**Mitigations**
- Log auth events, access denials, role/permission changes, configuration
  changes, and significant data exports. Include user id, source IP,
  user agent, request id.
- Redact secrets in a log filter before they reach the sink.
- Ship logs off-box to a SIEM or log service; retain per policy.
- Alert on: impossible travel, brute-force patterns, sudden permission
  grant, mass export, account takeover indicators.

**Checklist**
- [ ] Security events logged with correlation ids and user context.
- [ ] Logs centralized and retained; the host can't silence them.
- [ ] Redaction filter prevents secrets from entering logs.
- [ ] Alerts defined for the top 5 abuse patterns for your app.

---

## A10: Server-Side Request Forgery (SSRF)

The app fetches a URL the attacker controls, from a network the
attacker can't reach directly.

**Detection signals**
- Handlers that accept URLs (`picture_url`, `webhook`, `import_from`,
  `callback`) and pass them to `fetch`, `requests`, `axios`, `http.get`,
  a headless browser, or an image processor.
- Parsing with string operations (`url.startswith("https://")`) rather
  than a real URL parser.
- Clients with `allow_redirects=True` / `followRedirect: true`.
- No network egress controls: the app can reach `169.254.169.254`,
  `10.0.0.0/8`, `127.0.0.1`, `::1`.

**Mitigations**
- Parse with a real library (`urllib.parse`, `new URL()`).
- Allowlist schemes, hosts, and ports. Resolve the hostname and reject
  private/loopback/link-local IPs *after* resolution (to defeat DNS
  rebinding).
- Disable redirects on user-supplied fetches; if you must follow,
  re-validate the target.
- Block egress to cloud metadata and internal ranges at the network
  layer, not just in app code. This is the single most effective SSRF
  defense.

**Code example**
```python
# VULNERABLE
import requests
def fetch_avatar(url):
    return requests.get(url).content

# SECURE
import ipaddress, socket
from urllib.parse import urlparse

ALLOW_SCHEMES = {"https"}
ALLOW_HOSTS = {"images.example.com", "cdn.partner.com"}

def fetch_avatar(url):
    u = urlparse(url)
    if u.scheme not in ALLOW_SCHEMES or u.hostname not in ALLOW_HOSTS:
        raise ValueError("disallowed URL")
    for fam, _, _, _, sa in socket.getaddrinfo(u.hostname, None):
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("internal address")
    return requests.get(url, allow_redirects=False, timeout=5).content
```

**Checklist**
- [ ] URLs parsed with a library, not regex/startswith.
- [ ] Scheme + host allowlist enforced.
- [ ] Resolved IP rejected if in private/loopback/link-local ranges.
- [ ] Redirects off by default.
- [ ] Egress firewall blocks metadata endpoints and internal ranges.
