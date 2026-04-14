# OWASP API Security Top 10 (2023)

Load this reference whenever you're reviewing REST, GraphQL, or RPC
code. APIs share categories with the web Top 10 but emphasize different
failure modes: object-level authorization, property-level authorization,
rate/resource consumption, and inter-API trust.

**Source:** OWASP API Security Project 2023 edition —
<https://owasp.org/API-Security/editions/2023/en/0x11-t10/>.

## How to read this file

Each of the ten items has: a one-paragraph summary, detection signals
(what to look for in code or config), mitigations (with concrete
snippets), and a short checklist. When you flag a finding, quote both
the category code (`API1:2023`) and the descriptive name.

---

## API1:2023 — Broken Object-Level Authorization (BOLA)

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>

The #1 API vulnerability: a handler looks up an object by ID from the
request and returns or modifies it without verifying the caller's
relationship to that object.

**Detection signals**
- Handlers with `req.params.id` / `req.body.id` reaching the database
  in a plain `WHERE id = ?` query — no `user_id` clause.
- Sequential or guessable IDs in URLs (`/orders/1001`, `/orders/1002`).
- No ownership check after the lookup — the code returns whatever the
  query found.
- Admin checks based only on "is authenticated?" with no per-object
  policy.

**Mitigations**
```javascript
// SECURE: ownership enforced at the query layer
app.get('/api/orders/:id', auth, (req, res) => {
  const order = db.oneOrNone(
    'SELECT * FROM orders WHERE id = $1 AND user_id = $2',
    [req.params.id, req.user.id]
  );
  if (!order) return res.status(404).end();
  res.json(order);
});
```
- Prefer query-level enforcement; fall back to a policy check after
  the lookup. Never both absent.
- Use opaque IDs (UUIDv4, signed tokens) to make enumeration noisier,
  but never rely on them for authorization.
- Log every 403/404 from per-object handlers and alert on rapid
  sequential patterns.

**Checklist**
- [ ] Every object-fetching handler enforces ownership in the query or
      post-query policy.
- [ ] 403/404 responses on per-object endpoints are logged with user id
      and object id.
- [ ] Integration tests assert user A cannot read user B's objects.

---

## API2:2023 — Broken Authentication

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/>

Covers weak credential handling, broken token validation, and flaws in
authentication flows (password reset, MFA bypass, OAuth callback handling).

**Detection signals**
- JWT decoded (`base64`, `atob`) but never verified
  (`jwt.verify(...)` missing).
- JWTs accepted with `alg: none` or without algorithm pinning.
- Password reset tokens with long TTL, or with no per-use invalidation.
- Login endpoint without rate limit, account lockout, or CAPTCHA after
  repeated failures.
- OAuth callbacks that don't validate `state` / PKCE, or accept
  arbitrary `redirect_uri`.

**Mitigations**
```javascript
const decoded = jwt.verify(token, SECRET, {
  algorithms: ['HS256'],                // pin algorithm
  issuer: 'api.example.com',
  audience: 'web',
  maxAge: '15m',
});
```
- Pin the JWT algorithm; reject `alg: none`. Use asymmetric keys when a
  service verifies tokens it didn't sign.
- Rate-limit and lock out on login/MFA/reset (per-user + per-IP).
- Use PKCE for OAuth in browser and mobile clients; validate `state`
  and restrict `redirect_uri` to an exact allowlist.
- Invalidate reset tokens on use and after a short TTL (≤ 15 min).

**Checklist**
- [ ] All token verification has an explicit algorithm pin.
- [ ] Login, reset, and MFA endpoints rate-limited.
- [ ] Password reset tokens single-use with ≤ 15m TTL.
- [ ] OAuth `state` + PKCE enforced; `redirect_uri` is an exact match.

---

## API3:2023 — Broken Object Property-Level Authorization

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>

Authorization was right at the object level (user can access *this*
order), but the API exposes or accepts fields the user shouldn't
control (price, role, internal flags). Covers both read-side leaks
("mass assignment" in reverse) and write-side (classic mass assignment).

**Detection signals**
- `res.json(obj)` returning the whole row — `password_hash`,
  `internal_notes`, `credit_limit` — without a field filter.
- `Object.assign(entity, req.body)` or ORM `.update(request.json())` —
  any field the attacker names becomes part of the update.
- GraphQL types exposing fields the client-side UI never reads.
- ORM `select *` used in response serializers.

**Mitigations**
```javascript
// SECURE: explicit allowlist per role
const allowed = {
  user:  ['id','name','email','created_at'],
  admin: ['id','name','email','role','created_at','last_login'],
};
function pick(o, keys) {
  return Object.fromEntries(keys.filter(k => k in o).map(k => [k, o[k]]));
}
res.json(pick(user, allowed[req.user.role]));
```
- Never return raw ORM objects. Define explicit response schemas
  (pydantic, Marshmallow, Zod, Joi, DTO classes).
- On write, accept only a named set of fields. `update(..., fields=["name","email"])`.
- GraphQL: use field-level authorization directives; don't rely on
  resolver-only checks.

**Checklist**
- [ ] Response objects are filtered through an explicit schema.
- [ ] Writes accept only a named allowlist of fields per role.
- [ ] Privileged fields (role, balance) cannot be set via normal write
      endpoints.

---

## API4:2023 — Unrestricted Resource Consumption

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/>

The API can be coaxed into doing expensive work without limits —
causing denial of service, unbounded cloud spend, or amplified attacks.

**Detection signals**
- No rate limiting, or only a global per-IP limit that doesn't scale
  to authenticated users.
- List endpoints with no `limit` cap: `?limit=100000` silently honored.
- File upload handlers without size limits.
- Email/SMS send endpoints with no quota.
- Handlers that invoke third-party APIs charged per call (SMS, email,
  LLM) with no user budget.
- Unbounded regex, recursive JSON/XML parsing, ReDoS patterns.

**Mitigations**
```javascript
const rateLimit = require('express-rate-limit');
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.user?.id ?? req.ip,
}));
app.use(express.json({ limit: '1mb' }));
app.get('/api/items', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  ...
});
```
- Per-user and per-flow rate limits; tighter limits on expensive flows
  (`/search`, `/export`, `/ai/complete`).
- Cap result sizes (`LIMIT` in SQL; paginate defaults + max).
- Enforce request body size limits at the framework layer.
- Budget per user / per tenant for paid third-party calls; circuit-break
  on overruns.

**Checklist**
- [ ] Per-user rate limits on all endpoints.
- [ ] Request body size capped.
- [ ] List endpoints enforce a max `limit`.
- [ ] Per-user budget for paid external calls.

---

## API5:2023 — Broken Function-Level Authorization

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>

An authenticated non-admin user can invoke an admin-only endpoint
because authorization was enforced only in the UI, not the API.

**Detection signals**
- Admin endpoints under a distinct URL prefix (`/admin/...`,
  `/internal/...`) with no role check in middleware.
- Role check done once in a parent controller but not re-checked in
  child handlers.
- `DELETE`/`PATCH`/`PUT` methods exposed on handlers that only expose
  `GET` in the UI.
- Hidden or undocumented endpoints used by internal tooling accessible
  with any valid token.

**Mitigations**
```javascript
function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.user?.role)
      ? next()
      : res.status(403).json({ error: 'forbidden' });
}
app.delete('/api/users/:id', auth, requireRole('admin'), handler);
```
- Declarative role/permission middleware on every admin route.
- Deny by default at the router level; allow explicitly.
- Test matrix: for each endpoint, assert every non-authorized role
  gets 403.

**Checklist**
- [ ] Admin endpoints pass through a role-check middleware.
- [ ] Tests cover non-authorized access for every privileged endpoint.
- [ ] No "hidden" internal endpoints relying on obscurity.

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/>

High-value flows (purchase, reservation, signup, referral credit,
comment creation) are exposed without friction that stops automation —
attacker scripts the flow to harm the business: scalp stock, block
reservations, spam, or farm incentives. Unlike most Top 10 items, the
technical response is often correct; the harm is economic.

**Detection signals**
- `/checkout`, `/purchase`, `/reserve`, `/book`, `/invite`, `/redeem`,
  `/signup`, `/comments` handlers with no CAPTCHA, device
  fingerprint, or per-account quota beyond a generic rate limit.
- Referral or loyalty code paths that credit a wallet at signup,
  before any anti-fraud verification.
- Handlers that complete end-to-end in under 1s with no debounce —
  OWASP flags sub-second "add to cart → complete purchase" as a
  non-human pattern.
- No `User-Agent` / `Accept-Language` inspection; traffic from
  headless clients accepted without challenge.

**Mitigations**
```javascript
const purchaseLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,        // 1 hour
  max: 5,                           // 5 purchases per user per hour
  keyGenerator: (req) => req.user.id,
});
app.post('/api/checkout', auth, purchaseLimiter, checkoutHandler);
```
- Apply per-flow budgets keyed on the authenticated user, not just IP.
- Human-verification challenge (CAPTCHA, device attestation) on
  scriptable sensitive flows.
- Delay referral credit until a verified payment event, not signup.
- Timing gate: reject checkout if `now - viewedAt < 2s`.
- Block known Tor exits and datacenter IPs on B2C flows expecting
  residential traffic.

**Checklist**
- [ ] Every money/inventory/reputation flow has a per-user quota.
- [ ] Referral/loyalty credit follows a verified event, not signup.
- [ ] CAPTCHA or device attestation on checkout and bulk invite.
- [ ] Sub-second state-transition timing is logged and alerted on.

---

## API7:2023 — Server-Side Request Forgery

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/>

The API fetches a remote resource using a URL derived from the client
(directly or indirectly) and fails to validate it, letting an attacker
coerce the server into hitting internal addresses, cloud metadata, or
arbitrary hosts.

**Detection signals**
- Handlers that take a URL field (`picture_url`, `webhook_url`,
  `callback`, `source`, `import_from`) and pass it into `fetch`,
  `requests`, `axios`, or a headless browser.
- URL parsing by string match (`url.startswith("https://")`) —
  bypassable with `https://evil@internal`, IPv6 brackets, or
  userinfo tricks.
- HTTP clients with `allow_redirects=True` / `follow: true` on
  user-supplied URLs.
- Raw upstream response bodies/status returned to the client — enables
  the port-scan variant of SSRF.
- No egress firewall; application can reach `169.254.169.254`,
  `127.0.0.0/8`, `10.0.0.0/8`, `::1`, or internal service DNS.
- Blocklist-only validation (`"localhost" in url`) — misses `0.0.0.0`,
  decimal-encoded IPs, DNS rebinding, IPv6 loopback.

**Mitigations**
```python
from urllib.parse import urlparse
import ipaddress, socket

ALLOWED_HOSTS = {"images.example.com", "cdn.partner.com"}
ALLOWED_SCHEMES = {"https"}

def safe_target(raw_url: str) -> str:
    u = urlparse(raw_url)
    if u.scheme not in ALLOWED_SCHEMES: raise ValueError("scheme")
    if u.hostname not in ALLOWED_HOSTS:  raise ValueError("host")
    for fam, _, _, _, sa in socket.getaddrinfo(u.hostname, None):
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("internal address")
    return u.geturl()
```
- Parse with a real library, validate scheme + host on an allowlist,
  resolve the hostname and reject private/loopback/link-local IPs
  (defeats DNS rebinding).
- Disable redirects or re-validate after each hop.
- Isolate the fetcher in a network segment that can reach the public
  internet but not the VPC metadata endpoint or internal services.
- Return a normalized result to the caller — never the upstream body,
  status, or timing.

**Checklist**
- [ ] URLs parsed with a library, not regex/startswith.
- [ ] Scheme, host, and port on an allowlist.
- [ ] Resolved IPs checked against private ranges before the request.
- [ ] Redirects disabled or re-validated.
- [ ] Egress firewall blocks `169.254.169.254/32` and RFC1918 ranges.

---

## API8:2023 — Security Misconfiguration

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/>

Insecure defaults, missing hardening, or inconsistent parsing across
proxies and backends. Everything from debug flags to HTTP request
smuggling.

**Detection signals**
- Stack traces, debug pages, or `X-Powered-By` headers in production
  responses.
- Missing `Cache-Control: no-store` on responses carrying per-user
  data (CDN cache collision = data leak).
- CORS set to `Access-Control-Allow-Origin: *` combined with
  `Access-Control-Allow-Credentials: true`, or reflecting any `Origin`
  without allowlist.
- Routes responding to unintended verbs (`TRACE`, stray `PUT`/`DELETE`).
- Logging libraries or template engines with dangerous defaults
  (Log4Shell-class JNDI lookup in access logs).
- TLS missing on internal hops — OWASP requires TLS end-to-end.
- Divergent request parsing between proxy and backend (header folding,
  `Transfer-Encoding` vs `Content-Length` — CWE-444 smuggling).
- Cloud buckets / queues with permissive ACLs referenced from the API.

**Mitigations**
```javascript
const helmet = require('helmet');
const cors = require('cors');
app.use(helmet());
app.use(cors({
  origin: ['https://app.example.com'],
  credentials: true,
  methods: ['GET','POST','PUT','DELETE'],
}));
app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
```
- Pin security headers via `helmet` / equivalent; set `Cache-Control:
  no-store` on authenticated responses.
- CORS origin is an explicit allowlist; never combine `*` with
  credentials.
- Return 405 on unintended verbs; central error handler returns a
  generic response (log the stack internally).
- Run `trivy config`, `checkov`, `kube-linter` in CI; fail on high
  findings.
- TLS end-to-end, including service-to-service.

**Checklist**
- [ ] No debug / verbose errors in production.
- [ ] `Cache-Control: no-store` on all authenticated responses.
- [ ] CORS allowlist explicit; no `*` + credentials.
- [ ] Unexpected verbs → 405, not autoroute.
- [ ] IaC/dependency scanning runs per PR.

---

## API9:2023 — Improper Inventory Management

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/>

No authoritative, current inventory of API hosts, versions,
environments, and third-party data flows. Old/beta endpoints run
unpatched with weaker controls; sensitive data leaves via unaudited
integrations.

**Detection signals**
- Multiple hostnames serving the same API (`api.`, `beta.api.`,
  `staging.api.`, `v1.api.`) with different ingress controls.
- Route tables with `/v1/`, `/v2/`, `/v3/` and no deprecation header
  or sunset plan.
- OpenAPI/Swagger spec checked in but stale — code has endpoints not
  in spec, or spec endpoints return 404.
- Non-production environments sharing a database with production.
- Third-party integrations (webhooks, OAuth apps, analytics SDKs)
  added ad-hoc with no registry of what data each receives.
- DNS records pointing to hosts whose owner nobody can name.

**Mitigations**
```javascript
const OpenApiValidator = require('express-openapi-validator');
app.use(OpenApiValidator.middleware({
  apiSpec: './openapi.yaml',
  validateRequests: true,
  validateResponses: true,   // rejects undocumented responses
}));
app.use((req, res, next) => {
  res.set('X-API-Version', '2024-03');
  if (req.path.startsWith('/v1/')) {
    res.set('Deprecation', 'true');
    res.set('Sunset', 'Wed, 31 Dec 2025 23:59:59 GMT');
  }
  next();
});
```
- Generate spec from code or validate code against spec in CI; drift
  fails the build.
- Emit version + deprecation headers; track against a central inventory.
- Maintain a registry (env, owner, data classification, partners with
  access); reconcile against DNS / cloud inventory on a schedule.
- Apply identical controls (WAF, rate limit, auth) to beta/staging
  hosts that share a data store with production.

**Checklist**
- [ ] Every API host in a registry with env + owner + data class.
- [ ] OpenAPI spec validated in CI; drift fails the build.
- [ ] Each version has a documented sunset date.
- [ ] Non-prod environments never use unmasked production data.
- [ ] Registry of every third party receiving data, with justification.

---

## API10:2023 — Unsafe Consumption of APIs

**Source:** <https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/>

The API trusts data and behavior from third-party or upstream APIs
more than user input — skipping TLS verification, sanitization,
redirect validation, or timeouts. A compromised or malicious upstream
becomes an injection vector.

**Detection signals**
- HTTP clients to partner APIs with `verify=False` or custom trust
  stores that accept self-signed certs in production.
- Upstream response bodies written straight into SQL, shell, file
  paths, or rendered templates — validation applied to user input is
  skipped on "trusted" partners.
- `allow_redirects=True` on calls carrying sensitive request bodies —
  OWASP's Scenario #2 shows a 308 redirecting PHR data to an attacker.
- No timeout or response-size cap (`requests.get(url)` with no
  `timeout=`).
- Identifiers received from third parties used unescaped (OWASP's
  Scenario #3: a git repo name `'; drop db;--`).
- No circuit breaker on slow/hostile upstreams.

**Mitigations**
```python
import httpx
from pydantic import BaseModel, constr

class EnrichedAddress(BaseModel):
    street: constr(max_length=200)
    city: constr(max_length=100)
    country: constr(pattern=r"^[A-Z]{2}$")

with httpx.Client(timeout=5.0, follow_redirects=False, verify=True) as c:
    r = c.get(f"https://enrich.example.com/{addr_id}")
    r.raise_for_status()
    addr = EnrichedAddress.model_validate(r.json())

cur.execute(
  "INSERT INTO addresses (street, city, country) VALUES (%s, %s, %s)",
  (addr.street, addr.city, addr.country),
)
```
- Schema-validate every upstream response; escape before use.
- Disable redirects or constrain them to an allowlist of partner
  hosts; strip sensitive headers before following.
- Timeout + response-size cap + circuit breaker on every outbound
  integration (`opossum`, `resilience4j`, `pybreaker`).
- TLS verification on; never `verify=False` in production.
- Partner security posture reviewed at onboarding; record in the API9
  inventory.

**Checklist**
- [ ] All upstream calls verify TLS; no `verify=False`.
- [ ] Redirects off by default or restricted to an allowlist.
- [ ] Responses schema-validated before use.
- [ ] Timeouts, size caps, circuit breakers on every outbound call.
- [ ] Upstream values escaped with the same rigor as user input before
      reaching SQL/shell/filesystem/templates.
