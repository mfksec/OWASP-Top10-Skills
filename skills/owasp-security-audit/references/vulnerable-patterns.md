# Vulnerable / Secure Patterns — Quick Lookup

An index of paired vulnerable-and-secure code snippets, organized by
**language** and **OWASP category**. Use this when you've identified
a finding and want a concrete fix template in the user's language.

Full-length example files live in `../assets/examples/`. Each is a
side-by-side vulnerable / secure implementation of one category; open
the full file when you need end-to-end context (imports, routing,
middleware wiring). The snippets here are minimal extracts for quick
reference.

## Index

| Language   | Category                   | Full example file                          |
| ---------- | -------------------------- | ------------------------------------------ |
| Python     | A01 Broken Access Control  | `assets/examples/broken-access-control.py` |
| JavaScript | A02 Cryptographic Failures | `assets/examples/cryptographic-failures.js` |
| JavaScript | A03 Injection (SQL)        | `assets/examples/injection.js`              |
| Python     | A05 Security Misconfig     | `assets/examples/security-misconfiguration.py` |
| HTML/JS    | A03 XSS                    | `assets/examples/xss.html`                  |
| Python     | A09 Logging Failures       | `assets/examples/logging-monitoring-failures.py` |
| JavaScript | API1/API2/API5 auth bypass | `assets/examples/api-auth-bypass.js`        |
| YAML       | K01/K03/K08 K8s            | `assets/examples/k8s-rbac.yaml`             |
| Python     | LLM01/LLM05/LLM06/LLM10    | `assets/examples/prompt-injection.txt`      |

---

## A01 — Broken Access Control

### Python / Flask — ownership check

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

### JavaScript / Express — query-layer enforcement

```javascript
// VULNERABLE
app.get('/api/orders/:id', (req, res) => {
  const order = db.query('SELECT * FROM orders WHERE id = ?', req.params.id);
  res.json(order);
});

// SECURE
app.get('/api/orders/:id', auth, (req, res) => {
  const order = db.query(
    'SELECT * FROM orders WHERE id = $1 AND user_id = $2',
    [req.params.id, req.user.id]
  );
  if (!order) return res.status(404).end();
  res.json(order);
});
```

### JavaScript / Express — role middleware

```javascript
function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.user?.role)
      ? next()
      : res.status(403).json({ error: 'forbidden' });
}
app.delete('/api/users/:id', auth, requireRole('admin'), handler);
```

---

## A02 — Cryptographic Failures

### Python — password hashing

```python
# VULNERABLE
import hashlib
stored = hashlib.md5(password.encode()).hexdigest()

# SECURE
import bcrypt
stored = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
ok = bcrypt.checkpw(candidate.encode(), stored)
```

### JavaScript / Node — AES-GCM

```javascript
// VULNERABLE — AES-CBC with no MAC (plus weak key derivation)
const cipher = crypto.createCipher('aes-256-cbc', password);

// SECURE — AES-256-GCM with random IV and authenticated tag
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();
// store iv + ct + tag
```

### Python — secret from env

```python
# VULNERABLE
API_KEY = "sk-abc123..."

# SECURE
import os
try:
    API_KEY = os.environ["API_KEY"]
except KeyError:
    raise RuntimeError("API_KEY not set — refusing to start")
```

---

## A03 — Injection

### Python — parameterized SQL

```python
# VULNERABLE
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")

# SECURE
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```

### Python — subprocess without shell

```python
# VULNERABLE
import os
os.system(f"tar -czf {name} /var/data")

# SECURE
import subprocess
subprocess.run(["tar", "-czf", name, "/var/data"], check=True)
```

### JavaScript / DOM — avoid innerHTML

```javascript
// VULNERABLE
el.innerHTML = `<p>Hello, ${user.name}</p>`;

// SECURE
const p = document.createElement('p');
p.textContent = `Hello, ${user.name}`;
el.replaceChildren(p);
```

### Python — JSON instead of pickle (A08 overlap)

```python
# VULNERABLE
import pickle
obj = pickle.loads(request.data)

# SECURE
import json
obj = json.loads(request.data)  # then validate with pydantic/schema
```

---

## A05 — Security Misconfiguration

### Python / Flask — headers & debug

```python
# VULNERABLE
app.debug = True
app.config["SECRET_KEY"] = "dev"

# SECURE
import os
app.debug = False
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

@app.after_request
def secure_headers(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp
```

### JavaScript / Express — helmet + CORS allowlist

```javascript
const helmet = require('helmet');
const cors = require('cors');
app.use(helmet());
app.use(cors({
  origin: ['https://app.example.com'],
  credentials: true,
}));
```

---

## A07 / API2 — Authentication

### JavaScript — JWT verify with algorithm pin

```javascript
// VULNERABLE
const payload = JSON.parse(
  Buffer.from(token.split('.')[1], 'base64').toString()
);

// SECURE
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],     // explicit; defeats alg:none
  issuer: 'api.example.com',
  audience: 'web',
  maxAge: '15m',
});
```

### Python — rate limit login

```python
from flask_limiter import Limiter
limiter = Limiter(key_func=lambda: request.remote_addr)

@app.post("/login")
@limiter.limit("5 per minute")
def login(): ...
```

---

## A09 — Logging & Monitoring

### Python — structured + redacted

```python
import logging, json, re

SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{20,}|[A-Za-z0-9]{32,})")

def emit(event, **fields):
    payload = {k: SECRET_RE.sub("[REDACTED]", str(v)) for k, v in fields.items()}
    logging.info(json.dumps({"event": event, **payload}))

emit("auth.login.success", user_id=user.id, ip=request.remote_addr)
emit("auth.login.failure", email=email, reason="bad_password",
     ip=request.remote_addr)
```

---

## A10 / API7 — SSRF

```python
# VULNERABLE
import requests
def fetch(url): return requests.get(url).content

# SECURE
import ipaddress, socket, requests
from urllib.parse import urlparse

ALLOW = {"images.example.com", "cdn.partner.com"}

def fetch(url):
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOW:
        raise ValueError("disallowed URL")
    for _, _, _, _, sa in socket.getaddrinfo(u.hostname, None):
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("internal address")
    return requests.get(url, allow_redirects=False, timeout=5).content
```

---

## Kubernetes — hardened Pod + least-priv RBAC

```yaml
# SECURE Pod
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile: { type: RuntimeDefault }
  containers:
  - name: app
    image: registry.example.com/app@sha256:3b6eae...
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: [ALL] }
    resources:
      requests: { memory: 128Mi, cpu: 250m }
      limits:   { memory: 256Mi, cpu: 500m }
---
# Least-privilege Role (single object)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { namespace: payments, name: read-db-creds }
rules:
- apiGroups: [""]
  resources: [secrets]
  resourceNames: [db-creds]
  verbs: [get]
```

---

## LLM — role-separated messages + output filter

```python
# VULNERABLE
prompt = f"System: be helpful.\nUser: {user_input}\nAssistant:"
out = llm.generate(prompt)

# SECURE
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},   # pinned, not editable
    {"role": "user",   "content": user_input},      # validated, bounded length
]
out = llm.chat(messages, max_tokens=500)

# Redact before surfacing
import re
SECRETS = re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
safe = SECRETS.sub("[REDACTED]", out)
```

---

## iOS — Keychain (MASVS-STORAGE)

```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: account,
    kSecValueData as String: secret,
    kSecAttrAccessible as String:
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
]
SecItemDelete(query as CFDictionary)
SecItemAdd(query as CFDictionary, nil)
```

## Android — EncryptedSharedPreferences (MASVS-STORAGE)

```kotlin
val key = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
val prefs = EncryptedSharedPreferences.create(
    "secret_prefs", key, context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
)
```
