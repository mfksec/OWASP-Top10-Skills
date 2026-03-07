# 6. Security Misconfiguration

Security misconfigurations arise when systems, frameworks, or
infrastructure components are left in insecure states.

## Symptoms to recognize

- Default credentials still in use (`admin:admin`, etc.).
- Debug endpoints (e.g., `/debug`, `/actuator`) exposed in production.
- Unnecessary services running or ports open (FTP, SSH from web
  servers).
- Insecure HTTP headers missing (`X-Frame-Options`, `X-XSS-Protection`,
  etc.).
- Overly verbose error messages revealing stack traces or SQL queries.

## Remediation guidance

1. **Harden configurations** before deployment: disable unused
   features, remove demo code, and rotate default passwords.
2. **Use environment-specific settings** (development vs production).
3. **Automate configuration management** with tools like Ansible,
   Terraform, or Docker to minimize manual mistakes.
4. **Apply security headers** and configure them correctly:
   - `Content-Security-Policy`
   - `Strict-Transport-Security`
   - `X-Content-Type-Options: nosniff`
5. **Validate API and admin routes** are not accessible to unauthenticated
   users.
6. **Keep platform and dependencies patched**; disable version
   disclosure (e.g., `Server` header showing `nginx/1.18`).

## Examples

**Insecure: debug mode enabled in production (Flask):**
```python
app = Flask(__name__)
app.debug = True  // Exposes stack traces, REPL access!
```

**Secure: debug mode disabled in production (Flask):**
```python
app = Flask(__name__)
app.debug = False  // or use environment variable
if not os.getenv('FLASK_ENV') == 'development':
  app.debug = False
```

**Insecure: overpermissive CORS (Node.js/Express):**
```javascript
app.use(cors({ origin: '*' }));  // Allows any origin
```

**Secure: restrictive CORS (Node.js/Express):**
```javascript
app.use(cors({ origin: 'https://myapp.com', credentials: true }));
```

**Insecure: default credentials in database:**
```bash
mysql -u root -p  // Password: root (never changed!)
```

**Secure: strong, unique credentials:**
```bash
mysql -u dbadmin -p$(openssl rand -base64 32)  // Random password
```

**Insecure: version disclosure (Apache):**
```
Server: Apache/2.4.29 (Ubuntu)
```

**Secure: hide version (Apache config):**
```apache
ServerTokens Prod
ServerSignature Off
```

## Edge cases

- Cloud metadata services accessible from application code (SSRF risk).
- Over-permissive CORS policies (`Access-Control-Allow-Origin: *`).
- Temporary debug flags left enabled (`app.debug = true`).

## Prevention Checklist

- [ ] All default credentials have been changed to strong, unique values.
- [ ] Debug mode and development endpoints are disabled in production.
- [ ] Security headers are configured: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
- [ ] CORS is explicitly configured with trusted origins only.
- [ ] Unnecessary services, ports, and features are disabled.
- [ ] Server version information is hidden.
- [ ] All software and dependencies are up to date and regularly patched.
- [ ] Access to cloud metadata endpoints is blocked.

