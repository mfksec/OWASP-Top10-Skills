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

## Edge cases

- Cloud metadata services accessible from application code (SSRF
  risk).
- Over-permissive CORS policies (`Access-Control-Allow-Origin: *`).
- Temporary debug flags left enabled (`app.debug = true`).

## Quick checklist

- [ ] Are all default credentials changed?
- [ ] Is debugging/logging disabled in production?
- [ ] Are appropriate security headers configured?
- [ ] Are unnecessary services and endpoints removed?
- [ ] Are software versions hidden and up to date?

> The model should recommend using security scanners like
> `Nessus`/`OpenVAS` or cloud provider tools for configuration audits
> but still perform a manual review of settings.