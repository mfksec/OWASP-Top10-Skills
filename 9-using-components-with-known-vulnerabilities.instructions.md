# 9. Using Components with Known Vulnerabilities

Applications often rely on open-source libraries or frameworks. When
those components contain security flaws and are not updated, attackers
can take advantage of them.

## Detection clues

- `package.json`, `requirements.txt`, `Gemfile`, etc. listing old
  versions.
- URLs or comments referring to known CVEs.
- The presence of unmaintained or deprecated modules.

## Recommendations

1. **Maintain a dependency inventory** and regularly scan it for
   vulnerabilities using tools like `npm audit`, `Dependabot`,
   `Snyk`, or `OWASP Dependency-Check`.
2. **Update dependencies promptly** when security fixes are released.
3. **Avoid including unnecessary libraries**; remove unused packages.
4. **Isolate critical functions** behind interfaces so updates affect
   fewer areas of the codebase.
5. **Use locked versions** (package lock files), but review and update
   them frequently.
6. **Monitor third-party components** for security advisories specific
   to your platform (e.g., PyPI, Maven Central, npm).

## Examples

**Check for vulnerable dependencies (Node.js):**
```bash
npm audit
```

**Check for vulnerable dependencies (Python):**
```bash
pip install safety
safety check
```

**Outdated package manifest (package.json):**
```json
{
  "dependencies": {
    "lodash": "3.10.0"  // Contains known CVEs!
  }
}
```

**Updated package manifest:**
```json
{
  "dependencies": {
    "lodash": "^4.17.21"  // Patched version
  }
}
```

**Vulnerable Docker image:**
```dockerfile
FROM ubuntu:16.04  // Outdated OS with many CVEs
RUN npm install
```

**Secure Docker image:**
```dockerfile
FROM ubuntu:22.04  // Current LTS
RUN npm install && npm audit fix
```

**CI automation for scanning (GitHub Actions):**
```yaml
name: Security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm audit --audit-level=moderate
      - run: pip install safety && safety check
```

## Special cases

- Transitive dependencies: a secure top-level package may depend on an
  outdated library.
- Frontend packages: unpatched JavaScript libs served to clients can lead
  to XSS or other issues.
- Container images and OS packages also count; run `trivy` or `clair`
  scans.

## Prevention Checklist

- [ ] All dependencies are listed in a lock file (package-lock.json, requirements.lock, etc.).
- [ ] Regular dependency audits are performed using platform-specific tools.
- [ ] Vulnerable dependencies are updated promptly when patches are released.
- [ ] Unused dependencies are removed to reduce the attack surface.
- [ ] Transitive dependencies are reviewed and monitored.
- [ ] CI/CD pipelines include automated dependency scanning.
- [ ] Container base images are frequently updated and scanned.
- [ ] Security advisories and mailing lists are monitored.