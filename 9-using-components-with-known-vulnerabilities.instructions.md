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

## Special cases

- Transitive dependencies: a secure top‑level package may depend on an
  outdated library.
- Frontend packages: unpatched JavaScript libs served to clients can lead
  to XSS or other issues.
- Container images and OS packages also count; run `trivy` or `clair`
  scans.

## Quick checklist

- [ ] Are all core dependencies at their latest patched versions?
- [ ] Does the project include any abandoned or forked libraries?
- [ ] Is there an automated scanning process in CI?
- [ ] Have transitive dependencies been reviewed?

> The model should remind developers that security is a continuous
> process; simply installing a dependency once isn’t enough. Encourage
> subscribing to security mailing lists or using GitHub alerts.