# 3. Sensitive Data Exposure

Applications and APIs that do not properly protect sensitive information
— such as financial records, health data, or personal details — allow
attackers to access or transmit it insecurely.

## Things to watch for

- Transmitting secrets (passwords, tokens, keys) in cleartext over HTTP.
- Logging sensitive values (credit card numbers, social security
  numbers).
- Storing unencrypted data at rest or using weak encryption (DES,
  ECB mode).
- Failure to enforce `Strict-Transport-Security`, `Content-Security-Policy`,
  or other headers that mitigate data leaks in transit.
- Predictable or public URLs serving private files (e.g., `GET
  /files/transaction_12345.pdf`).

## Defensive measures

1. **Always use HTTPS/TLS** and redirect HTTP requests to HTTPS.
2. **Encrypt data at rest** with modern algorithms and proper key
   management.
3. **Mask or omit sensitive fields** from logs and error messages.
4. **Use the principle of least privilege** for database access.
5. **Avoid storing secrets in code**; use environment variables or a
   secrets manager.
6. **Apply robust input validation** on uploads to prevent data
   exfiltration via metadata or hidden fields.

## Edge cases

- Data exposure through `Referer` headers when linking to third-party
  sites.
- Response bodies accidentally including sensitive tokens when
  pagination occurs (e.g., `pageToken` visible in JSON).
- In mobile apps, storing credentials in insecure storage (plist filed,
  SharedPreferences without encryption).

## Quick checklist

- [ ] Is TLS enforced site‑wide?
- [ ] Are sensitive values excluded from logs and stack traces?
- [ ] Are encryption keys rotated and protected?
- [ ] Does any URL leak private information?
- [ ] Are appropriate security headers present?

> The model should point developers to OWASP’s [Cryptographic
> Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
> when deeper guidance is necessary.