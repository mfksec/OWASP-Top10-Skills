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

## Examples

**Insecure: storing API key in code (Python):**
```python
api_key = "sk-abc123xyz789"
response = requests.get("https://api.example.com", headers={"Authorization": api_key})
```

**Secure: storing API key in environment variable (Python):**
```python
import os
api_key = os.getenv("API_KEY")
if not api_key:
  raise ValueError("API_KEY not set")
response = requests.get("https://api.example.com", headers={"Authorization": api_key})
```

**Insecure: logging sensitive data (Java):**
```java
logger.info("User login: username=" + username + ", password=" + password);
```

**Secure: masking sensitive data in logs (Java):**
```java
logger.info("User login: username=" + username + ", password=****");
```

**Insecure: transmitting over HTTP:**
```html
<form action="http://example.com/login" method="POST">
  <input type="password" name="pwd">  <!-- Sent in cleartext! -->
</form>
```

**Secure: enforcing HTTPS and headers (Node.js):**
```javascript
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (req.protocol !== 'https') {
    return res.redirect(301, 'https://' + req.host + req.url);
  }
  next();
});
```

## Edge cases

- Data exposure through `Referer` headers when linking to third-party
  sites.
- Response bodies accidentally including sensitive tokens when
  pagination occurs (e.g., `pageToken` visible in JSON).
- In mobile apps, storing credentials in insecure storage (plist filed,
  SharedPreferences without encryption).

## Prevention Checklist

- [ ] HTTPS/TLS is enforced site-wide; HTTP traffic is redirected.
- [ ] Encryption keys are stored securely (secrets manager, HSM, not in code).
- [ ] Data at rest is encrypted with AES-256 or equivalent.
- [ ] Sensitive values never appear in logs, error messages, or source code.
- [ ] Security headers are configured: `Strict-Transport-Security`, `Content-Security-Policy`.
- [ ] Database access is restricted to least-privilege accounts.

