# 2. Broken Authentication and Session Management

When authentication mechanisms are implemented incorrectly, attackers
can compromise passwords, keys, or session tokens, or exploit other
implementation flaws to assume other users’ identities.

## Red flags to spot

- Passwords stored in plaintext or with weak hashing (MD5, SHA1).
- Login logic that doesn’t rate-limit or lock out after repeated
  failures.
- Missing multi-factor authentication for sensitive operations.
- Session IDs that don’t expire or are predictable (e.g., incremental
  numbers in URLs).
- Password reset flows that rely on weak tokens or expose information
  about user existence.

## Best practices

1. **Hash passwords** with a strong algorithm (bcrypt, Argon2, PBKDF2).
2. **Implement account lockout/rate limiting** after several failed
   attempts.
3. **Use secure, HttpOnly cookies** for session tokens and rotate them
   after login.
4. **Invalidate sessions on logout** and after a reasonable timeout.
5. **Don't expose credentials** in URLs or logs; use POST bodies.
6. **Ensure MFA** is available for privileged accounts and critical
   actions.
7. **Protect password reset tokens** with sufficient entropy and
   expiration; send them via email only, not via SMS or GET parameters.

## Common scenarios

- `if (user.password == submitted)` — direct comparison suggests a lack
  of hashing.
- OTP or 2FA codes sent via email but validated without expiration checks.
- `sessionid=123456` in query strings.

## Quick checklist

- [ ] Are passwords hashed with an approved algorithm?
- [ ] Is there brute-force protection on login endpoints?
- [ ] Are session tokens unpredictable and stored securely?
- [ ] Are authentication cookies marked `Secure` and `HttpOnly`?
- [ ] Does logout or password change invalidate existing sessions?
- [ ] Is MFA offered or enforced where appropriate?

> The AI should also remind developers of secure libraries like
> `Passport.js`, `Spring Security`, or `Devise` that handle many of
> these issues, and to keep dependencies up to date.
