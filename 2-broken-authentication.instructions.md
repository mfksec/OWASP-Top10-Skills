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

## Examples

**Insecure password storage (Node.js):**
```javascript
if (user.password === submittedPassword) { // No hashing!
  // Authenticate user
}
```

**Secure password storage (Node.js with bcrypt):**
```javascript
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);
if (await bcrypt.compare(submittedPassword, hash)) {
  // Authenticate user
}
```

**Insecure session handling (PHP):**
```php
$_SESSION['user_id'] = $user_id; // Session ID is predictable
```

**Secure session handling (PHP):**
```php
session_regenerate_id(true);
setcookie('PHPSESSID', '', [
  'expires' => time() + 3600,
  'path' => '/',
  'secure' => true,
  'httponly' => true,
  'samesite' => 'Strict',
]);
```

**Weak password reset token (Python):**
```python
import random
token = str(random.randint(100000, 999999))  // Guessable!
```

**Strong password reset token (Python):**
```python
import secrets
token = secrets.token_urlsafe(32)  // Cryptographically secure
```

## Prevention Checklist

- [ ] Passwords are hashed using bcrypt, Argon2, or PBKDF2 with adequate salt and iterations.
- [ ] Login endpoints have rate limiting or account lockout after failed attempts.
- [ ] Session tokens are generated using cryptographically secure randomness.
- [ ] Authentication cookies are marked `Secure`, `HttpOnly`, and `SameSite=Strict`.
- [ ] Sessions are invalidated on logout and after inactivity periods.
- [ ] Password reset tokens expire after a short time and are single-use.
- [ ] Multi-factor authentication is implemented for privileged accounts.

