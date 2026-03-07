# 10. Insufficient Logging & Monitoring

Without proper logging and monitoring, attackers can operate inside an
application undetected and response teams cannot assess the scope of an
incident.

## Red flags

- Authentication and authorization failures aren’t logged.
- Logs contain sensitive data (passwords, tokens) in cleartext.
- No centralized logging system; logs are scattered across servers.
- Lack of alerts for unusual activities (e.g., repeated 404s, failed
  logins, high-volume requests).

## Guidance

1. **Log security-relevant events**: logins, logouts, access denied,
   file access, configuration changes.
2. **Ensure logs have context** (user ID, timestamp, source IP) and are
   tamper-evident.
3. **Monitor and alert** on anomalies using SIEM tools or cloud native
   monitors (CloudWatch, Azure Monitor).
4. **Protect log storage** – restrict who can read or modify logs.
5. **Rotate and archive logs** securely; retain them for a period
   appropriate to your compliance needs.

## Examples

**Insecure: no logging of authentication events (Express.js):**
```javascript
app.post('/login', (req, res) => {
  if (authenticate(req.body.username, req.body.password)) {
    req.session.userId = user.id;  // No log!
  }
});
```

**Secure: logging authentication (Express.js):**
```javascript
const logger = require('winston');
app.post('/login', (req, res) => {
  try {
    if (authenticate(req.body.username, req.body.password)) {
      logger.info('Login successful', {
        username: req.body.username,
        ip: req.ip,
        timestamp: new Date(),
      });
      req.session.userId = user.id;
    } else {
      logger.warn('Login failed', { username: req.body.username, ip: req.ip });
    }
  } catch (error) {
    logger.error('Login error', { error: error.message });
  }
});
```

**Insecure: logging secrets (Python):**
```python
logger.info(f"Connecting with password: {password}")  // Don't do this!
```

**Secure: redacting secrets (Python):**
```python
logger.info(f"Connecting to DB")  // No sensitive data
```

**Insecure: insufficient monitoring:**
```bash
echo "Failed login" >> /var/log/auth.log  // Logs written, no alerts
```

**Secure: monitoring with alerts:**
```yaml
AlarmActions:
  - SNS topic for failed logins
MetricName: FailedLoginAttempts
Statistic: Sum
Threshold: 5  // Alert if 5 failed logins in 5 minutes
```

## Edge cases

- Logging too much data can expose sensitive information or create
  performance issues.
- Attackers may delete their own log entries if they gain file system
  access.
- Application logs may be bypassed if the attacker achieves remote code
  execution and disables logging.

## Prevention Checklist

- [ ] All security-relevant events are logged: logins, failed authentications, access denials.
- [ ] Logs include sufficient context: user ID, source IP, timestamp, action, result.
- [ ] Sensitive data never appears in logs.
- [ ] Logs are centralized and retained for a sufficient period.
- [ ] Log integrity is protected: write-once storage or cryptographic signatures.
- [ ] Automated alerts are triggered for suspicious patterns.
- [ ] Log access is restricted to authorized personnel.
- [ ] Log retention policies comply with compliance requirements.