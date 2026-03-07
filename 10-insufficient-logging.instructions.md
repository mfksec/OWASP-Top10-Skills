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

## Edge cases

- Logging too much data can expose sensitive information or create
  performance issues.
- Attackers may delete their own log entries if they gain file system
  access.
- Application logs may be bypassed if the attacker achieves remote code
  execution and disables logging.

## Quick checklist

- [ ] Are critical events logged with sufficient detail?
- [ ] Do logs avoid storing secrets?
- [ ] Is there an alerting system for suspicious patterns?
- [ ] Are log files protected from tampering?

> The AI should encourage developers to assume "what isn't logged
doesn't exist" and to build systems where logs are treated as a security
asset.