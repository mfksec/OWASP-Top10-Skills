# 8. Insecure Deserialization

Applications that deserialize untrusted data without sufficient checks can
be made to execute arbitrary code, escalate privileges, or cause
application crashes.

## Red flags

- Use of `pickle`, `PHP unserialize()`, `Java`’s `ObjectInputStream`, or
  similar features on input received from users (cookies, POST bodies,
  WebSocket messages).
- Accepting uploaded files that are later deserialized by the server.
- Logging or storing serialized objects that are later reloaded without
  validation.

## Mitigations

1. **Avoid native serialization formats** when possible; use JSON or
   other simple formats and explicitly parse fields.
2. **Validate and sanitize** serialized content before deserializing.
3. **Restrict which classes can be instantiated** during deserialization
   (e.g., `allowed_classes` in PHP’s `unserialize()`).
4. **Use integrity checks or signatures** on serialized payloads to detect
   tampering.
5. **Run deserialization logic in a sandbox or with limited permissions**.

## Exploitation techniques

- Crafting a malicious payload that, when deserialized, invokes a
  gadget chain in application libraries leading to code execution.
- Modifying fields to escalate privileges, e.g., changing `isAdmin=false`
  to `true` in a serialized session object.

## Quick checklist

- [ ] Does any user-controlled data get passed to a deserializer?
- [ ] Are non-binary formats preferred wherever feasible?
- [ ] Is deserialization restricted to known-safe classes?
- [ ] Is there a mechanism to verify payload integrity (HMAC,
      signature)?

> The model should cite OWASP’s [Insecure Deserialization Cheat
> Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Deserialization_Cheat_Sheet.html)
> for deeper study and suggest libraries or patterns that avoid the issue.