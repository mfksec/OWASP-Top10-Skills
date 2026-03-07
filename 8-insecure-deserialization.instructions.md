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

## Examples

**Insecure: unsafe pickle deserialization (Python):**
```python
import pickle
users = pickle.loads(request.data)  // Untrusted data!
```

**Secure: JSON deserialization (Python):**
```python
import json
users = json.loads(request.data)  // Safe, only data structures
```

**Insecure: unsafe Java deserialization:**
```java
ObjectInputStream eis = new ObjectInputStream(request.getInputStream());
Object obj = eis.readObject();  // Gadget chain risk!
```

**Secure: whitelisted class deserialization (Java):**
```java
ObjectInputStream eis = new ObjectInputStream(request.getInputStream()) {
  protected Class<?> resolveClass(ObjectStreamClass osc)
    throws IOException, ClassNotFoundException {
    if (!osc.getName().startsWith("com.myapp.")) {
      throw new ClassNotFoundException(osc.getName());
    }
    return super.resolveClass(osc);
  }
};
Object obj = eis.readObject();
```

**Insecure: PHP unserialize with user input:**
```php
$data = unserialize($_COOKIE['user']);  // Dangerous!
```

**Secure: JSON for cookies (PHP):**
```php
$data = json_decode($_COOKIE['user'], true);
if (json_last_error() !== JSON_ERROR_NONE) {
  throw new Exception('Invalid data');
}
```

## Exploitation techniques

- Crafting a malicious payload that, when deserialized, invokes a
  gadget chain in application libraries leading to code execution.
- Modifying fields to escalate privileges, e.g., changing `isAdmin=false`
  to `true` in a serialized session object.

## Prevention Checklist

- [ ] Serialized data is never accepted from user input; JSON is used instead.
- [ ] Only trusted sources are deserialized if native serialization is unavoidable.
- [ ] A whitelist of allowed classes is defined and enforced during deserialization.
- [ ] Serialized payloads are signed (HMAC or RSA) to detect tampering.
- [ ] Deserialization runs with minimal privileges or in a sandboxed environment.
- [ ] Libraries and gadget chains are kept up to date and reviewed.