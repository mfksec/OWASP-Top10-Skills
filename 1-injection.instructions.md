# 1. Injection (SQL, Command, NoSQL, etc.)

Injection flaws occur when untrusted data is sent to an interpreter as
part of a command or query. The attacker’s hostile data can trick the
interpreter into executing unintended commands or accessing data without
proper authorization.

## Common patterns

- Concatenating user input directly into a SQL query string:
  ```js
  const sql = "SELECT * FROM users WHERE email='" + req.body.email + "'";
  db.query(sql, ...);
  ```
- Executing shell commands with unsanitized arguments:
  ```python
  os.system("tar -czf " + filename + " /var/data")
  ```
- Constructing XPath, LDAP, or NoSQL expressions using raw input.

## Detection clues

- Look for string construction operations that mix literals and
  variables from request parameters, cookies, headers, or files.
- Functions named `exec`, `query`, `run`, `shell`, etc., are red flags
  when passed user-controlled data.
- Absence of parameter binding, prepared statements, or escaping calls.

## Mitigation strategies

1. **Use parameterized queries / prepared statements** provided by the
   database driver.
2. **Whitelist input** – only allow expected characters or values, and
   reject the rest.
3. **Escape or encode data** only when an interpreter requires it, but
   prefer parameterization.
4. **Avoid invoking interpreters** unnecessarily. When running
   commands, use safe APIs (e.g., Python’s `subprocess.run([...])` with a
   list argument).
5. **Employ ORM/ODM libraries** carefully; understand how they handle
   interpolation.

## Bypass and edge cases

- Numeric fields may be exploited with `0 OR 1=1` or `; DROP TABLE`
- Encodings (`%27`, Unicode homoglyphs) may bypass naive filters.
- In NoSQL (MongoDB) an attacker can send `{"$gt": ""}` to bypass
  equality checks.
- When using ORM query builders, injection can happen in the `raw`
  or `literal` clauses.

## Quick checklist

- [ ] Are all user inputs treated as data, not code?
- [ ] Are queries executed with bound parameters?
- [ ] Is there any use of string concatenation in commands?
- [ ] Are shell calls replaced with safer APIs?
- [ ] Has input been validated against a whitelist?

## Example fix

Bad:
```php
$query = "SELECT * FROM products WHERE id=" . $_GET['id'];
$result = mysqli_query($conn, $query);
```

Good:
```php
$stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

---
This file should provide the model with enough context to recognize and
handle injection vulnerabilities across languages and interpreters.