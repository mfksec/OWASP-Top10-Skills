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

## Prevention Checklist

- [ ] Treat all input as data; never interpolate it directly into commands.
- [ ] Use bound parameters or parameterized queries for every database
      operation.
- [ ] Avoid string concatenation when building SQL, shell, XPath, or
      other interpreter statements.
- [ ] When invoking the operating system, prefer APIs that accept argument
      lists (`subprocess.run`, `spawn`, etc.).
- [ ] Whitelist allowed values and reject or canonicalize the rest.
- [ ] Review ORM/ODM raw or literal interfaces for potential injection
      risks.

## Example fix

**PHP (MySQLi)**

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

**Node.js (mysql library)**

Bad:
```js
const q = `SELECT * FROM users WHERE email='${req.body.email}'`;
db.query(q, callback);
```
Good:
```js
const q = 'SELECT * FROM users WHERE email = ?';
db.query(q, [req.body.email], callback);
```

**Python shell command**

Bad:
```python
os.system("tar -czf " + filename + " /var/data")
```
Good:
```python
subprocess.run(["tar", "-czf", filename, "/var/data"], check=True)
```

These examples demonstrate that the user-supplied data is always sent as
an argument rather than merged into the command string.

---
The above instructions are meant to be included in the `1-injection.instructions.md` file, which is part of a larger OWASP Top 10 skill that teaches developers how to identify and fix common security vulnerabilities. Each instruction file focuses on a specific category of weakness, providing examples, detection clues, mitigation strategies, and prevention checklists to help developers secure their code against these threats. 