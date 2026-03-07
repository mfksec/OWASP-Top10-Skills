# 7. Cross-Site Scripting (XSS)

XSS vulnerabilities occur when an application includes untrusted data in a
web page without proper validation or escaping, allowing attackers to
execute arbitrary JavaScript in victims’ browsers.

## Types of XSS

- **Stored (persistent):** data saved on the server and displayed later
  (e.g., comments, profile fields).
- **Reflected:** malicious input echoed in an immediate response (e.g., in
  a search result).
- **DOM-based:** the vulnerability exists in client-side scripts that
  modify the DOM using unsanitized input.

## Detection hints

- Look for `innerHTML`, `document.write`, or template literals that
  interpolate user data.
- Server-side templates that don’t escape output (e.g., `<%= user.name
  %>` in ERB without `h`).
- Absence of output encoding functions (e.g., `htmlspecialchars`,
  `escapeHtml`).

## Defensive patterns

1. **Escape output** based on context (HTML, attribute, JavaScript,
   URL).
2. **Use a safe templating engine** that auto-escapes by default.
3. **Validate input** and strip unwanted tags or attributes using a
   library like DOMPurify.
4. **Implement Content Security Policy (CSP)** with `script-src`
   restrictions and `nonce`/`hash` support to limit script execution.
5. **Avoid inserting user-provided HTML** unless absolutely necessary.

## Examples

**Insecure: reflected XSS (PHP):**
```php
<input value="<?= $_GET['q'] ?>">  <!-- If q=\" onclick=alert(1) -->
```

**Secure: escaped output (PHP):**
```php
<input value="<?= htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') ?>">
```

**Insecure: stored XSS (Express.js):**
```javascript
app.post('/comment', (req, res) => {
  db.query('INSERT INTO comments (text) VALUES (?)', req.body.text);
});
app.get('/comments', (req, res) => {
  const comments = db.query('SELECT text FROM comments');
  res.send(comments.map(c => `<p>${c.text}</p>`).join(''));  // Unescaped!
});
```

**Secure: escaped output (Express.js):**
```javascript
const escapeHtml = require('escape-html');
app.get('/comments', (req, res) => {
  const comments = db.query('SELECT text FROM comments');
  res.send(comments.map(c => `<p>${escapeHtml(c.text)}</p>`).join(''));
});
```

**Insecure: DOM-based XSS (JavaScript):**
```javascript
const userInput = document.getElementById('userInput').value;
document.getElementById('output').innerHTML = userInput;  // Raw HTML!
```

**Secure: DOM-based safe replacement (JavaScript):**
```javascript
const userInput = document.getElementById('userInput').value;
document.getElementById('output').textContent = userInput;  // Text only
```

**Insecure: React with dangerouslySetInnerHTML:**
```jsx
<div dangerouslySetInnerHTML={{ __html: userContent }} />
```

**Secure: React with proper escaping:**
```jsx
<div>{userContent}</div>  // React auto-escapes by default
```

## Bypass and edge cases

- Crafting payloads using event handlers (`onerror`, `onclick`) or URI
  schemes (`javascript:`).
- Polyglot strings that break out of attribute contexts (e.g.,
  `" onmouseover=alert(1) "`).
- Storing payloads in unexpected places like JSON fields that are later
  rendered.

## Prevention Checklist

- [ ] All user-supplied data is escaped based on context (HTML, attribute, JavaScript, URL).
- [ ] Templating engines auto-escape output by default.
- [ ] `innerHTML` and similar unsafe APIs are avoided with user data.
- [ ] Content Security Policy (CSP) is implemented with strict `script-src` directives.
- [ ] DOMPurify or equivalent is used if HTML input is necessary.
- [ ] Client-side data from `location.hash` and `localStorage` is sanitized before rendering.
- [ ] File uploads cannot contain executable scripts.