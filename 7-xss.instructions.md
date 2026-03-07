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

## Bypass and edge cases

- Crafting payloads using event handlers (`onerror`, `onclick`) or URI
  schemes (`javascript:`).
- Polyglot strings that break out of attribute contexts (e.g.,
  `" onmouseover=alert(1) "`).
- Storing payloads in unexpected places like JSON fields that are later
  rendered.

## Quick checklist

- [ ] Are all user-supplied strings escaped before rendering?
- [ ] Does the app use a CSP that restricts script sources?
- [ ] Are any `innerHTML` or equivalent APIs used with raw input?
- [ ] Is client-side code sanitizing data from `location.hash` or
      `localStorage`?

> When explaining fixes, the AI should provide example sanitization code
> appropriate to the language/framework (React `dangerouslySetInnerHTML`
> notes, Angular’s automatic binding, etc.).