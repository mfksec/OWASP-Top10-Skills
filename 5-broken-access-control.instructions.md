# 5. Broken Access Control

Access control failures allow users to act outside of their intended
permissions, whether by bypassing UI checks or manipulating backend
references.

## Common indicators

- URLs or API endpoints that reference IDs directly (`/user/1234/orders`)
  without verifying the current user owns the resource.
- Client-side enforcement only (hiding buttons with JavaScript but not
  enforcing server-side checks).
- Role or permission logic duplicated in many places, increasing the
  chance of a missing check.

## Defensive advice

1. **Enforce authorization on the server** for every sensitive action.
   Use middleware, filters, or decorators to avoid omission.
2. **Implement horizontal and vertical checks**: confirm the acting user
   is allowed to access the target resource and perform the requested
   operation.
3. **Do not rely on obscurity**; numeric or GUID identifiers aren’t
   sufficient.
4. **Tokenize or encrypt identifiers** when exposing them to users.
5. **Use established libraries/framework features** for access control
   (e.g., Django’s `@login_required` + `user.has_perm`, Spring Security
   annotations, Express ACL middleware).

## Bypass techniques

- Parameter tampering: modify `?id=42` to `?id=43`.
- Changing HTTP verbs: using `PUT` instead of `POST` if only `POST`
  handlers validate permissions.
- Exploiting mass-assignment to overwrite `role` or `isAdmin` flags.

## Quick checklist

- [ ] Are resource accesses checked against the authenticated user?
- [ ] Do APIs verify both the identity and the requested action?
- [ ] Is there a centralized place for authorization logic?
- [ ] Are default-deny policies in place when roles are ambiguous?

> The AI should remind developers that access control is a common
> source of high-severity vulnerabilities in bug bounty reports and to
> consider using attribute-based access control (ABAC) for complex
> scenarios.