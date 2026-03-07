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

## Examples

**Insecure: no authorization check (Express.js):**
```javascript
app.get('/users/:id/orders', (req, res) => {
  const orders = db.query('SELECT * FROM orders WHERE user_id = ?', req.params.id);
  res.json(orders); // No check if req.user.id === req.params.id!
});
```

**Secure: authorization check (Express.js):**
```javascript
app.get('/users/:id/orders', (req, res) => {
  if (req.user.id !== parseInt(req.params.id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const orders = db.query('SELECT * FROM orders WHERE user_id = ?', req.params.id);
  res.json(orders);
});
```

**Insecure: client-side only enforcement (JavaScript):**
```javascript
if (user.role === 'admin') {
  document.getElementById('deleteBtn').style.display = 'block';
}
```

**Secure: server-side authorization (Django):**
```python
from django.contrib.auth.decorators import permission_required

@permission_required('app.delete_resource')
def delete_resource(request, resource_id):
  if request.user.id != resource.owner_id:
    return HttpResponseForbidden()
  resource.delete()
  return JsonResponse({'status': 'deleted'})
```

**Insecure: mass assignment (Python/Flask):**
```python
@app.route('/user/update', methods=['POST'])
def update_user():
  user = User.query.get(request.form.get('user_id'))
  user.update(request.form)  // Blindly assigns all fields!
  db.session.commit()
```

**Secure: whitelist allowed fields (Python/Flask):**
```python
@app.route('/user/update', methods=['POST'])
def update_user():
  user = User.query.get(request.user.id)  // Use authenticated user
  allowed_fields = {'name', 'email', 'phone'}
  for field in allowed_fields:
    if field in request.form:
      setattr(user, field, request.form[field])
  db.session.commit()
```

## Bypass techniques

- Parameter tampering: modify `?id=42` to `?id=43`.
- Changing HTTP verbs: using `PUT` instead of `POST` if only `POST` handlers validate permissions.
- Exploiting mass-assignment to overwrite `role` or `isAdmin` flags.

## Prevention Checklist

- [ ] Authorization is enforced on the server for every sensitive operation.
- [ ] User identity is verified before access checks.
- [ ] Resource ownership is confirmed before permitting the action.
- [ ] A centralized authorization mechanism is used consistently.
- [ ] Default-deny policy is applied; only explicitly allowed actions are permitted.
- [ ] All HTTP methods (GET, POST, PUT, DELETE, PATCH) are protected.
- [ ] Mass-assignment vulnerabilities are prevented by whitelisting fields.

