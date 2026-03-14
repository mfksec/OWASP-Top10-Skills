# Testing & Verification Guide

## Overview

This guide provides comprehensive testing procedures to validate the OWASP Security Skill across all standards, contexts, and example files.

---

## 1. File Integrity Tests

### Test 1.1: Verify All Files Present

```bash
# Run verification
./install.sh  # Select option 4 (test only)

# Manual check
ls -la owasp-comprehensive-security-skills.md
ls -la owasp-css.instructions.md
ls -la skill.json
ls -la DEPLOYMENT.md
ls -la TESTING.md

# Verify examples (should be 9 files)
ls -la examples/ | wc -l
```

**Expected Result:**
- ✅ All core files present (permissions: -rw-r--r--)
- ✅ skill.json is valid JSON
- ✅ 9 example files in examples/

### Test 1.2: Validate JSON Syntax

```bash
python3 -m json.tool skill.json > /dev/null && echo "✓ Valid JSON"
```

**Expected Result:**
- ✅ No JSON syntax errors

---

## 2. Cross-Reference Validation

### Test 2.1: Check Anchor Links

```bash
# Extract all anchor references from README
grep -o '#[a-z-]*' README.md | sort | uniq

# Verify corresponding sections exist
grep "^## Section\|^## Cross" owasp-comprehensive-security-skills.md
```

**Expected Result:**
- ✅ All referenced anchors exist in target files
- ✅ All 6 sections present in skills file
- ✅ Cross-standard reference section at end

### Test 2.2: Validate Example References

```bash
# Check that all examples in README are documented in skill.json
for file in examples/*.py examples/*.js examples/*.yaml examples/*.txt examples/*.html; do
    filename=$(basename "$file")
    grep -q "$filename" skill.json && echo "✓ $filename" || echo "✗ $filename (missing from skill.json)"
done
```

**Expected Result:**
- ✅ All 9 examples referenced in skill.json
- ✅ Each example has correct metadata

### Test 2.3: Code File Syntax Checking

**Python files:**
```bash
python3 -m py_compile examples/broken-access-control.py
python3 -m py_compile examples/security-misconfiguration.py
python3 -m py_compile examples/logging-monitoring-failures.py
```

**JavaScript files:**
```bash
node --check examples/cryptographic-failures.js
node --check examples/injection.js
node --check examples/api-auth-bypass.js
```

**YAML files:**
```bash
python3 -c "import yaml; yaml.safe_load(open('examples/k8s-rbac.yaml'))"
```

**HTML files:**
```bash
# Manual check - verify DOCTYPE and structure
head -5 examples/xss.html
```

**Expected Result:**
- ✅ No syntax errors in Python files
- ✅ No syntax errors in JavaScript files
- ✅ Valid YAML in Kubernetes manifest
- ✅ Valid HTML structure

---

## 3. Activation Trigger Tests

### Test 3.1: Web Application Activation

**Test Prompt:**
```
I'm building a Node.js REST API with user authentication. 
Can you review this endpoint for OWASP vulnerabilities?

app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  const result = db.query(query);
  res.json(result);
});
```

**Expected Response:**
- ✅ Trigger: Web app context detected
- ✅ Reference: Mentions Section 1 (Top 10)
- ✅ Vulnerability: Identifies SQL injection (A03)
- ✅ Mitigation: Shows parameterized query example
- ✅ Checklist: Provides verification steps

**Verification:**
- ✓ References `owasp-comprehensive-security-skills.md`
- ✓ Mentions "A03" or "Injection"
- ✓ Suggests `db.query(query, [req.params.id])`

### Test 3.2: API Security Activation

**Test Prompt:**
```
Review this API endpoint for OWASP API Security risks:

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    // Just check if token exists
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

app.get('/api/admin/users', verifyToken, (req, res) => {
  // Return all users regardless of who's asking
  res.json(db.query('SELECT * FROM users'));
});
```

**Expected Response:**
- ✅ Trigger: API context detected
- ✅ Reference: Section 4 (API Security)
- ✅ Vulnerabilities: Missing rate limiting, broken function-level auth
- ✅ Standard: Mentions OWASP API Security Top 10

**Verification:**
- ✓ References Section 4
- ✓ Mentions "API2" or "broken authorization"
- ✓ Suggests role-based access control

### Test 3.3: Kubernetes Activation

**Test Prompt:**
```
Review this Kubernetes manifest for security issues:

apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      runAsUser: 0
    env:
    - name: DB_PASSWORD
      value: "SuperSecret123!"
```

**Expected Response:**
- ✅ Trigger: Kubernetes context detected
- ✅ Reference: Section 5 (Kubernetes Top 10)
- ✅ Vulnerabilities: Running as root, plaintext secrets
- ✅ Standard: OWASP Kubernetes Top 10

**Verification:**
- ✓ References Section 5 or "K01", "K03"
- ✓ Mentions "Pod Security"
- ✓ Suggests `runAsUser: 1000`

### Test 3.4: Mobile App Activation

**Test Prompt:**
```
I'm building an iOS app. Is this authentication implementation 
secure according to MASVS?

let keychain = Keychain()
let password = "MyPassword123"
keychain.set(password, forKey: "user_password")

let stored = keychain.get("user_password")
```

**Expected Response:**
- ✅ Trigger: Mobile context detected
- ✅ Reference: Section 3 (MASVS)
- ✅ Issue: Plaintext password storage
- ✅ Solution: Use system credential storage

**Verification:**
- ✓ References Section 3 or "MASVS"
- ✓ Mentions "STORAGE-2" or similar
- ✓ Suggests `Keychain` usage

### Test 3.5: LLM/AI Activation

**Test Prompt:**
```
I'm building an AI agent that takes user prompts. How do I 
prevent prompt injection?

user_input = request.args.get('query')
system = "You are a helpful assistant."
prompt = system + "\n" + user_input
response = llm.call(prompt)
return response
```

**Expected Response:**
- ✅ Trigger: AI/LLM context detected
- ✅ Reference: Section 6 (Agentic Applications)
- ✅ Vulnerability: Direct concatenation (AG01)
- ✅ Mitigation: Structured prompting, input validation

**Verification:**
- ✓ References Section 6 or "AG01"
- ✓ Mentions "prompt injection"
- ✓ Suggests input validation/sanitization

### Test 3.6: Compliance Activation

**Test Prompt:**
```
What ASVS L2 requirements must I implement for user authentication?
```

**Expected Response:**
- ✅ Trigger: Compliance context detected
- ✅ Reference: Section 2 (ASVS 5.0)
- ✅ Level-Specific: L2 requirements
- ✅ Detailed: Lists specific requirements

**Verification:**
- ✓ References Section 2
- ✓ Mentions "ASVS"
- ✓ Lists L1, L2, L3 requirements

---

## 4. Example File Activation Tests

### Test 4.1: Broken Access Control Example

```bash
# Copy example code to file
cat examples/broken-access-control.py
```

**Test Prompt:**
```
Review this Python Flask code for security issues:

[paste entire broken-access-control.py]
```

**Expected Response:**
- ✅ Identifies VULNERABLE patterns
- ✅ Shows SECURE alternatives
- ✅ References Section 1 (Top 10)
- ✅ Mentions A01 (Broken Access Control)

**Verification Checklist:**
- ✓ Mentions `require_auth` decorator
- ✓ Identifies missing authorization check
- ✓ Suggests role verification
- ✓ Shows complete secure pattern

### Test 4.2: Cryptographic Failures Example

```bash
cat examples/cryptographic-failures.js
```

**Test Prompt:**
```
Review this JavaScript code for cryptographic vulnerabilities:

[paste entire cryptographic-failures.js]
```

**Expected Response:**
- ✅ Identifies weak hashing (MD5, SHA1)
- ✅ Identifies plaintext storage
- ✅ Identifies missing HTTPS enforcement
- ✅ Shows bcrypt/AES-256-GCM solutions

**Verification:**
- ✓ Mentions bcrypt
- ✓ Mentions AES-256-GCM
- ✓ Suggests environment variables for secrets
- ✓ References HSTS header

### Test 4.3: All 9 Examples

For each example file:

1. Open the file
2. Copy full content
3. Ask: "Review this code for OWASP vulnerabilities and suggest fixes"
4. Verify response includes:
   - ✅ Specific vulnerability identification
   - ✅ Reference to correct OWASP standard section
   - ✅ VULNERABLE vs SECURE pattern recognition
   - ✅ Concrete mitigation steps
   - ✅ Checklists provided

---

## 5. Cross-Standard Reference Tests

### Test 5.1: Mapping Validation

**Test Prompt:**
```
How do authentication requirements vary across OWASP Top 10, 
ASVS, and MASVS?
```

**Expected Response:**
- ✅ References multiple sections
- ✅ Shows level-specific requirements
- ✅ Mentions platform-specific (iOS/Android) differences
- ✅ References skill.json cross-reference mapping

### Test 5.2: Multi-Standard Request

**Test Prompt:**
```
I'm building a REST API for an iOS app. What security standards 
should I follow?
```

**Expected Response:**
- ✅ References Top 10 (web app)
- ✅ References API Security (API design)
- ✅ References MASVS (mobile)
- ✅ Integrates all three standards

---

## 6. Performance Tests

### Test 6.1: Response Time

**Measure:**
- ⏱ Time from prompt to first response
- Expected: < 3 seconds on standard hardware
- Log results: `response_time.log`

### Test 6.2: Memory Usage

**Measure:**
- 💾 Memory footprint when skill is active
- Expected: ~100KB overhead
- Monitor with system tools

### Test 6.3: Context Window Efficiency

**Measure:**
- 📊 Tokens used per response
- Expected: ~1,000-2,000 tokens average
- Verify with token counting tools

---

## 7. Documentation Tests

### Test 7.1: README Accuracy

- [ ] All standards listed with correct versions
- [ ] Installation instructions work
- [ ] Use cases cover all 6 standards
- [ ] Links to examples are valid
- [ ] Quick start example produces expected skill response

### Test 7.2: skill.json Completeness

- [ ] All 9 examples listed
- [ ] All activation triggers present
- [ ] All standards documented
- [ ] Version info current
- [ ] Metadata accurate

### Test 7.3: DEPLOYMENT.md Usability

- [ ] Installation script works
- [ ] Verification steps complete
- [ ] Troubleshooting covers common issues
- [ ] Custom path installation documented
- [ ] Team deployment instructions clear

---

## 8. Integration Tests

### Test 8.1: IDE Integration

**For VS Code:**
- [ ] Skill activates when viewing Python/JS/YAML files
- [ ] Can paste code directly in assistant pane
- [ ] Links to examples work

**For JetBrains IDEs:**
- [ ] Copilot integration works
- [ ] Can reference security checks
- [ ] Quick fixes suggest secure patterns

---

## 9. Regression Tests

After updates, verify:

- [ ] All 6 standards still referenced correctly
- [ ] No broken anchor links
- [ ] All 9 examples still valid
- [ ] Activation triggers still working
- [ ] Performance metrics unchanged

---

## 10. Sign-Off Checklist

**Verification Complete** ✅

- [ ] All files present and valid
- [ ] All 6 activation triggers tested
- [ ] All 9 examples work correctly
- [ ] Cross-references accurate
- [ ] Documentation complete
- [ ] Installation verified
- [ ] Performance acceptable
- [ ] Ready for production deployment

---

## Reporting Issues

If any test fails:

1. **Document:**
   - Test name and number
   - Expected vs actual result
   - Environment (OS, model, version)
   - Steps to reproduce

2. **Report:**
   - GitHub Issues (bug report)
   - Include test evidence
   - Suggest fix if obvious

3. **Track:**
   - Link to issue in changelog
   - Update DEPLOYMENT.md if needed
   - Plan fix for next version

---

## Test Results Template

```markdown
# Test Results: OWASP Security Skill [VERSION]

Date: [DATE]
Tester: [NAME]
Environment: [OS, Model, Version]

## Results

### File Integrity: ✅ PASS / ❌ FAIL
- All files present: ✅
- JSON valid: ✅
- Examples: ✅ (9/9)

### Activation Triggers: ✅ PASS / ❌ FAIL
- Web app: ✅
- API: ✅
- Mobile: ✅
- Kubernetes: ✅
- LLM/AI: ✅
- Compliance: ✅

### Examples: ✅ PASS / ❌ FAIL
- Test count: 9/9 ✅
- Vulnerabilities identified: ✅
- Mitigations provided: ✅

### Documentation: ✅ PASS / ❌ FAIL
- README: ✅
- DEPLOYMENT: ✅
- TESTING: ✅

### Overall: ✅ PASS / ❌ FAIL

## Notes
[Add any additional observations]
```

---