# Deployment Guide

## Quick Start

### Option 1: Interactive Installation (Recommended)

```bash
cd OWASP-Security-Skills
./install.sh
```

This script will:
- ✅ Detect your operating system
- ✅ Guide you through installation target selection
- ✅ Verify all required files are present
- ✅ Create proper symlinks for skill activation
- ✅ Test the installation immediately

### Option 2: Manual Installation

For **Claude Desktop** (macOS):
```bash
mkdir -p ~/.claude/skills
ln -s /path/to/OWASP-Security-Skills ~/.claude/skills/owasp-security
# Restart Claude Desktop
```

For **Claude Desktop** (Linux):
```bash
mkdir -p ~/.local/share/claude/skills
ln -s /path/to/OWASP-Security-Skills ~/.local/share/claude/skills/owasp-security
# Restart Claude Desktop
```

For **GitHub Copilot**:
```bash
mkdir -p ~/.copilot/skills
ln -s /path/to/OWASP-Security-Skills ~/.copilot/skills/owasp-security
# Restart your IDE
```

For **Other Assistants**:
```bash
# Copy directory to your assistant's skills folder
cp -r OWASP-Security-Skills ~/.agents/skills/owasp-security
```

---

## Verification

After installation, verify the skill works:

### Test 1: Activation Check
Ask your assistant:
```
Please audit this code for OWASP vulnerabilities:

const sql = `SELECT * FROM users WHERE id = ${userId}`;
```

**Expected response:**
- ✅ References `owasp-comprehensive-security-skills.md`
- ✅ Identifies SQL injection (A03)
- ✅ Suggests parameterized queries
- ✅ Shows example of secure implementation

### Test 2: Multi-Standard Activation
Ask about different context:
```
Review this Kubernetes manifest for security issues:
[paste content from examples/k8s-rbac.yaml]
```

**Expected response:**
- ✅ References Section 5: OWASP Kubernetes Top 10
- ✅ Identifies RBAC misconfiguration (K02)
- ✅ Suggests least-privilege approach

### Test 3: Example File Testing
Copy/paste entire content from:
- `examples/broken-access-control.py`
- `examples/cryptographic-failures.js`
- `examples/security-misconfiguration.py`
- `examples/logging-monitoring-failures.py`

Verify the skill identifies both VULNERABLE and SECURE patterns.

---

## Configuration

### Activation Triggers

The skill automatically activates when it detects:

**Web Application Context:**
- Keywords: "web app", "API", "REST", "authentication", "injection", "XSS"
- Example: Code snippets, API endpoints, auth flows

**API Security Context:**
- Keywords: "API", "endpoint", "token", "BOLA", "rate limiting"
- Example: REST/GraphQL API code, JWT implementation

**Mobile Context:**
- Keywords: "iOS", "Android", "Keychain", "MASVS", "mobile"
- Example: Swift/Kotlin code, mobile app config

**Kubernetes Context:**
- Keywords: "kubernetes", "k8s", "RBAC", "pod", "secrets"
- Example: YAML manifests, cluster configuration

**LLM/AI Context:**
- Keywords: "LLM", "AI", "agent", "prompt", "agentic"
- Example: LLM integration code, agent configuration

**Compliance Context:**
- Keywords: "ASVS", "MASVS", "compliance", "L1", "L2", "L3"
- Example: Requirement verification, standard questions

### Customization

To customize activation rules:

1. Edit `owasp-css.instructions.md` for model guidance
2. Edit `skill.json` for activation trigger configuration
3. Update `README.md` for documentation changes
4. Add new examples to `examples/` folder

---

## Troubleshooting

### Skill Not Activating

**Problem:** Skill doesn't respond to security questions
**Solution:**
1. Verify installation path is correct
2. Check that all files exist: `ls -la ~/.claude/skills/owasp-security/`
3. Restart the assistant application completely
4. Try asking explicit question: "Review this for OWASP vulnerabilities"

### Missing Files

**Problem:** Some example files are missing
**Solution:**
```bash
cd OWASP-Security-Skills
./install.sh  # Select "4" for test only
```

This will verify all files are present.

### Incorrect References

**Problem:** Skill references wrong version or standard
**Solution:**
1. Verify `owasp-comprehensive-security-skills.md` is intact
2. Check `skill.json` has correct section references
3. Update instructions in `owasp-css.instructions.md`

### Performance Issues

**Problem:** Slow responses or model timeout
**Solution:**
1. This skill requires ~8k minimum context window
2. Use Claude 4+ models (Haiku 4.5, Sonnet 4.1, or Opus 3+)
3. Ensure system has adequate memory
4. Check internet connection if using cloud models

---

## Production Deployment

### For Teams/Organizations

1. **Clone Repository:**
   ```bash
   git clone https://github.com/mfkocalar/OWASP-Security-Skills.git /opt/security-skills/owasp
   cd /opt/security-skills/owasp
   ```

2. **Verify Installation:**
   ```bash
   ./install.sh  # Select option 4 (test only)
   ```

3. **Create Symlinks for All Users:**
   ```bash
   for user in $(ls /home); do
       sudo -u $user mkdir -p /home/$user/.claude/skills
       sudo -u $user ln -s /opt/security-skills/owasp /home/$user/.claude/skills/owasp-security
   done
   ```

4. **Document in Wiki/Docs:**
   - Point team to README.md for usage
   - Include examples from `examples/` folder
   - Set up regular skill updates (monthly)

5. **Monitor Usage:**
   - Track which standards are used most
   - Gather feedback on examples
   - Plan enhancements based on team needs

### Continuous Updates

The skill is actively maintained. To get latest updates:

```bash
cd OWASP-Security-Skills
git pull origin main
# No reinstallation needed if symlinked
```

Updates include:
- ✅ Latest vulnerability data
- ✅ New example code patterns
- ✅ Enhanced detection rules
- ✅ Additional standards integration

### Compliance & Auditing

If your organization requires:

1. **License Attribution:**
   - MIT License - include in security documentation
   - Maintain CONTRIBUTING.md for contributor records

2. **Version Tracking:**
   - Current version: See `skill.json` → "version"
   - Changelog: See `skill.json` → "changelog"
   - Release notes: GitHub releases

3. **Security Audit Trail:**
   - Git history shows all changes
   - Version tags map to security advisory dates
   - Contributors listed in CONTRIBUTING.md

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Skill Load Time | <500ms |
| Average Response | <3s |
| Memory Footprint | ~100KB |
| Example Code | 1,840 lines |
| Example Files | 9 |
| Standards Covered | 6 |
| Vulnerabilities | 60+ patterns |

---

## Support

Need help?

- 📖 **Documentation:** See README.md
- 💬 **Discussions:** GitHub Discussions
- 🐛 **Issues:** GitHub Issues
- 📧 **Contact:** See CONTRIBUTING.md

---

## Next Steps

1. ✅ **Installation:** Run `./install.sh`
2. ✅ **Verification:** Test with examples from `examples/`
3. ✅ **Customization:** Adapt to your organization's needs
4. ✅ **Training:** Share with security team
5. ✅ **Feedback:** Report issues or suggest enhancements
