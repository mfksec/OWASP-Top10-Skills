# OWASP Top 10 Security Skill

_A lightweight plug‑in for your AI assistant that turns it into a
security-minded co‑developer._

Drop this folder into your model’s skill directory, and from that point
on, any web-related prompt—an API design, a React component, or a
request for a security review—will trigger a deep dive into the
**OWASP Top 10**. The assistant will behave more like a bug bounty
hunter than a code generator, spotting holes and teaching you how to
patch them.

---

## 🔍 How It Helps

This skill doesn’t just flag problems; it teaches and guides:

- **Reads your code and descriptions** and looks for risky patterns.
- **Breaks vulnerabilities down** with plain‑English explanations.
- **Recommends concrete remedies**, often with sample code or commands.
- **Warns about clever bypasses** attackers love to use.
- **Waits for you to ask** or automatically jumps in when sensing
  web‑app context.


## 📥 Installation

Getting started is fast:

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/OWASP-Top10-Skills.git
   cd OWASP-Top10-Skills
   ```
2. Link or copy it into your assistant’s skill folder:
   - **Claude:** `~/.claude/skills/owasp-top10`
   - **GitHub Copilot:** `~/.copilot/skills/owasp-top10` or
     `.github/skills`
   - **Codex/other agents:** similar directories under `~/.agents`.

   ```bash
   ln -s "$PWD" ~/.claude/skills/owasp-top10
   ```

3. Reload or restart the assistant if needed.

Now the skill is live; it will silently monitor your prompts and
respond when it spots web security issues.


## 🎯 What It Covers

Every member of the OWASP Top 10 is in scope. When the skill engages, it
will consider whether your code exhibits any of the following weakness
classes:

1. Injection (SQL, command, NoSQL, etc.)
2. Broken Authentication & Session Management
3. Sensitive Data Exposure
4. XML External Entity attacks (XXE)
5. Broken Access Control
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Outdated or vulnerable third-party components
10. Insufficient Logging & Monitoring

Each category has its own instruction file that teaches the model how
attackers think and how developers should fight back.


## 🚀 Quick Start

Just ask. For example:

```
I'm building a Flask API. Please scan this handler for OWASP Top 10
vulnerabilities and suggest how to fix anything you find.

[insert code here]
```

The assistant will reply with a clear, categorized analysis—"Injection in
this query…", "Missing auth check on that endpoint…"—and show you how
to patch the issue.

You can also call it directly:

```
Run a full OWASP Top 10 audit on my project.
```

and it will return a checklist-style summary.

## 🧪 Examples

A handful of intentionally vulnerable snippets are included in the
`examples/` folder.  You can paste their contents into a prompt or open
them in a browser to trigger the corresponding vulnerability.  These are
for manual testing and learning only:

- `examples/injection.js` – SQL injection via string concatenation.
- `examples/xss.html` – reflected XSS using `innerHTML`.

Feel free to add more samples for other categories as you build out the
skill.



