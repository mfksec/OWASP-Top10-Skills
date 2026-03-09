# OWASP Top 10 Security Skill


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
   git clone https://github.com/mfksec/OWASP-Top10-Skills.git
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

All ten vulnerability categories are covered in the comprehensive
**`owasp-top10-skills.md`** file. This consolidated guide teaches the model
how attackers think and how developers should fight back, with practical
examples, mitigation strategies, and prevention checklists for each
vulnerability type.


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
Review my code against the OWASP Top 10 and provide recommendations.
```

The assistant will return a detailed security analysis with references to
the specific vulnerability categories in **`owasp-top10-skills.md`**, including
code examples, mitigation strategies, and prevention checklists.

## 🧪 Examples

A handful of intentionally vulnerable snippets are included in the
`examples/` folder.  You can paste their contents into a prompt to trigger
the corresponding vulnerability detection.  These are for manual testing and
learning only:

- `examples/injection.js` – SQL injection via string concatenation.
- `examples/xss.html` – reflected XSS using `innerHTML`.

For detailed guidance on each vulnerability category, refer to the
**`owasp-top10-skills.md`** file, which contains comprehensive explanations,
detection hints, mitigation strategies, and prevention checklists for all
ten OWASP Top 10 vulnerabilities.

Feel free to add more samples for other categories as you build out the
skill.



