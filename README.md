# passcheck

A Python password strength checker focused on **real-world security weaknesses**.

The tool analyzes passwords locally and provides a score, findings, and clear improvement suggestions.

> 🔐 Password input is hidden in the terminal and never stored.

---

## Features
- Length analysis
- Character variety (upper / lower / digits / symbols)
- Estimated entropy calculation
- Detection of weak patterns:
  - sequences (e.g. `1234`, `abcd`)
  - repeated characters (e.g. `aaaa`)
- **Dictionary word detection**
- **Leetspeak normalization** (detects `p@ssw0rd`, `adm1n`, etc.)
- Actionable suggestions to improve password strength

---

## Usage

### Interactive prompt (recommended)
```bash
python password_checker.py
