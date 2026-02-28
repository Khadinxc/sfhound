# Contributing to SFHound

Thank you for your interest in contributing to SFHound! This document outlines the process for contributing code, documentation, and bug reports.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and constructive environment. Please be considerate of others and focus on the merit of ideas.

---

## Reporting Bugs

Before opening a new issue, please search [existing issues](https://github.com/Khadinxc/sfhound/issues) to avoid duplicates.

When filing a bug report, include:

- **SFHound version** and Python version
- **Operating system** and version
- **Steps to reproduce** the issue
- **Expected vs. actual behavior**
- **Relevant log output** or error messages (redact any credentials or org-specific data)

---

## Suggesting Features

Feature requests are welcome. Open an issue with the label `enhancement` and describe:

- The use case or problem being solved
- Your proposed solution or behavior
- Any alternatives you considered

---

## Development Setup

```bash
git clone https://github.com/Khadinxc/sfhound.git
cd sfhound/salesforce-opengraph
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Submitting Changes

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes.** Keep commits focused and atomic.

3. **Test your changes** against a Developer Edition or sandbox org before submitting.

4. **Open a Pull Request** against `main` with a clear description of:
   - What the change does
   - Why it is needed
   - Any relevant issue numbers (`Closes #123`)

5. Be responsive to review feedback. PRs with no activity for 30 days may be closed.

---

## Coding Standards

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code style.
- Use descriptive variable and function names.
- Add docstrings to public functions and classes.
- Keep extractor, graph, and output logic separated according to the existing module structure:
  - `extractor/` — Salesforce API data collection
  - `graph/` — node and edge construction
  - `examples/` — standalone usage examples
- Do not commit credentials, private keys, `config.yaml`, or org-specific data.
