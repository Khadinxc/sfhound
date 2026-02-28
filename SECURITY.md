# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest (`main`) | :white_check_mark: |
| older commits | :x: |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in SFHound, please report it responsibly via one of the following channels:

- **GitHub Private Vulnerability Reporting:** Use the [Security Advisory](https://github.com/Khadinxc/sfhound/security/advisories/new) feature on this repository.
- **Email:** Contact the maintainer directly through the contact information listed on [sfhound.kaibersec.com](https://sfhound.kaibersec.com/).

Please include as much of the following as possible to help us assess and address the issue quickly:

- Description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected component(s) (e.g., `extractor/auth.py`, `sfhound.py`)
- Any suggested mitigations

---

## Response Timeline

| Step | Target |
| ---- | ------ |
| Acknowledgement | Within 3 business days |
| Initial assessment | Within 7 business days |
| Fix or mitigation guidance | Dependent on severity |

---

## Scope

SFHound is an **offensive security tool** intended for authorized use against Salesforce orgs you own or have explicit written permission to test. Vulnerabilities in scope include:

- Credential or token leakage introduced by this tool's code
- Insecure defaults that could expose collected data
- Dependency vulnerabilities with a known exploit path

Out of scope:

- Vulnerabilities in the Salesforce platform itself (report to [Salesforce Trust](https://www.salesforce.com/company/legal/trust-and-compliance-documentation/))
- Issues in third-party libraries (report upstream; we will update the dependency)

---

## Disclosure Policy

We follow coordinated disclosure. We ask that you give us a reasonable remediation window before public disclosure.
