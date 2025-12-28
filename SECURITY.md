# Security Policy

## Experimental / Audit-Only Notice

This software is **experimental** and **not production-ready**. It is published **only for transparency and security audit** at this time. Do not rely on it to protect funds, credentials, or sensitive data in real trading environments.

This repository is **source-available for audit** under the terms in `LICENSE`. We take security reports seriously and prefer **responsible disclosure**.

## Supported Versions

Security fixes, if any, are provided at the discretion of the Rights Holder. If you are using a fork or modified copy, you are responsible for its security.

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately**:

- Email: **hello@qhash.foundation**
- PGP / Public Key info:
  - https://qhash.foundation/static/security.html
  - https://qhashfoundation.github.io/pgp/

When possible, encrypt your report using our PGP key.

### What to include

To help us reproduce and triage quickly, include:

- A clear description of the issue and impact
- Steps to reproduce (proof-of-concept if available)
- Affected component(s) and version/commit hash
- Environment details (OS, Go version, configuration)
- Any logs or crash traces (redact secrets)
- Suggested fix or mitigation (optional)

### What **not** to include

Do **not** send:
- API keys, secrets, seed phrases, private keys, or passwords
- Full database files containing secrets
- Sensitive personal data

If sensitive data is needed to reproduce, provide a **minimal redacted** sample.

## Disclosure Process

We aim to follow this general process:

1. **Acknowledgement** of receipt
2. **Triage** and severity assessment
3. **Fix** development and internal verification
4. **Release / advisory** (timing coordinated with the reporter when feasible)

We may request a short embargo period to prepare a fix before public disclosure.

## Scope Notes

This project is designed to minimize risk:
- Local IPC (UNIX socket) where applicable
- Signed responses for daemon IPC (where implemented)
- No intentional exfiltration of secrets

However, security depends on the user’s host environment. Keep your system updated and follow least-privilege practices.

## Safe Harbor

We welcome good-faith security research that:
- Avoids privacy violations and data destruction
- Does not degrade service availability for others
- Does not exfiltrate real user secrets

Please give us a reasonable opportunity to address issues before public disclosure.
