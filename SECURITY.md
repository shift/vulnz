# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Because vulnz is a security tool, we take security seriously. If you discover a security vulnerability, please follow responsible disclosure:

### How to Report

1. **Do NOT open a public GitHub issue** -- this could expose users to risk
2. **Use GitHub Security Advisories** -- Go to the [Security tab](https://github.com/shift/vulnz/security) and click "Report a vulnerability"
3. **Or email directly** -- Contact the maintainer at [shift+vulnz@someone.section.me](mailto:shift+vulnz@somoene.section.me) with the subject line: `[SECURITY] vulnz: <brief description>`

### What to Include

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if applicable)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Status updates**: Every 5 business days while we investigate
- **Resolution timeline**: We aim to resolve critical issues within 7 days
- **Credit**: We will publicly credit reporters (unless you prefer to remain anonymous)

### Scope

Security issues may include:
- Remote code execution through malicious input data
- Path traversal vulnerabilities in archive extraction
- Credential leakage in logs or error messages
- Denial of service through resource exhaustion
- Supply chain attacks through compromised dependencies

### Out of Scope

- Upstream data source issues (NVD, ENISA, etc.)
- Known limitations documented in README
- Issues in development dependencies not shipped in binaries

## Security Best Practices for Users

- Always run vulnz with the latest version
- Use a dedicated API key for NVD access (set `NVD_API_KEY` environment variable)
- Review workspace directories periodically for orphaned files
- Run in a containerized or sandboxed environment when processing untrusted data sources

## Contact

For non-security questions, open a regular GitHub issue or contact the maintainer.
