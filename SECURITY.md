# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

S.T.A.R. is a security tool that operates at the kernel level. We take security vulnerabilities in this project extremely seriously.

### Responsible Disclosure

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities through one of these channels:

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the Security tab of this repository.
2. **Direct Contact**: Reach out via [naveed-gung.dev](https://naveed-gung.dev) with the subject line "S.T.A.R. Security Report".

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)
- Your contact information for follow-up

### Response Timeline

- **Acknowledgment**: Within 48 hours of report
- **Initial Assessment**: Within 7 days
- **Fix Development**: Depends on severity (critical: 72 hours, high: 14 days, medium: 30 days)
- **Public Disclosure**: Coordinated with reporter after fix is released

### Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| Critical | Remote code execution, kernel compromise | Buffer overflow in driver communication |
| High | Privilege escalation, detection bypass | Evasion of memory scanning |
| Medium | Information disclosure, DoS | Crash via malformed input |
| Low | Minor issues, hardening | Missing input validation |

## Security Design Principles

S.T.A.R. follows these security principles as defined in the SRS:

- **Local Operation Only**: No outbound network connections from monitoring components
- **Non-Destructive**: Read-only access to system structures by default
- **Anti-Tampering**: Self-integrity checking at runtime
- **Data Minimization**: Configurable collection levels, automatic PII sanitization
- **Audit Trail**: Complete logging with cryptographic signing

## Code Signing

All release binaries and kernel drivers are digitally signed. Verify signatures before installation.

## Acknowledgments

We maintain a hall of fame for security researchers who responsibly disclose vulnerabilities. Contributors will be credited (with permission) in release notes.
