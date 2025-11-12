# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in OpenEnclaven, please report it responsibly.

### Reporting Process

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please:

1. Email your findings to: [your-security-email@example.com]
2. Encrypt your message using our PGP key (available on request)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
   - Your contact information (for credit)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Triage**: Within 1 week
- **Fix Development**: Depends on severity (critical issues prioritized)
- **Public Disclosure**: After patch is released (coordinated disclosure)

### Scope

**In Scope**:
- Memory safety vulnerabilities (buffer overflows, use-after-free)
- Cryptographic implementation flaws
- Authentication/authorization bypasses
- Information disclosure
- Denial of service (non-trivial)
- Protocol implementation bugs

**Out of Scope**:
- Theoretical side-channel attacks without PoC
- Issues in dependencies (report to upstream)
- Social engineering attacks
- Physical access attacks
- Issues requiring root/admin privileges
- Denial of service via resource exhaustion (known limitation)

### Security Features

OpenEnclaven implements the following security measures:

1. **Memory Safety**: RAII, smart pointers, bounds checking
2. **Cryptography**: AES-256-GCM, constant-time operations
3. **Input Validation**: Size limits, sanitization
4. **Compiler Hardening**: Stack protector, PIE, FORTIFY_SOURCE
5. **Testing**: Fuzzing, sanitizers, static analysis

### Known Limitations

See README.md for a comprehensive threat model and known limitations.

## Security Updates

Security patches will be released as:
- Patch version bumps (e.g., 0.1.0 -> 0.1.1) for minor issues
- Minor version bumps (e.g., 0.1.0 -> 0.2.0) for moderate issues
- Major version bumps (e.g., 0.1.0 -> 1.0.0) for critical issues

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

### Security Advisories

Security advisories will be published at:
- GitHub Security Advisories
- Project security mailing list (TBD)

## Best Practices for Users

1. **Keep Updated**: Always use the latest version
2. **Run Tests**: Execute test suite before deployment
3. **Enable Sanitizers**: Use ASan/UBSan in development
4. **Review Code**: Audit code changes before production use
5. **Monitor Logs**: Watch for suspicious activity
6. **Limit Exposure**: Run in sandboxed environments
7. **Principle of Least Privilege**: Run with minimal permissions

## Vulnerability Disclosure Policy

We follow **coordinated disclosure**:

1. Reporter notifies us privately
2. We confirm and develop a fix
3. We notify affected users (if applicable)
4. We release a patch
5. We publish a security advisory
6. Reporter receives credit (if desired)

Typical timeline: 90 days from report to public disclosure.

## Credits

We appreciate security researchers who help improve OpenEnclaven's security. Reporters will be credited in:
- Security advisories
- Release notes
- CONTRIBUTORS.md (if desired)

## Legal

By reporting vulnerabilities responsibly, you agree to:
- Give us reasonable time to fix the issue
- Not exploit the vulnerability
- Not publicly disclose before our advisory

We will not pursue legal action against security researchers who:
- Report in good faith
- Do not access user data beyond proof-of-concept
- Do not perform destructive testing

## Contact

Security Team: [your-security-email@example.com]

PGP Key Fingerprint: [TBD]

---

**Remember**: This is a research prototype. No software provides absolute security. See README.md for comprehensive disclaimers.
