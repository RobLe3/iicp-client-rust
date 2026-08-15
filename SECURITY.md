# Security policy

## Supported releases

Security fixes target the latest published release line. Older releases may not
receive backports. Confirm the installed version before reporting a problem and
upgrade to the latest compatible release when practical.

## Reporting a vulnerability

Use the repository's [private security-advisory form](https://github.com/RobLe3/iicp-client-rust/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include the affected version, execution mode, minimal reproduction, expected
security boundary and observed impact. Remove credentials, task payloads,
private topology, personal data and production records. If a report affects
protocol semantics or several implementations, the maintainers will coordinate
a sanitized public correction in the [IICP specification repository](https://github.com/RobLe3/IICP) after disclosure is safe.

## Security boundary

Transport encryption does not hide plaintext from the selected execution
provider. Directory data is discovery and policy evidence, not provider
authentication by itself. Unsupported required security or confidentiality
profiles must fail closed. See the public [IICP adversary and trust model](https://github.com/RobLe3/IICP/blob/main/docs/security/privacy-adversary-and-trust-model.md) for the shared boundary.

A pull request, issue or successful test run does not authorize a package
publication, service deployment or disclosure of private incident material.
