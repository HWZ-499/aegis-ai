# CWE-918 Server-Side Request Forgery

Tags: cwe-918, ssrf, outbound-http, allowlist

SSRF occurs when server-side code makes network requests to a URL controlled by
the user. Attackers may reach internal services, cloud metadata endpoints, or
private network resources.

## Fix template

- Use a strict destination allowlist and block private, loopback, link-local,
  and metadata address ranges after DNS resolution.
- Normalize and validate scheme, host, port, and redirects.
- Disable redirects or revalidate every redirect target.
- Prefer mapping user choices to server-side known endpoints instead of accepting
  arbitrary URLs.
