# Security Policy

## Reporting a Vulnerability
Please open a GitHub Security Advisory or contact the maintainer privately.

## Operational Guidance
- Do not embed Loki credentials in Logpush destination URLs.
- Use Worker secrets for:
  - LOGPUSH_TOKEN
  - LOKI_AUTH_HEADER
- Minimize log fields; avoid sending cookies/headers unless necessary.
- Rotate LOGPUSH_TOKEN if you suspect the Logpush job config has been exposed.
