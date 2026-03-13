# Compliance: FedRAMP (IL2), DoD IL4, and EU Sovereignty

This document describes how Sentry and related components can be deployed to align with FedRAMP Moderate (Impact Level 2), DoD Impact Level 4 (IL4), and EU data sovereignty (EU SOV) requirements. It covers **application-level** technical and configuration guidance only; infrastructure, physical security, and contractual controls are out of scope.

---

## 1. FedRAMP Moderate (IL2)

### 1.1 TLS and cryptography

**Requirements:** FedRAMP Moderate expects TLS 1.2 or higher (TLS 1.0/1.1 disabled) and strong cipher suites per NIST SP 800-52 Rev. 2. Certificate validation must be enabled for outbound HTTPS.

**Current state:**

- Outbound HTTPS from Sentry uses `requests`/`urllib3` via `sentry.net.http.SafeSession`. TLS version and cipher behavior follow the Python runtime and system OpenSSL defaults.
- Integrations (Jira, Splunk, Webhooks, GitHub Enterprise, service hooks) default to **verify_ssl=True** (certificate verification on). Do not disable verification in production.
- For FIPS 140-3 alignment, Sentry supports `SENTRY_FIPS_MODE=1` (FIPS-aware hashing); Relay, Symbolicator, and Taskbroker can be built with FIPS features. See component-specific FIPS docs (e.g. `relay/docs/FIPS.md`, `symbolicator/docs/FIPS.md`).

**Operational guidance:**

- Use a Python 3.x build and system OpenSSL that default to TLS 1.2+ and disable TLS 1.0/1.1.
- Configure reverse proxies and load balancers in front of Sentry to enforce TLS 1.2+ and approved cipher suites (e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
- For deployments that must demonstrate application-level TLS configuration, set the **system.http-tls-minimum-version** option (e.g. to `"1.2"` or `"1.3"`). When set, outbound HTTPS sessions created via `build_session()` and `safe_urlopen()` use an SSLContext that enforces that minimum TLS version. See `sentry/net/http.py` and `sentry/http.py`.

### 1.2 Session and access control

**Requirements:** FedRAMP often expects configurable session timeouts and account lockout.

**Operational guidance:**

- Configure Django session and security settings appropriately:
  - `SESSION_COOKIE_AGE`: set an idle timeout (e.g. 15–60 minutes) per your policy.
  - `SESSION_SAVE_EVERY_REQUEST`: consider enabling to refresh the session on activity.
  - Use authentication backends that support lockout (e.g. after N failed attempts); Django and SSO providers can support this via configuration.
- No application code change is required if these are satisfied via Django settings and your auth provider.

### 1.3 Cookie security, HTTPS, and security headers

**Requirements:** FedRAMP expects session and CSRF cookies to be protected (Secure, HttpOnly, SameSite where applicable) and the application to be served only over HTTPS in production. Security headers (e.g. X-Frame-Options, CSP) reduce clickjacking and injection risks.

**Current state:**

- **Security headers:** Sentry sets `X-Frame-Options: deny`, `X-Content-Type-Options: nosniff`, and `X-XSS-Protection: 1; mode=block` via `SecurityHeadersMiddleware`; CSP is applied via `csp.middleware.CSPMiddleware`. Jira extension and some views may override X-Frame-Options where embedding is required.
- **Cookies:** Session and CSRF cookie behavior is controlled by Django settings. Sentry sets `SESSION_COOKIE_SAMESITE = None` by default to support certain SSO/IDP redirect flows; `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_HTTPONLY` are not set to strict values by default and depend on deployment.

**Operational guidance:**

- **Production:** Set `SESSION_COOKIE_SECURE = True` and `SESSION_COOKIE_HTTPONLY = True`. Set `CSRF_COOKIE_SECURE = True` when using HTTPS. For SameSite, use `SESSION_COOKIE_SAMESITE = "Lax"` (or `"Strict"`) if your SSO/IDP flows allow it; if you rely on cross-site POST redirects, leaving `None` may be necessary but should be documented and accepted as a compliance exception.
- **HTTPS only:** Ensure the application is only reachable over HTTPS in production (e.g. Django `SECURE_SSL_REDIRECT = True`, `SECURE_PROXY_SSL_HEADER` if behind a terminating proxy). Rely on the reverse proxy or load balancer to enforce TLS 1.2+ and strong ciphers for inbound connections.
- Keep security headers enabled and align CSP with your FedRAMP/IL4 policy (e.g. no unsafe-inline if required).

### 1.4 Password policy

**Requirements:** FedRAMP typically requires minimum length, complexity, and (where applicable) password history or breach checks.

**Current state:** Sentry configures Django password validators in `sentry/conf/server.py`, including minimum length, user-attribution similarity, common password, numeric-only, and maximum length, plus an optional Pwned Passwords validator. This meets or exceeds typical FedRAMP password strength expectations.

**Operational guidance:** Confirm that minimum length and complexity match your agency or FedRAMP policy (adjust validators in configuration if needed). Ensure the Pwned Passwords validator is enabled and acceptable for your network (it performs an outbound check).

### 1.5 Audit logging and retention

**Requirements:** Audit logs must be retained and protected per FedRAMP policy.

**Current state:**

- Sentry provides audit logging (e.g. `sentry.utils.audit`, `audit_log.get_event_id`, integration and workflow audit entries). Events are stored in the audit log backend configured for the deployment.
- Event retention is configurable via the **system.event-retention-days** option (`sentry/options/defaults.py`).

**Operational guidance:**

- Retain and protect audit logs according to your FedRAMP retention and access policies.
- Set **system.event-retention-days** (and any other retention options) to align with your data classification and FedRAMP requirements.

### 1.6 Sensitive data in logs

**Requirements:** Credentials, tokens, and other secrets must not appear in application or audit logs.

**Operational guidance:** Sentry uses structured logging and audit events; integration metadata is documented as non-sensitive where exposed. Operators should ensure that log sinks (and any log forwarding) do not capture request bodies or headers that may contain credentials, and that options marked `FLAG_CREDENTIAL` are never logged. Review custom logging or integrations for accidental exposure of secrets.

### 1.7 Other operational expectations

- **Encryption at rest:** FedRAMP/IL4 typically require encryption at rest for sensitive data. Use encrypted databases, caches, and object storage (e.g. database and storage encryption offered by your cloud or platform) per your policy; the application does not implement encryption at rest itself.
- **Multi-factor authentication (MFA):** Enable MFA for user and privileged access where required by policy. Use an identity provider or SSO that supports MFA and configure Sentry to use it.
- **Patches and dependencies:** Keep the application and its dependencies patched per your vulnerability management and FedRAMP continuous monitoring requirements.

For full-stack deployments (Sentry, Relay, Snuba, Symbolicator, Taskbroker, etc.), see the self-hosted documentation and each component’s FIPS or security documentation for build and runtime configuration.

---

## 2. DoD Impact Level 4 (IL4)

IL4 builds on FedRAMP Moderate with stricter cryptographic and assurance expectations.

**Application-level guidance:**

- Follow all FedRAMP Moderate (IL2) guidance above (TLS 1.2+, certificate verification, session/audit/retention).
- Use **FIPS 140-2 or 140-3 validated** cryptographic modules where required:
  - Relay, Symbolicator, and Taskbroker support FIPS builds (OpenSSL FIPS provider). Build and run them with the `fips` feature and a FIPS-validated OpenSSL build when IL4 requires it.
  - Sentry supports FIPS-aware hashing when `SENTRY_FIPS_MODE=1` is set.
- Prefer TLS 1.3 where available; configure OpenSSL and proxies to use TLS 1.2 minimum and approved cipher suites. Document that the application stack supports this when so configured.
- Any IL4-specific hardening (e.g. stricter cipher lists, hardware-backed crypto) is achieved via deployment and OpenSSL/platform configuration; the application code does not preclude it.

---

## 3. EU Sovereignty (EU SOV) and EU Data Boundary

### 3.1 Data residency and regional processing

**Requirements:** EU SOV and related frameworks (e.g. EU Data Boundary, sovereign cloud) often require that personal data be stored and processed **within the EU** (or a designated sovereign partition).

**Current state:**

- Sentry supports **regions** and **relocation** (e.g. `system.region`, `relocation.selectable-regions`, `relocation.enabled`). These allow multi-region and migration but **do not enforce** “EU only” or “no transfer outside EU” in application code.
- Data residency is achieved by **where** you deploy: run Sentry and all backing services (databases, caches, object storage, Relay, Snuba, etc.) **only in EU regions or an EU sovereign cloud**. Do not configure regions or integrations that send data to non-EU endpoints.

**Operational guidance:**

- Deploy the full stack (Sentry, Relay, Snuba, Symbolicator, Taskbroker, etc.) and all data stores in EU-only regions or an EU sovereign cloud (e.g. AWS European Sovereign Cloud, Azure EU Data Boundary).
- Use **relocation.selectable-regions** and related options to reflect EU-only targets if you use the relocation feature.
- Do not enable integrations or outbound services that send personal data to non-EU systems unless you have appropriate transfer mechanisms (see below).

### 3.2 Third-country transfers

**Requirements:** EU law (e.g. GDPR, Data Act) restricts transfers of personal data outside the EU unless safeguards (e.g. SCCs, BCRs, adequacy decisions) are in place.

**Current state:**

- The application does **not** implement transfer-restriction logic (e.g. blocking specific endpoints or regions). Compliance is achieved through deployment, network policy, and contracts.

**Operational guidance:**

- Ensure that outbound connections from EU deployments do not send personal data to systems outside the EU (or to third countries without appropriate transfer mechanisms).
- Rely on deployment boundaries, DPA/contracts, and cloud provider commitments (e.g. EU Data Boundary) to satisfy transfer requirements.

### 3.3 PII and data minimization

**Current state:**

- Relay and Sentry support **PII scrubbing** and configurable data scrubbing (e.g. `sentry:relay_pii_config`, project datascrubbers). This supports GDPR-style minimization and control over what is stored and transmitted.

**Operational guidance:**

- Configure PII scrubbing and data scrubbing for EU/GDPR deployments so that only necessary data is retained and exposed.

---

## 4. Summary

| Framework     | Area                | Application support / action |
|---------------|---------------------|-------------------------------|
| FedRAMP IL2   | TLS 1.2+, ciphers   | Rely on stack + proxies; optional **system.http-tls-minimum-version** |
| FedRAMP IL2   | FIPS / verify_ssl   | FIPS mode and verify_ssl=True by default in place |
| FedRAMP IL2   | Session / audit     | Configure Django + retention; audit log exists |
| FedRAMP IL2   | Cookie / HTTPS      | Set Secure, HttpOnly, SameSite; HTTPS-only in production |
| FedRAMP IL2   | Password policy     | Strong validators ship by default; confirm vs policy |
| FedRAMP IL2   | Security headers    | X-Frame-Options, CSP, etc. in place; keep enabled |
| FedRAMP IL2   | No secrets in logs  | Operators ensure credentials not logged |
| IL4           | Same + FIPS validated | Use FIPS builds; document TLS/crypto config |
| EU SOV        | Data residency      | EU-only deployment; no app-level residency enforcement |
| EU SOV        | Transfers           | Deployment and contracts; no app-level enforcement |
| EU SOV        | PII / minimization  | PII scrubbing and datascrubbers available |

This document does not constitute a formal compliance certification. Operators are responsible for validating their deployment against the applicable frameworks and authority requirements.
