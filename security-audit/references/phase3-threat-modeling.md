# Phase 3 Reference: Threat Modeling (STRIDE)

## STRIDE Deep Dive

Apply each STRIDE category at every trust boundary identified in Phase 2. For each, consider what specific threats apply given the system's architecture and actors.

### S — Spoofing (Authentication Threats)

**Question:** Can an attacker assume another identity?

#### Threat Examples by Component

| Component | Spoofing Threat | What to Check |
|-----------|----------------|---------------|
| Login endpoint | Credential stuffing, brute force | Rate limiting, account lockout, CAPTCHA |
| Session management | Session hijacking, fixation | Secure cookie flags, session regeneration on auth |
| JWT tokens | Token forgery, stolen tokens | Signature verification, expiration, `alg` handling |
| API keys | Key theft, key guessing | Key entropy, rotation, scope limitation |
| OAuth flow | Authorization code interception | State parameter, PKCE, redirect URI validation |
| Service-to-service | Service impersonation | Mutual TLS, signed requests, shared secrets |
| Email-based auth | Email spoofing, link interception | Token expiration, one-time use, HTTPS links |
| Webhook receivers | Forged webhook calls | Signature verification, IP allowlisting |
| WebSocket | Connection hijacking | Origin verification, token-based auth |

#### Common CWEs
- CWE-287: Improper Authentication
- CWE-384: Session Fixation
- CWE-346: Origin Validation Error
- CWE-290: Authentication Bypass by Spoofing

---

### T — Tampering (Integrity Threats)

**Question:** Can an attacker modify data they shouldn't?

#### Threat Examples by Component

| Component | Tampering Threat | What to Check |
|-----------|-----------------|---------------|
| Request body | Parameter manipulation, mass assignment | Input validation, allowlisting fields |
| URL parameters | IDOR via ID manipulation | Authorization checks on every access |
| Cookies | Cookie tampering | Signed/encrypted cookies, server-side sessions |
| File uploads | Malicious file content | Content-type validation, file scanning |
| Database records | Unauthorized modification | Row-level authorization, audit logging |
| Configuration | Config file modification | File permissions, integrity monitoring |
| Client-side storage | localStorage/cookie tampering | Server-side validation of all client data |
| API responses | Response manipulation (MITM) | HTTPS, HSTS, certificate pinning |
| Webhook payloads | Payload modification in transit | HMAC signature verification |

#### Common CWEs
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-352: Cross-Site Request Forgery
- CWE-915: Mass Assignment
- CWE-639: Authorization Bypass Through User-Controlled Key

---

### R — Repudiation (Audit/Logging Threats)

**Question:** Can an attacker perform actions without a trace?

#### Threat Examples by Component

| Component | Repudiation Threat | What to Check |
|-----------|-------------------|---------------|
| Auth events | Unlogged login attempts/failures | Auth event logging (success + failure) |
| Admin actions | Unaudited admin operations | Admin audit trail |
| Data modifications | Untracked data changes | Change history, audit columns |
| API calls | Unlogged API access | Request logging with actor identity |
| Financial transactions | Undeniable transaction records | Transaction logging, integrity protection |
| User consent | Unrecorded consent/agreement | Consent logging with timestamps |
| Deletion operations | Unrecoverable deletions without audit | Soft deletes, deletion logging |

#### What Good Logging Looks Like
- **Who**: Authenticated identity (user ID, service name)
- **What**: Action performed (create, read, update, delete)
- **When**: Timestamp (UTC, ISO 8601)
- **Where**: Source IP, endpoint, resource identifier
- **Outcome**: Success or failure with reason
- **NOT**: Sensitive data (passwords, tokens, PII in logs)

#### Common CWEs
- CWE-778: Insufficient Logging
- CWE-223: Omission of Security-relevant Information
- CWE-532: Insertion of Sensitive Information into Log File

---

### I — Information Disclosure (Confidentiality Threats)

**Question:** Can an attacker access data they shouldn't see?

#### Threat Examples by Component

| Component | Disclosure Threat | What to Check |
|-----------|------------------|---------------|
| Error responses | Stack traces, internal paths, DB schema | Custom error handlers, production error config |
| API responses | Over-fetching, exposing internal fields | Response serialization, field selection |
| Logs | PII, tokens, passwords in logs | Log sanitization, structured logging |
| Debug endpoints | Enabled debug/profiling in production | Debug mode configuration |
| Directory listing | Exposed file structure | Web server configuration |
| Source maps | Client-side source code exposure | Source map deployment config |
| Git history | Secrets in previous commits | Secret scanning, `.gitignore` |
| Error messages | Account enumeration via login/signup errors | Generic error messages |
| HTTP headers | Server version, framework info | Header stripping configuration |
| Timing attacks | Username existence via response timing | Constant-time comparisons |
| CORS misconfiguration | Cross-origin data access | CORS policy review |
| Cache headers | Sensitive data cached in browser/CDN | Cache-Control, no-store for sensitive |

#### Common CWEs
- CWE-200: Exposure of Sensitive Information
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-548: Exposure of Information Through Directory Listing

---

### D — Denial of Service (Availability Threats)

**Question:** Can an attacker degrade or prevent service?

#### Threat Examples by Component

| Component | DoS Threat | What to Check |
|-----------|-----------|---------------|
| API endpoints | Request flooding | Rate limiting, throttling |
| File uploads | Large file uploads | File size limits, streaming |
| Search/query | Complex query attacks | Query complexity limits, timeouts |
| Regular expressions | ReDoS (catastrophic backtracking) | Regex review for nested quantifiers |
| GraphQL | Deep/wide query nesting | Query depth/complexity limits |
| WebSocket | Connection exhaustion | Connection limits, heartbeats |
| Database | Slow query attacks | Query timeouts, connection pools |
| Memory | Memory exhaustion via large payloads | Request size limits, streaming parsing |
| CPU | Algorithmic complexity attacks | Input size limits, efficient algorithms |
| External dependencies | Cascading failure from downstream | Circuit breakers, timeouts, fallbacks |
| Background jobs | Job queue flooding | Queue size limits, deduplication |
| Account lockout | Locking out legitimate users | Lockout duration, CAPTCHA alternatives |

#### Common CWEs
- CWE-400: Uncontrolled Resource Consumption
- CWE-1333: Inefficient Regular Expression Complexity
- CWE-770: Allocation of Resources Without Limits
- CWE-834: Excessive Iteration

---

### E — Elevation of Privilege (Authorization Threats)

**Question:** Can an attacker gain permissions beyond their authorization?

#### Threat Examples by Component

| Component | EoP Threat | What to Check |
|-----------|-----------|---------------|
| API endpoints | Missing authorization checks | Auth middleware on all protected routes |
| URL/path parameters | IDOR via ID guessing/enumeration | Ownership verification, UUID vs sequential IDs |
| Role management | Self-assignment of roles | Role change authorization |
| Admin panel | Accessing admin routes without admin role | Role-based access control on admin routes |
| File access | Path traversal to restricted files | Path canonicalization, chroot/jail |
| Feature flags | Bypassing feature gates | Server-side feature flag enforcement |
| API versioning | Accessing deprecated unpatched endpoints | Deprecation enforcement, consistent security |
| Batch operations | Bypassing per-item authorization | Authorization check on each item in batch |
| GraphQL | Accessing unauthorized fields/mutations | Field-level authorization |
| Mass assignment | Setting admin/role fields via request | Allowlisted fields for updates |
| JWT claims | Modifying claims (role, permissions) | Signature verification, server-side claims |

#### Common CWEs
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-269: Improper Privilege Management

---

## Risk Scoring Matrix

### Likelihood Assessment

| Score | Likelihood | Criteria |
|-------|-----------|----------|
| 5 | **Almost Certain** | Publicly known technique, automated tools exist, no special access needed |
| 4 | **Likely** | Known technique, requires basic skills, low barrier |
| 3 | **Possible** | Requires moderate skill or specific conditions |
| 2 | **Unlikely** | Requires high skill, insider knowledge, or rare conditions |
| 1 | **Rare** | Requires exceptional circumstances or theoretical only |

### Impact Assessment

| Score | Impact | Criteria |
|-------|--------|----------|
| 5 | **Critical** | Full system compromise, mass data breach, financial loss at scale |
| 4 | **Major** | Significant data exposure, service-wide outage, individual financial loss |
| 3 | **Moderate** | Limited data exposure, partial service degradation, reputational damage |
| 2 | **Minor** | Minimal data exposure, brief disruption, limited scope |
| 1 | **Negligible** | No real data exposure, cosmetic impact, theoretical concern |

### Risk Score = Likelihood × Impact

| | Impact 1 | Impact 2 | Impact 3 | Impact 4 | Impact 5 |
|---|---------|---------|---------|---------|---------|
| **Likelihood 5** | 5 (Low) | 10 (Med) | 15 (High) | 20 (Crit) | 25 (Crit) |
| **Likelihood 4** | 4 (Low) | 8 (Med) | 12 (Med) | 16 (High) | 20 (Crit) |
| **Likelihood 3** | 3 (Low) | 6 (Low) | 9 (Med) | 12 (Med) | 15 (High) |
| **Likelihood 2** | 2 (Info) | 4 (Low) | 6 (Low) | 8 (Med) | 10 (Med) |
| **Likelihood 1** | 1 (Info) | 2 (Info) | 3 (Low) | 4 (Low) | 5 (Low) |

---

## STRIDE to CWE/OWASP Mapping

| STRIDE | OWASP Top 10 (2021) | Key CWEs |
|--------|---------------------|----------|
| Spoofing | A07: Identification and Authentication Failures | CWE-287, CWE-384, CWE-346 |
| Tampering | A03: Injection, A08: Software and Data Integrity Failures | CWE-345, CWE-352, CWE-915 |
| Repudiation | A09: Security Logging and Monitoring Failures | CWE-778, CWE-223 |
| Information Disclosure | A01: Broken Access Control, A02: Cryptographic Failures | CWE-200, CWE-209, CWE-532 |
| Denial of Service | — (not in Top 10, but critical) | CWE-400, CWE-1333, CWE-770 |
| Elevation of Privilege | A01: Broken Access Control | CWE-862, CWE-863, CWE-639, CWE-269 |

---

## Threat Register Entry Example

```
| # | STRIDE | Threat | Boundary | L | I | Risk | Existing Mitigation |
|---|--------|--------|----------|---|---|------|---------------------|
| T1 | S | Credential stuffing on /login | Internet→App | 5 | 4 | 20 Crit | Rate limiting (5 req/min), but no CAPTCHA |
| T2 | E | IDOR on /api/users/:id/profile | App→DB | 4 | 4 | 16 High | Auth required, but no ownership check |
| T3 | I | Stack traces in error responses | App→Internet | 4 | 2 | 8 Med | Custom error handler in prod, but some exceptions leak |
| T4 | T | Mass assignment on user update | Internet→App | 3 | 4 | 12 Med | No field allowlisting on PUT /users/:id |
| T5 | D | ReDoS in email validation regex | Internet→App | 3 | 3 | 9 Med | No input length limit before regex |
| T6 | R | No audit log for admin actions | Admin→App | 2 | 3 | 6 Low | General request logging exists |
```
