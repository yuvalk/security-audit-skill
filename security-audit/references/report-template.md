# Security Audit Report Template

Use this template to compile the final report after completing all four phases.

---

# Security Audit Report: [Project Name]

**Date:** [YYYY-MM-DD]
**Auditor:** Claude Code Security Audit
**Scope:** [description of what was audited — full codebase / specific modules / etc.]
**Commit:** [git commit hash at time of audit]

---

## 1. Executive Summary

### Overview

A comprehensive security audit was performed on [Project Name], covering threat modeling and code review across eight security domains. The audit identified **[N] findings**: **[X] Critical**, **[Y] High**, **[Z] Medium**, **[W] Low**, and **[V] Informational**.

### Risk Assessment

**Overall Risk Level:** [Critical / High / Medium / Low]

[2-3 sentences summarizing the overall security posture. Note the most significant areas of concern and any notably well-implemented security controls.]

### Top 3 Critical Issues

1. **[Finding ID]: [Title]** — [One sentence summary and impact]
2. **[Finding ID]: [Title]** — [One sentence summary and impact]
3. **[Finding ID]: [Title]** — [One sentence summary and impact]

### Findings Summary

| Severity | Count |
|----------|-------|
| Critical | [N] |
| High | [N] |
| Medium | [N] |
| Low | [N] |
| Informational | [N] |
| **Total** | **[N]** |

---

## 2. System Profile

[Condensed version of the Phase 1 System Profile artifact. Include:]

**Tech Stack:** [languages, frameworks, key dependencies]
**Architecture:** [monolith/microservices/serverless]
**Entry Points:** [count and types — N HTTP endpoints, M WebSocket handlers, etc.]
**Data Stores:** [list with sensitivity level]
**External Integrations:** [list]

---

## 3. Threat Model Summary

[Condensed version of the Phase 3 Threat Register. Include only the top threats:]

| # | STRIDE | Threat | Risk | Status |
|---|--------|--------|------|--------|
| T1 | ... | ... | ... | Finding [ID] / Mitigated / Accepted |

---

## 4. Findings

### 4.1 Input Validation & Injection

[Findings in this domain, ordered by severity]

---

#### [CRITICAL] INJ-001: [Title]

**STRIDE Category:** [S/T/R/I/D/E]
**Security Domain:** Input Validation & Injection
**Threat Register Link:** T[N]
**Location:** `path/to/file.ext:42`

**Code:**
```[language]
// Vulnerable code snippet
```

**Description:**
[What the vulnerability is. Be specific about why this code is insecure and what assumptions are violated.]

**Attack Scenario:**
1. Attacker [does X]
2. This causes [Y]
3. Resulting in [Z]

**Impact:**
[What damage results. Be specific: data types exposed, operations available, blast radius.]

**Recommendation:**
```[language]
// Specific fix code
```

**References:**
- CWE-XXX: [Title](https://cwe.mitre.org/data/definitions/XXX.html)
- OWASP: [Category](https://owasp.org/Top10/)

---

### 4.2 Authentication

[Findings in this domain, ordered by severity]

---

### 4.3 Authorization

[Findings in this domain, ordered by severity]

---

### 4.4 Code Resiliency

[Findings in this domain, ordered by severity]

---

### 4.5 Availability & DoS

[Findings in this domain, ordered by severity]

---

### 4.6 Cryptography & Secrets

[Findings in this domain, ordered by severity]

---

### 4.7 Data Protection

[Findings in this domain, ordered by severity]

---

### 4.8 Dependencies

[Findings in this domain, ordered by severity]

---

## 5. Prioritized Remediation Roadmap

### Immediate (Fix within 24-48 hours)

These are critical/high severity findings that are actively exploitable:

| Priority | Finding | Effort | Description |
|----------|---------|--------|-------------|
| 1 | [ID] | [Low/Med/High] | [One-line description of the fix] |
| 2 | [ID] | [Low/Med/High] | [One-line description of the fix] |

### Short-term (Fix within 1-2 weeks)

Medium severity findings and quick-win improvements:

| Priority | Finding | Effort | Description |
|----------|---------|--------|-------------|
| 3 | [ID] | [Low/Med/High] | [One-line description of the fix] |
| 4 | [ID] | [Low/Med/High] | [One-line description of the fix] |

### Medium-term (Fix within 1-3 months)

Architectural improvements and defense-in-depth measures:

| Priority | Finding | Effort | Description |
|----------|---------|--------|-------------|
| 5 | [ID] | [Low/Med/High] | [One-line description of the fix] |

### Long-term (Plan and schedule)

Strategic security improvements:

| Priority | Finding | Effort | Description |
|----------|---------|--------|-------------|
| 6 | [ID] | [Low/Med/High] | [One-line description of the fix] |

### Quick Wins

These are low-effort fixes that can be done immediately regardless of severity:

- [ ] [Finding ID]: [one-line fix description]
- [ ] [Finding ID]: [one-line fix description]

### Grouped Fixes

These findings share a common root cause and should be fixed together:

**[Group name — e.g., "Missing authorization middleware"]:**
- [Finding ID], [Finding ID], [Finding ID]
- Fix: [shared remediation approach]

---

## Example Finding (for reference — delete this section in actual reports)

The following is a fully worked example demonstrating the expected level of detail:

---

#### [HIGH] AUTH-001: JWT Tokens Accepted Without Algorithm Verification

**STRIDE Category:** Spoofing
**Security Domain:** Authentication
**Threat Register Link:** T2
**Location:** `src/middleware/auth.js:23`

**Code:**
```javascript
const decoded = jwt.verify(token, process.env.JWT_SECRET);
```

**Description:**
The JWT verification call does not specify which algorithms are accepted. An attacker who can influence the token's `alg` header could potentially exploit algorithm confusion attacks. If the server's public key is known (common with RS256), an attacker could forge tokens by switching to HS256 and using the public key as the HMAC secret.

**Attack Scenario:**
1. Attacker obtains the server's public key (often exposed at `/.well-known/jwks.json` or in source code)
2. Attacker crafts a JWT with `alg: HS256` and signs it using the public key as the HMAC secret
3. Server verifies the token using `jwt.verify(token, publicKey)` — since no algorithm is specified, it accepts HS256 and treats the public key as the HMAC secret
4. The forged token passes verification, granting the attacker arbitrary identity

**Impact:**
Complete authentication bypass. An attacker can forge tokens for any user, including administrators, gaining full access to all authenticated functionality and data.

**Recommendation:**
```javascript
const decoded = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],  // Explicitly specify allowed algorithms
  issuer: 'myapp',        // Optional: verify issuer
  audience: 'myapp-api',  // Optional: verify audience
});
```

**References:**
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- OWASP: A07:2021 — Identification and Authentication Failures
- [Auth0 Blog: Critical Vulnerabilities in JSON Web Token Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
