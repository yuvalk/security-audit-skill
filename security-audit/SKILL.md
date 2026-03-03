---
name: security-audit
description: "Comprehensive security code audit with threat modeling. Use when asked to: perform a security audit, find vulnerabilities, threat model a project, check for security issues, review code security, attack surface analysis, or STRIDE analysis."
allowed-tools: Read, Grep, Glob, Bash, Agent, WebSearch, WebFetch
---

# Security Code Audit

You are performing a comprehensive security code audit. This is NOT a simple grep-for-patterns exercise — you will first understand the project, model the actors and threats, and then conduct a targeted code review informed by that context.

## Methodology Overview

The audit follows four phases in order. Each phase produces an artifact that feeds the next:

1. **Project Understanding** → System Profile
2. **Actor Modeling** → Actor Model
3. **Threat Modeling** → Threat Register
4. **Code Security Review** → Findings & Report

Do not skip phases. Phase 4 findings without Phase 1-3 context are pattern-matching without understanding — they miss logic bugs and produce false positives.

---

## Phase 1 — Project Understanding

**Goal:** Build a complete mental model of the system before looking for vulnerabilities.

Load the detailed reference: `references/phase1-project-understanding.md`

### Steps

1. **Identify the tech stack** — Read manifest/config files to determine languages, frameworks, and dependencies:
   - `package.json`, `go.mod`, `requirements.txt`, `Gemfile`, `pom.xml`, `Cargo.toml`, `*.csproj`
   - Framework-specific configs: `next.config.js`, `settings.py`, `application.yml`, etc.

2. **Map the architecture** — Find and document:
   - **Entry points**: HTTP routes, gRPC services, CLI commands, message queue consumers, cron jobs
   - **Data stores**: Databases, caches, file storage, external APIs
   - **External integrations**: Third-party services, OAuth providers, payment gateways, email services

3. **Identify sensitive operations** — Look for:
   - Authentication flows (login, registration, password reset, token refresh)
   - Authorization checks (role/permission verification, resource ownership)
   - Payment/billing processing
   - Admin/management actions
   - Data export/import, bulk operations
   - User data deletion (GDPR/privacy)

4. **Trace data flows** — For each entry point, trace:
   - Where does user input enter? (request body, query params, headers, file uploads, WebSocket messages)
   - How is it processed? (validation, sanitization, transformation)
   - Where does it go? (database queries, file system, external APIs, rendered templates, logs)
   - What trust boundaries does it cross?

### Output: System Profile

```
## System Profile

**Project**: [name]
**Tech Stack**: [languages, frameworks, versions]
**Architecture**: [monolith/microservices/serverless/etc.]

### Entry Points
| Type | Location | Handler | Auth Required |
|------|----------|---------|---------------|
| ... | ... | ... | ... |

### Data Stores
| Store | Type | Contains | Sensitivity |
|-------|------|----------|-------------|
| ... | ... | ... | ... |

### External Integrations
| Service | Purpose | Data Exchanged |
|---------|---------|----------------|
| ... | ... | ... |

### Sensitive Operations
- [operation]: [location] — [why it's sensitive]

### Data Flow Summary
[Key data flows with trust boundary crossings noted]
```

---

## Phase 2 — Actor Modeling

**Goal:** Enumerate who interacts with the system and what they can do.

Load the detailed reference: `references/phase2-actor-modeling.md`

### Steps

1. **Enumerate actors** — Identify all entities that interact with the system:
   - Unauthenticated users (anonymous visitors, bots, scanners)
   - Authenticated users (by role: regular user, moderator, admin, superadmin)
   - Service accounts (internal microservices, CI/CD pipelines, monitoring)
   - External systems (partner APIs, OAuth providers, webhooks)
   - Background jobs (cron tasks, queue workers, scheduled processes)

2. **Define trust levels** — For each actor:
   - What authentication mechanism is used?
   - What authorization scope do they have?
   - What input vectors can they use? (which endpoints, what data)
   - What data can they see?
   - What actions can they perform?

3. **Identify trust boundaries** — Mark transitions where:
   - Untrusted input enters the system
   - Privilege level changes (user→admin context)
   - Data crosses network boundaries
   - Internal services call external ones

4. **Build access control matrix** — Map actors to resources and operations:

### Output: Actor Model

```
## Actor Model

### Actors
| Actor | Trust Level | Auth Mechanism | Input Vectors | Data Visibility |
|-------|-------------|----------------|---------------|-----------------|
| ... | ... | ... | ... | ... |

### Trust Boundaries
| Boundary | From (Trust Level) | To (Trust Level) | Crossing Point |
|----------|-------------------|-------------------|----------------|
| ... | ... | ... | ... |

### Access Control Matrix
| Resource/Operation | Unauth | User | Admin | Service |
|-------------------|--------|------|-------|---------|
| ... | ... | ... | ... | ... |
```

---

## Phase 3 — Threat Modeling (STRIDE)

**Goal:** Systematically identify threats at each trust boundary using the STRIDE framework.

Load the detailed reference: `references/phase3-threat-modeling.md`

### STRIDE Categories

For each trust boundary identified in Phase 2, evaluate all six categories:

| Category | Threat | Security Property | Question |
|----------|--------|--------------------|----------|
| **S**poofing | Identity impersonation | Authentication | Can an attacker pretend to be someone else? |
| **T**ampering | Data modification | Integrity | Can an attacker modify data they shouldn't? |
| **R**epudiation | Deniable actions | Non-repudiation | Can an attacker perform actions without audit trail? |
| **I**nformation Disclosure | Unauthorized data access | Confidentiality | Can an attacker read data they shouldn't? |
| **D**enial of Service | Availability degradation | Availability | Can an attacker degrade or prevent service? |
| **E**levation of Privilege | Exceeding authorization | Authorization | Can an attacker gain higher privileges? |

### Risk Rating

Rate each threat: **Likelihood** (1-5) × **Impact** (1-5) = **Risk Score** (1-25)

| Score | Rating |
|-------|--------|
| 20-25 | Critical |
| 13-19 | High |
| 7-12 | Medium |
| 3-6 | Low |
| 1-2 | Informational |

### Output: Threat Register

```
## Threat Register

| # | STRIDE | Threat | Boundary | Likelihood | Impact | Risk | Existing Mitigation |
|---|--------|--------|----------|------------|--------|------|---------------------|
| T1 | ... | ... | ... | ... | ... | ... | ... |
```

---

## Phase 4 — Code Security Review

**Goal:** Conduct a targeted code review driven by the threats identified in Phase 3.

Load the detailed references:
- `references/phase4-code-review.md` — grep patterns and checklists per security domain
- `references/vulnerability-patterns.md` — language-specific anti-patterns

### Priority Order

Review the eight security domains in this order, spending proportionally more time on domains where Phase 3 identified higher-risk threats:

1. **Input Validation & Injection** — SQL injection, command injection, template injection, XSS, path traversal, deserialization attacks, SSRF
2. **Authentication** — Password storage, session management, JWT validation, MFA bypass, account enumeration, credential stuffing protection
3. **Authorization** — IDOR, missing permission checks, horizontal/vertical privilege escalation, parameter manipulation, forced browsing
4. **Code Resiliency** — Error swallowing, missing resource cleanup, crash recovery, graceful degradation, race conditions, TOCTOU
5. **Availability & DoS** — Rate limiting, resource exhaustion, ReDoS, algorithmic complexity attacks, unbounded operations
6. **Cryptography & Secrets** — Hardcoded secrets, weak algorithms, bad RNG, TLS configuration, key management
7. **Data Protection** — PII in logs, data leaks in error messages, CORS misconfiguration, cookie flags, over-fetching in APIs, cache poisoning
8. **Dependencies** — Known CVEs, unmaintained packages, typosquatting risk, dependency confusion

### How to Review Each Domain

For each domain:
1. Consult the grep patterns in `references/phase4-code-review.md` for the project's language(s)
2. Search the codebase using those patterns
3. For each match, evaluate whether it's a true finding using the false-positive guidance
4. Cross-reference findings against the Threat Register — a pattern match at a trust boundary with a relevant threat is higher severity
5. Document findings using the format below

### Red Flags — Investigate Immediately

These patterns almost always indicate a vulnerability. If you find any, investigate immediately regardless of which phase you're in:

- `eval()`, `exec()`, `Function()` with user-controlled input
- String concatenation/interpolation in SQL queries
- Custom cryptographic implementations
- Hardcoded passwords, API keys, tokens, or secrets in source code
- Disabled security controls with TODO comments (`// TODO: add auth check`)
- Catch-all exception handlers that swallow errors silently
- `chmod 777` or overly permissive file/directory permissions
- HTTP (not HTTPS) for sensitive data transmission
- Deserialization of untrusted data (`pickle.loads`, `ObjectInputStream`, `unserialize`)
- `Access-Control-Allow-Origin: *` with credentials
- JWT with `alg: none` or symmetric signing with a weak secret
- XML parsing without disabling external entities (XXE)
- `dangerouslySetInnerHTML` with unsanitized input
- Debug/development mode enabled in production configs

---

## Severity Rating

| Severity | Criteria | Examples |
|----------|----------|---------|
| **Critical** | Remote, unauthenticated, leads to full compromise or mass data breach | Unauthenticated RCE, SQL injection exposing all user data, auth bypass |
| **High** | Exploitable with low privileges, significant data exposure or privilege escalation | Authenticated SQL injection, IDOR to other users' data, privilege escalation to admin |
| **Medium** | Requires specific conditions, limited scope impact | Stored XSS in admin panel, CSRF on non-critical actions, information disclosure of internal paths |
| **Low** | Minimal direct impact, defense-in-depth improvement | Missing security headers, verbose error messages, weak password policy |
| **Informational** | Poor practice, not directly exploitable in current context | Missing rate limiting on non-sensitive endpoints, outdated but unaffected dependency |

---

## Finding Format

For each vulnerability found, document:

```
### [SEVERITY] [FINDING-ID]: [Title]

**STRIDE Category:** [S/T/R/I/D/E]
**Security Domain:** [one of the 8 domains]
**Threat Register Link:** [T# from Phase 3]
**Location:** `file/path.ext:line_number`

**Code:**
```[language]
[relevant code snippet]
```

**Description:**
[What the vulnerability is and why the code is insecure]

**Attack Scenario:**
[Step-by-step description of how an attacker would exploit this]

**Impact:**
[What damage results from successful exploitation]

**Recommendation:**
```[language]
[specific fix with code example]
```

**References:**
- CWE-XXX: [title]
- OWASP: [relevant category]
```

---

## Final Report Structure

After completing all four phases, compile the final report. Load the template from `references/report-template.md`.

The report follows this structure:

1. **Executive Summary** — High-level findings count by severity, overall risk assessment, top 3 most critical issues
2. **System Profile** — From Phase 1 (condensed)
3. **Threat Model Summary** — From Phase 3 (top threats only)
4. **Findings** — All findings grouped by security domain, ordered by severity within each domain
5. **Prioritized Remediation Roadmap** — Ordered action items: fix critical/high first, then medium, then low; group related fixes; note quick wins vs. architectural changes

---

## Execution Notes

- **Be thorough but focused.** The threat model directs your code review. Spend more time on code paths that handle higher-risk threats.
- **Follow data flows.** Don't just grep for patterns — trace user input from entry point through processing to output/storage. Vulnerabilities live in the gaps between components.
- **Check for absence.** Missing controls are often worse than broken ones. No rate limiting? No CSRF protection? No input validation? These are findings.
- **Consider composition.** Individual components may be safe, but their combination may not be. A reflected value that's HTML-encoded but not URL-encoded in an `href` is still XSS.
- **Verify, don't assume.** Before reporting a finding, confirm the vulnerability actually exists by reading the surrounding code. Check for middleware, decorators, or framework-level protections that may mitigate the issue.
- **Use agents for parallel work.** When searching multiple security domains simultaneously, use the Agent tool to parallelize grep searches across different patterns.
