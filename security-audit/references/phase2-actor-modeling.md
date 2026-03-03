# Phase 2 Reference: Actor Modeling

## Actor Taxonomy

### Standard Actor Types

Every system has some subset of these actor types. Enumerate which ones apply:

#### Human Actors

| Actor | Description | Typical Trust Level |
|-------|-------------|---------------------|
| **Anonymous visitor** | No authentication, browsing public content | Untrusted |
| **Unauthenticated user** | At login/registration page, providing credentials | Untrusted |
| **Authenticated user** | Logged in with standard permissions | Low trust |
| **Premium/paid user** | Authenticated with additional entitlements | Low trust |
| **Moderator** | Content moderation privileges | Medium trust |
| **Support agent** | Can view/modify user accounts for support | Medium-High trust |
| **Admin** | System administration privileges | High trust |
| **Superadmin/Owner** | Full system access, can manage other admins | Highest trust |

#### System Actors

| Actor | Description | Typical Trust Level |
|-------|-------------|---------------------|
| **Internal microservice** | Service-to-service within the same trust domain | High trust |
| **Background worker** | Async job processor (queue consumer, cron) | Medium-High trust |
| **CI/CD pipeline** | Deployment and build automation | High trust |
| **Monitoring/observability** | Health checks, metrics collection | Medium trust |
| **External partner API** | Third-party system calling our API | Varies (verify) |
| **Webhook sender** | External service sending event notifications | Low trust (verify signatures) |
| **OAuth provider** | Identity provider (Google, GitHub, etc.) | Medium trust (verify tokens) |
| **CDN/proxy** | Content delivery, request forwarding | Medium trust |

### Trust Level Definitions

| Level | Name | Definition | Verification Required |
|-------|------|------------|----------------------|
| 0 | **Untrusted** | No identity verification, assume hostile | Full input validation, rate limiting |
| 1 | **Identified** | Identity claimed but not verified (pre-auth) | Input validation, brute-force protection |
| 2 | **Authenticated** | Identity verified via credentials/token | Authorization checks on every operation |
| 3 | **Authorized** | Authenticated + confirmed permissions for action | Audit logging, scope enforcement |
| 4 | **Privileged** | Administrative access, elevated permissions | MFA, session controls, audit everything |
| 5 | **System** | Internal service with verified identity | Mutual TLS, signed requests, least privilege |

## Building the Actor Model

### Step 1: Discover Actors from Code

Search for authentication and authorization patterns to find which actors the system recognizes:

```
# Role definitions
grep -rn "role.*=\|roles\s*[:=]\|enum.*Role\|ROLE_\|UserRole\|isAdmin\|is_admin" \
  --include="*.{js,ts,py,go,rb,java}"

# Permission checks
grep -rn "hasPermission\|can\(\|authorize\|@Authorize\|@PreAuthorize\|PermissionRequired\|requires_permission" \
  --include="*.{js,ts,py,go,rb,java}"

# User types/models
grep -rn "userType\|user_type\|accountType\|account_type\|UserKind" \
  --include="*.{js,ts,py,go,rb,java}"

# Auth middleware usage
grep -rn "requireAuth\|isAuthenticated\|@login_required\|@auth_required\|Authenticated\|Protected" \
  --include="*.{js,ts,py,go,rb,java}"

# API key / service auth
grep -rn "apiKey\|api_key\|serviceToken\|service_token\|x-api-key\|Bearer" \
  --include="*.{js,ts,py,go,rb,java}"
```

### Step 2: Map Input Vectors per Actor

For each actor, document how they interact with the system:

| Input Vector | Description | Security Concern |
|-------------|-------------|------------------|
| HTTP request body | JSON, form data, multipart | Injection, deserialization |
| URL path parameters | `/users/:id`, `/api/v1/resource/:slug` | IDOR, path traversal |
| Query parameters | `?search=`, `?page=`, `?filter=` | Injection, parameter pollution |
| HTTP headers | `Authorization`, `Cookie`, custom headers | Header injection, spoofing |
| File uploads | Images, documents, CSV imports | Malicious files, path traversal, XXE |
| WebSocket messages | Real-time bidirectional data | Injection, authorization bypass |
| GraphQL queries | Nested queries, mutations | Query complexity attacks, over-fetching |
| Email input | Reply-to processing, inbound email | Header injection, phishing |

### Step 3: Define Data Visibility per Actor

For each data type in the system, document which actors can see it:

```
## Data Visibility Matrix

| Data Type | Anonymous | User (own) | User (other) | Admin | Service |
|-----------|-----------|------------|--------------|-------|---------|
| Username  | Public    | Read/Write | Read         | R/W   | Read    |
| Email     | No        | Read/Write | No           | Read  | Read    |
| Password  | No        | Write      | No           | Reset | No      |
| Profile   | Public    | Read/Write | Read          | R/W   | Read    |
| Messages  | No        | Own only   | No           | All   | All     |
| Billing   | No        | Own only   | No           | Read  | Read    |
| Admin logs| No        | No         | No           | Read  | Write   |
```

## Trust Boundaries

### Common Trust Boundary Patterns

| Boundary | From | To | What Crosses |
|----------|------|----|-------------|
| **Internet → Application** | Untrusted network | Web server/API | HTTP requests, user input |
| **Application → Database** | Application code | Database engine | SQL queries, data |
| **Application → External API** | Internal service | Third-party | API calls, credentials |
| **Frontend → Backend** | Browser/client | Server | API calls, tokens |
| **Service → Service** | Microservice A | Microservice B | Internal API calls, data |
| **User → Admin** | Regular user context | Admin context | Privilege elevation |
| **Upload → Processing** | User-submitted file | File processor | File content |
| **Config → Runtime** | Config/env files | Running application | Secrets, settings |

### Trust Boundary Misassumptions

Common mistakes in trust boundary design — check for these:

1. **"Internal network is trusted"** — Assuming service-to-service calls don't need auth because they're on the same network. Lateral movement after initial breach.

2. **"Frontend validation is sufficient"** — Trusting client-side validation without server-side re-validation. All client-side checks are bypassable.

3. **"Authenticated means authorized"** — Checking if a user is logged in but not checking if they have permission for the specific resource/action. Classic IDOR source.

4. **"Admin actions don't need validation"** — Admins still submit user input that can contain injection payloads. Admin panels are often less hardened.

5. **"Webhook signatures are always checked"** — Receiving webhook data from external services without verifying the signature. Attackers can forge webhook calls.

6. **"Environment variables are secure"** — Assuming env vars can't leak through debug endpoints, error messages, or child processes.

7. **"Database queries from internal services are safe"** — Internal services can still have SQL injection if they pass through user-originated data without parameterization.

8. **"File uploads are just data"** — Uploaded files can contain executable code, path traversal sequences, XML with external entities, or polyglot payloads.

## Access Control Matrix Template

Build this matrix by combining the actors from Step 1, the resources from Phase 1's System Profile, and the operations the system supports:

```
## Access Control Matrix

### Resource: User Profile
| Operation | Anonymous | Owner | Other User | Admin | Service |
|-----------|-----------|-------|------------|-------|---------|
| View      | [?]       | [?]   | [?]        | [?]   | [?]     |
| Edit      | [?]       | [?]   | [?]        | [?]   | [?]     |
| Delete    | [?]       | [?]   | [?]        | [?]   | [?]     |

### Resource: API Key
| Operation | Anonymous | Owner | Other User | Admin | Service |
|-----------|-----------|-------|------------|-------|---------|
| Create    | [?]       | [?]   | [?]        | [?]   | [?]     |
| List      | [?]       | [?]   | [?]        | [?]   | [?]     |
| Revoke    | [?]       | [?]   | [?]        | [?]   | [?]     |
```

Mark each cell as: **Allow**, **Deny**, **N/A**, or **UNCLEAR** (needs investigation).

Cells marked **UNCLEAR** become investigation targets in Phase 3.

## Output Checklist

Before moving to Phase 3, confirm you have documented:

- [ ] All actor types that interact with the system
- [ ] Trust level for each actor with justification
- [ ] Authentication mechanism for each actor type
- [ ] Input vectors available to each actor
- [ ] Data visibility/access per actor
- [ ] All trust boundaries identified
- [ ] Access control matrix with any UNCLEAR cells flagged
- [ ] Trust boundary misassumptions checked against the list above
