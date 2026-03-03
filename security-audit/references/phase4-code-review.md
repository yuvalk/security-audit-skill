# Phase 4 Reference: Code Security Review

## Search Patterns by Security Domain

For each domain, use these grep patterns adapted to the project's language(s). These patterns find candidates — always verify in context before reporting.

---

## 1. Input Validation & Injection

### SQL Injection

```
# String concatenation in queries (all languages)
grep -rn "query.*+\|execute.*+\|sql.*+\|SELECT.*+\|INSERT.*+\|UPDATE.*+\|DELETE.*+" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Template literals in queries (JavaScript/TypeScript)
grep -rn 'query.*`\|execute.*`\|sql.*`' --include="*.{js,ts}"

# f-strings / format in queries (Python)
grep -rn "execute.*f['\"].*\|cursor.*format\|query.*%.*%" --include="*.py"

# String.Format in queries (Java/.NET)
grep -rn 'String\.format.*SELECT\|String\.format.*INSERT' --include="*.{java,cs}"

# Raw queries without parameterization
grep -rn "raw\s*(\|rawQuery\|exec_raw\|execute_raw\|textual\|Exec(" --include="*.{js,ts,py,go,rb,java}"
```

**False positive guidance:** ORM methods (`.find()`, `.where()`) with object parameters are generally safe. Raw SQL with parameter placeholders (`?`, `$1`, `:param`) is safe. Only flag concatenated user input.

### Command Injection

```
# Shell execution functions
grep -rn "exec(\|execSync\|spawn\|child_process\|subprocess\|system(\|popen\|os\.system\|os\.popen\|Runtime\.exec\|ProcessBuilder\|backtick" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Go specific
grep -rn "exec\.Command\|os/exec" --include="*.go"

# Template/eval injection
grep -rn "eval(\|Function(\|setTimeout.*string\|setInterval.*string" --include="*.{js,ts}"
grep -rn "eval(\|exec(\|compile(" --include="*.py"
grep -rn "Kernel\.eval\|instance_eval\|class_eval\|send(" --include="*.rb"
```

**False positive guidance:** `exec` with hardcoded commands and no user input is safe. Check if the arguments are user-controlled by tracing back to the input source.

### XSS (Cross-Site Scripting)

```
# React dangerouslySetInnerHTML
grep -rn "dangerouslySetInnerHTML\|__html" --include="*.{jsx,tsx,js,ts}"

# Template engine unescaped output
grep -rn "{{{.*}}}\|{!!.*!!}\|<%=.*%>\|\|raw\||safe\|mark_safe\|Markup(" \
  --include="*.{html,hbs,ejs,erb,py,twig,blade.php}"

# DOM manipulation with user input
grep -rn "\.innerHTML\|\.outerHTML\|document\.write\|insertAdjacentHTML" --include="*.{js,ts,jsx,tsx}"

# jQuery HTML insertion
grep -rn '\.html(\|\.append(\|\.prepend(\|\.after(\|\.before(' --include="*.{js,ts}"
```

### Path Traversal

```
# File operations with user input
grep -rn "readFile\|writeFile\|createReadStream\|createWriteStream\|open(\|fopen\|file_get_contents" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Path joining (check if user input is sanitized)
grep -rn "path\.join\|path\.resolve\|os\.path\.join\|filepath\.Join" --include="*.{js,ts,py,go}"

# Directory traversal indicators
grep -rn "\.\./\|\.\.\\\\|%2e%2e\|%252e" --include="*.{js,ts,py,go,rb,java,php}"
```

### Deserialization

```
# Unsafe deserialization
grep -rn "pickle\.loads\|yaml\.load\(.*\)\|yaml\.unsafe_load\|Marshal\.load\|unserialize(\|ObjectInputStream\|readObject(\|JSON\.parse.*eval\|jsonpickle" \
  --include="*.{py,rb,php,java,js,ts}"

# YAML without safe loader (Python)
grep -rn "yaml\.load(" --include="*.py"
```

### Server-Side Request Forgery (SSRF)

```
# HTTP requests with user-controlled URLs
grep -rn "fetch(\|axios\.\|requests\.\(get\|post\)\|http\.Get\|urllib\|HttpClient\|curl_exec\|file_get_contents.*http" \
  --include="*.{js,ts,py,go,rb,java,php}"
```

**False positive guidance:** Only flag if the URL or any part of it (host, path, query) comes from user input. Hardcoded URLs are safe.

---

## 2. Authentication

```
# Password hashing (check for weak algorithms)
grep -rn "md5\|sha1\|sha256.*password\|hashlib\.\(md5\|sha1\)\|crypto\.createHash\|MessageDigest" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Proper password hashing (should exist)
grep -rn "bcrypt\|argon2\|scrypt\|pbkdf2\|PBKDF2\|password_hash" \
  --include="*.{js,ts,py,go,rb,java,php}"

# JWT configuration
grep -rn "jwt\.\(sign\|verify\|decode\)\|jsonwebtoken\|jose\|PyJWT\|jwt-go\|nimbus-jose" \
  --include="*.{js,ts,py,go,rb,java}"

# JWT algorithm specification
grep -rn "algorithm.*none\|alg.*none\|HS256\|RS256\|algorithms\s*=" \
  --include="*.{js,ts,py,go,rb,java}"

# Session configuration
grep -rn "session\.\(secret\|cookie\|maxAge\|expires\)\|SESSION_\|cookie.*secure\|httpOnly\|sameSite" \
  --include="*.{js,ts,py,go,rb,java}"

# Password comparison (timing-safe?)
grep -rn "===.*password\|==.*password\|strcmp.*password\|password.*===\|password.*==" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Account enumeration
grep -rn "user not found\|email not registered\|no account\|invalid username\|unknown user" \
  --include="*.{js,ts,py,go,rb,java,php}"
```

---

## 3. Authorization

```
# Missing authorization checks — routes without auth middleware
# (Framework specific — see Phase 1 for which framework)

# IDOR indicators — user-controlled IDs in data access
grep -rn "params\.\(id\|userId\|user_id\)\|req\.params\|request\.args\.\(get\)\|c\.Param\|@PathVariable" \
  --include="*.{js,ts,py,go,rb,java}"

# Direct object references without ownership check
grep -rn "findById\|find_by_id\|get_object_or_404\|First(&\|FindOne\|findOne\|findUnique" \
  --include="*.{js,ts,py,go,rb,java}"

# Mass assignment
grep -rn "Object\.assign.*req\.body\|\.update(.*req\.body\|\.create(.*req\.body\|params\.permit\|attr_accessible\|fillable" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Role checks (verify they exist where needed)
grep -rn "isAdmin\|is_admin\|role\s*===\|hasRole\|has_role\|checkPermission\|check_permission" \
  --include="*.{js,ts,py,go,rb,java}"
```

---

## 4. Code Resiliency

```
# Empty catch blocks
grep -rn "catch.*{\s*}\|except.*pass\|rescue\s*$\|catch\s*{\s*//\|catch\s*{\s*$" \
  --include="*.{js,ts,py,go,rb,java}"

# Error swallowing
grep -rn "catch.*{\s*//.*ignore\|catch.*{\s*//.*todo\|catch.*{\s*//.*hack" \
  --include="*.{js,ts,py,go,rb,java}"

# Ignored error returns (Go)
grep -rn "_, _ :=\|_ = .*err\|if err != nil {\s*$" --include="*.go"

# Missing finally/defer for cleanup
grep -rn "\.connect(\|\.open(\|acquire(\|Lock(\|createConnection" \
  --include="*.{js,ts,py,go,rb,java}"

# Race conditions
grep -rn "async.*await\|goroutine\|threading\|Thread\.\|concurrent\.\|sync\.Mutex" \
  --include="*.{js,ts,py,go,rb,java}"
```

---

## 5. Availability & DoS

```
# Missing rate limiting on sensitive endpoints
# (Check auth endpoints, API endpoints, file upload endpoints)

# Regular expression DoS (ReDoS)
# Look for nested quantifiers: (a+)+, (a|b)*c, (a*)*
grep -rn "new RegExp\|re\.compile\|regexp\.Compile\|Pattern\.compile\|Regexp\.new" \
  --include="*.{js,ts,py,go,rb,java}"

# Unbounded queries
grep -rn "find(\|findAll\|select\s*\*\|SELECT \*\|\.all(\|\.list(\|findMany" \
  --include="*.{js,ts,py,go,rb,java}"

# Missing pagination
grep -rn "limit\|offset\|page\|skip\|take\|per_page\|pageSize" \
  --include="*.{js,ts,py,go,rb,java}"

# Large file/data handling
grep -rn "readFileSync\|read()\|\.read(\|ioutil\.ReadAll\|io\.ReadAll" \
  --include="*.{js,ts,py,go,rb,java}"

# No timeout on external calls
grep -rn "fetch(\|axios\.\|requests\.\|http\.\(Get\|Post\)\|HttpClient" \
  --include="*.{js,ts,py,go,rb,java}"
```

---

## 6. Cryptography & Secrets

```
# Hardcoded secrets
grep -rn "password\s*=\s*['\"].*['\"]\|secret\s*=\s*['\"].*['\"]\|api_key\s*=\s*['\"].*['\"]\|token\s*=\s*['\"].*['\"]" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Weak cryptographic algorithms
grep -rn "DES\|RC4\|MD5\|SHA1\|ECB\|Math\.random\|rand(\|random\.random" \
  --include="*.{js,ts,py,go,rb,java,php}"

# Cryptographically secure random
grep -rn "crypto\.randomBytes\|secrets\.\|crypto/rand\|SecureRandom\|CSPRNG" \
  --include="*.{js,ts,py,go,rb,java}"

# TLS/SSL configuration
grep -rn "rejectUnauthorized.*false\|verify.*false\|CERT_NONE\|InsecureSkipVerify.*true\|ssl.*false" \
  --include="*.{js,ts,py,go,rb,java}"

# Hardcoded IVs/nonces
grep -rn "iv\s*=\s*['\"].*['\"]\|nonce\s*=\s*['\"].*['\"]\|IV\s*=\s*\[\|createCipheriv" \
  --include="*.{js,ts,py,go,rb,java}"
```

---

## 7. Data Protection

```
# PII in logs
grep -rn "console\.log.*password\|logger.*email\|log\.\(info\|debug\|warn\|error\).*\(password\|token\|secret\|ssn\|credit.card\)" \
  --include="*.{js,ts,py,go,rb,java}"

# CORS configuration
grep -rn "Access-Control-Allow-Origin.*\*\|cors.*origin.*\*\|AllowAllOrigins\|allow_all_origins" \
  --include="*.{js,ts,py,go,rb,java}"

# Cookie security flags
grep -rn "cookie\|setCookie\|Set-Cookie\|res\.cookie" --include="*.{js,ts,py,go,rb,java}"
# Then check for: Secure, HttpOnly, SameSite flags

# Sensitive data in URLs
grep -rn "GET.*password\|GET.*token\|GET.*secret\|query.*password\|query.*token" \
  --include="*.{js,ts,py,go,rb,java}"

# Information in error responses
grep -rn "stack.*trace\|stackTrace\|traceback\|res\.send.*err\|res\.json.*error.*message" \
  --include="*.{js,ts,py,go,rb,java}"

# Cache headers for sensitive data
grep -rn "Cache-Control\|no-store\|no-cache\|private" --include="*.{js,ts,py,go,rb,java}"
```

---

## 8. Dependencies

```
# Check for known vulnerabilities
# JavaScript
npm audit 2>/dev/null || true
yarn audit 2>/dev/null || true

# Python
pip-audit 2>/dev/null || safety check 2>/dev/null || true

# Go
govulncheck ./... 2>/dev/null || true

# Ruby
bundle-audit check 2>/dev/null || true

# Check for outdated packages
npm outdated 2>/dev/null || true
pip list --outdated 2>/dev/null || true
go list -m -u all 2>/dev/null || true
bundle outdated 2>/dev/null || true
```

---

## Fix Pattern Examples

### SQL Injection Fix

**Vulnerable:**
```javascript
// BAD
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query);
```

**Fixed:**
```javascript
// GOOD — parameterized query
db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
```

### Command Injection Fix

**Vulnerable:**
```python
# BAD
os.system(f"convert {user_filename} output.png")
```

**Fixed:**
```python
# GOOD — use array form, never shell=True with user input
subprocess.run(["convert", user_filename, "output.png"], shell=False, check=True)
```

### XSS Fix

**Vulnerable:**
```javascript
// BAD
element.innerHTML = userInput;
```

**Fixed:**
```javascript
// GOOD — use textContent for text, or sanitize for HTML
element.textContent = userInput;
// OR if HTML is needed:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### IDOR Fix

**Vulnerable:**
```javascript
// BAD — no ownership check
app.get('/api/users/:id/data', auth, async (req, res) => {
  const data = await db.users.findById(req.params.id);
  res.json(data);
});
```

**Fixed:**
```javascript
// GOOD — verify the requester owns the resource
app.get('/api/users/:id/data', auth, async (req, res) => {
  if (req.user.id !== req.params.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const data = await db.users.findById(req.params.id);
  res.json(data);
});
```

### Mass Assignment Fix

**Vulnerable:**
```javascript
// BAD — accepts all fields from request
await User.update(req.body, { where: { id: req.params.id } });
```

**Fixed:**
```javascript
// GOOD — allowlist specific fields
const { name, email, bio } = req.body;
await User.update({ name, email, bio }, { where: { id: req.params.id } });
```
