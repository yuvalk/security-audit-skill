# Phase 1 Reference: Project Understanding

## Tech Stack Discovery

### Manifest Files to Check

Search for these files to identify the tech stack:

| File | Language/Ecosystem | Key Info |
|------|--------------------|----------|
| `package.json` | JavaScript/TypeScript | Dependencies, scripts, engines |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | JS | Exact versions for CVE lookup |
| `tsconfig.json` | TypeScript | Compiler options, strict mode |
| `go.mod` | Go | Module path, Go version, deps |
| `go.sum` | Go | Exact versions |
| `requirements.txt` / `Pipfile` / `pyproject.toml` | Python | Dependencies |
| `setup.py` / `setup.cfg` | Python | Package metadata |
| `Gemfile` / `Gemfile.lock` | Ruby | Dependencies |
| `pom.xml` / `build.gradle` | Java | Dependencies, plugins |
| `Cargo.toml` / `Cargo.lock` | Rust | Dependencies |
| `*.csproj` / `*.sln` | .NET/C# | Dependencies, framework |
| `composer.json` | PHP | Dependencies |
| `mix.exs` | Elixir | Dependencies |

### Framework Detection Patterns

#### JavaScript/TypeScript
```
# Express.js
grep -r "require('express')\|from 'express'" --include="*.{js,ts}"
grep -r "app\.\(get\|post\|put\|delete\|patch\|use\)" --include="*.{js,ts}"

# Next.js
ls next.config.{js,mjs,ts} pages/ app/

# Fastify
grep -r "require('fastify')\|from 'fastify'" --include="*.{js,ts}"

# NestJS
grep -r "@Controller\|@Module\|@Injectable" --include="*.ts"

# Hono
grep -r "from 'hono'\|require('hono')" --include="*.{js,ts}"
```

#### Python
```
# Django
ls manage.py */settings.py */urls.py
grep -r "from django" --include="*.py"

# Flask
grep -r "from flask\|Flask(__name__)" --include="*.py"

# FastAPI
grep -r "from fastapi\|FastAPI()" --include="*.py"

# aiohttp
grep -r "from aiohttp\|aiohttp.web" --include="*.py"
```

#### Go
```
# Standard net/http
grep -r "net/http" --include="*.go"

# Gin
grep -r "github.com/gin-gonic/gin" --include="*.go"

# Echo
grep -r "github.com/labstack/echo" --include="*.go"

# Fiber
grep -r "github.com/gofiber/fiber" --include="*.go"

# Chi
grep -r "github.com/go-chi/chi" --include="*.go"
```

#### Java
```
# Spring Boot
grep -r "@SpringBootApplication\|@RestController\|@RequestMapping" --include="*.java"

# Jakarta EE / JAX-RS
grep -r "@Path\|@GET\|@POST\|@PUT\|@DELETE" --include="*.java"
```

#### Ruby
```
# Rails
ls config/routes.rb app/controllers/ Gemfile
grep -r "Rails.application" --include="*.rb"

# Sinatra
grep -r "require 'sinatra'\|Sinatra::Base" --include="*.rb"
```

## Entry Point Discovery

### HTTP Routes/Handlers

| Framework | Pattern to Search | File Locations |
|-----------|-------------------|----------------|
| Express | `router.get/post/put/delete`, `app.get/post` | `routes/`, `src/routes/`, `api/` |
| Next.js (pages) | Files in `pages/api/` | `pages/api/**/*.{js,ts}` |
| Next.js (app) | `route.ts` files | `app/**/route.{js,ts}` |
| Django | `urlpatterns`, `path()`, `re_path()` | `urls.py` files |
| FastAPI | `@app.get/post/put/delete` | Python files with router decorators |
| Flask | `@app.route`, `@blueprint.route` | Python files with route decorators |
| Gin | `r.GET/POST/PUT/DELETE`, `router.Group` | Go files with router setup |
| Spring | `@GetMapping`, `@PostMapping`, `@RequestMapping` | Controller classes |
| Rails | `resources`, `get/post/put/delete` in routes.rb | `config/routes.rb` |

### Other Entry Points

- **CLI commands**: `commander`, `cobra`, `argparse`, `click`, `thor`, `clap`
- **Message queue consumers**: `amqplib`, `bull`, `celery`, `sidekiq`, `kafka`
- **gRPC services**: `.proto` files, generated server stubs
- **WebSocket handlers**: `ws`, `socket.io`, `gorilla/websocket`, `channels`
- **Cron/scheduled jobs**: `node-cron`, `crontab`, `celery beat`, `whenever`
- **GraphQL resolvers**: `graphql` schema definitions, resolver functions

## Database & Storage Identification

| Technology | Detection Pattern |
|------------|-------------------|
| PostgreSQL | `pg`, `psycopg2`, `pgx`, `database/sql` + postgres driver |
| MySQL | `mysql2`, `mysqlclient`, `go-sql-driver/mysql` |
| MongoDB | `mongoose`, `pymongo`, `mongo-driver` |
| Redis | `redis`, `ioredis`, `go-redis` |
| SQLite | `sqlite3`, `better-sqlite3` |
| Prisma | `prisma/client`, `schema.prisma` |
| TypeORM | `typeorm`, entity decorators |
| Sequelize | `sequelize`, model definitions |
| SQLAlchemy | `sqlalchemy`, model definitions |
| GORM | `gorm.io/gorm` |
| Elasticsearch | `@elastic/elasticsearch`, `elasticsearch-py` |

## Config & Secrets Loading

Look for how the project handles configuration and secrets:

```
# Environment variables
grep -r "process\.env\.\|os\.environ\|os\.Getenv\|ENV\[" --include="*.{js,ts,py,go,rb}"

# Config files
ls .env .env.* config/ *.config.{js,ts,json,yaml,yml}

# Secret management
grep -r "aws-sdk.*secrets\|vault\|doppler\|dotenv\|keyring" --include="*.{js,ts,py,go,rb}"
```

## Security-Relevant Middleware/Configuration

Look for existing security measures:

```
# Helmet (Express security headers)
grep -r "helmet" --include="*.{js,ts}"

# CORS configuration
grep -r "cors\|Access-Control" --include="*.{js,ts,py,go,rb,java}"

# CSRF protection
grep -r "csrf\|csurf\|CSRFProtect" --include="*.{js,ts,py,go,rb}"

# Rate limiting
grep -r "rate.limit\|rateLimit\|throttle\|RateLimiter" --include="*.{js,ts,py,go,rb}"

# Authentication middleware
grep -r "passport\|jwt\|jsonwebtoken\|auth.*middleware\|authenticate" --include="*.{js,ts,py,go,rb}"

# Input validation
grep -r "joi\|yup\|zod\|class-validator\|cerberus\|marshmallow" --include="*.{js,ts,py,go,rb}"
```

## Output Checklist

Before moving to Phase 2, confirm you have documented:

- [ ] All languages and frameworks in use (with versions if available)
- [ ] All HTTP/API entry points
- [ ] All other entry points (CLI, queues, cron, WebSocket, gRPC)
- [ ] All data stores and what they contain
- [ ] All external service integrations
- [ ] All sensitive operations identified
- [ ] Key data flows with trust boundary crossings
- [ ] Existing security middleware and controls
