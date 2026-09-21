# EcoShield AI

**AI-Powered Carbon Footprint & Cybersecurity Monitoring System**

EcoShield AI is a full-stack web application that combines an AI carbon-footprint
calculator with a defense-in-depth cybersecurity layer. It calculates environmental
impact across transportation, home energy, food, shopping, and waste; forecasts
future emissions; generates ranked reduction recommendations; and continuously
monitors account security using deterministic rules *plus* explainable ML anomaly
detection.

Built as a college-level B.Sc Cyber Security project demonstrating **Environmental
Technology + Artificial Intelligence + Cybersecurity + Web Development + Data
Analytics**.

---

## Features

### Environmental / AI
- **Carbon calculator** across five modules (transportation, energy, food, shopping, waste).
- **Modular calculation engine** using configurable, admin-editable emission factors (no hard-coded assumptions).
- **Daily / monthly / annual** totals in kg CO₂e and tons CO₂e with per-category percentages.
- **AI prediction** of next-month and annual footprint (Ridge regression with an 80% confidence band).
- **Personalized recommendations** ranked by estimated CO₂e reduction (clearly labeled as estimates).
- **EcoShield AI Assistant** — a grounded chatbot that answers using your *aggregate, non-PII* footprint data.
- **Dashboard** with doughnut, bar, and line charts (Chart.js) and monthly trend analysis.

### Cybersecurity
- Argon2id password hashing (bcrypt fallback + transparent rehash). **No plain-text passwords.**
- JWT access tokens + server-side hashed refresh tokens, session-bound via `sid`.
- Role-Based Access Control: `USER`, `ADMIN`, `SECURITY_ADMIN`.
- CSRF double-submit cookie protection, secure/HttpOnly cookies, CORS allow-list.
- Sliding-window rate limiting on all routes (stricter on auth + AI).
- **AI suspicious-login detection** combined with deterministic rules (brute-force,
  impossible-travel, new device/location). Risk score 0–100 → Low / Medium / High,
  with explainable reasons. ML only *adds* to the deterministic baseline; it never
  makes security decisions on its own.
- Account lockout after repeated failed logins; temporary blocking by staff.
- **Tamper-evident audit log** (SHA-256 hash chain) with a verify endpoint.
- Optional TOTP (RFC 6238) two-factor authentication.
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS when secure).
- Data privacy: user data export, account deletion, minimal collection, sanitized errors.

---

## Tech Stack

| Layer     | Technology |
|-----------|------------|
| Frontend  | HTML5, CSS3, JavaScript, Tailwind CSS (CDN), Chart.js (CDN) — glassmorphism dark/green theme |
| Backend   | Python 3.11+, FastAPI, Uvicorn, Pydantic v2 |
| Database  | SQLite by default; PostgreSQL / MySQL supported via `database/schema.sql` |
| ORM       | SQLAlchemy 2.x (typed `Mapped` style) |
| AI        | scikit-learn (IsolationForest, Ridge), Pandas, NumPy; optional OpenAI LLM |
| Security  | argon2-cffi, bcrypt, PyJWT |
| Testing   | pytest + FastAPI TestClient |

---

## Project Structure

```
EcoShield-AI/
├── frontend/            # static multi-page UI served by FastAPI
│   ├── index.html       # landing
│   ├── register.html  login.html  dashboard.html
│   ├── calculator.html  recommendations.html  assistant.html
│   ├── history.html  security.html  profile.html  admin.html
│   ├── css/styles.css
│   └── js/api.js  js/app.js
├── backend/
│   ├── app.py           # FastAPI app, middleware, static mount
│   ├── config.py        # pydantic-settings configuration
│   ├── database.py      # engine, sessions, init_db
│   ├── models/          # entities.py (16 tables), schemas.py (Pydantic)
│   ├── routes/          # auth, carbon, dashboard, ai, security, admin, profile
│   ├── services/        # carbon engine, emission factors, auth, security, seed
│   ├── security/        # password, tokens, audit, rate_limit, deps, events,
│   │                    #   login_guard, cookies, totp
│   ├── ai/              # anomaly, prediction, recommendations, assistant
│   └── utils/           # request_context, sanitize, timeutil
├── database/schema.sql  # PostgreSQL / MySQL DDL for all 16 tables
├── docs/architecture.md # architecture, data-flow, ER diagrams + threat model
├── tests/               # 33 pytest cases (auth, carbon, ai, security)
├── requirements.txt
├── pytest.ini
├── .env.example
└── README.md
```

---

## Installation

### 1. Prerequisites
- Python **3.11+** (3.13 verified)
- `pip` and `venv`

### 2. Clone & enter the project
```bash
cd EcoShield-AI
```

### 3. Create and activate a virtual environment
```bash
python -m venv .venv

# Windows (Git Bash)
. .venv/Scripts/activate
# Windows (PowerShell)
# .\.venv\Scripts\Activate.ps1
# macOS / Linux
# source .venv/bin/activate
```

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

### 5. Configure the environment
```bash
cp .env.example .env
```
Edit `.env` and **set a strong `ECOSHIELD_SECRET_KEY`**:
```bash
python -c "import secrets;print(secrets.token_urlsafe(48))"
```
The default configuration uses SQLite (`ecoshield.db`), so the app runs with zero
database setup. See *Database configuration* below for PostgreSQL/MySQL.

### 6. Run the server
```bash
uvicorn backend.app:app --reload
```
On first startup the app creates all tables, seeds 33 emission factors, seeds demo
accounts, and generates 8 months of sample carbon history for the demo user.

### 7. Open the app
Browse to **http://localhost:8000** — the frontend is served directly by FastAPI.
Interactive API docs: **http://localhost:8000/docs**

---

## Demo Accounts

Seeded on first run (local demonstration only — override via env vars in production):

| Role            | Email                    | Password          |
|-----------------|--------------------------|-------------------|
| User            | `user@ecoshield.app`     | `EcoShield#User1` |
| Admin           | `admin@ecoshield.app`    | `EcoShield#Admin1`|
| Security Admin  | `security@ecoshield.app` | `EcoShield#Sec1`  |

---

## Database Configuration

**SQLite (default, zero setup):**
```
ECOSHIELD_DATABASE_URL=sqlite:///./ecoshield.db
```

**PostgreSQL:**
```bash
pip install psycopg2-binary
createdb ecoshield
psql -d ecoshield -f database/schema.sql
```
```
ECOSHIELD_DATABASE_URL=postgresql+psycopg2://user:pass@localhost:5432/ecoshield
```

**MySQL:**
```bash
pip install PyMySQL
mysql -u root -p ecoshield < database/schema.sql
```
```
ECOSHIELD_DATABASE_URL=mysql+pymysql://user:pass@localhost:3306/ecoshield
```

The 16 tables: `users`, `user_profiles`, `carbon_records`, `transportation`,
`energy_usage`, `food_usage`, `shopping_usage`, `waste_usage`, `emission_factors`,
`carbon_predictions`, `recommendations`, `login_events`, `security_events`,
`audit_logs`, `sessions`, `notifications`.

---

## API Reference

All endpoints are prefixed with `/api`.

### Meta
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Service health check |
| GET | `/api/csrf-token` | Issue/refresh the CSRF cookie |

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Create an account |
| POST | `/api/auth/verify-email` | Verify email token |
| POST | `/api/auth/login` | Log in (may return MFA challenge) |
| POST | `/api/auth/mfa/verify` | Complete TOTP MFA login |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Revoke current session |
| POST | `/api/auth/forgot-password` | Request a reset token |
| POST | `/api/auth/reset-password` | Reset password with token |
| POST | `/api/auth/change-password` | Change password (authed) |
| POST | `/api/auth/password-strength` | Evaluate a candidate password |
| POST | `/api/auth/mfa/enable` `/api/auth/mfa/disable` | Manage TOTP MFA |
| GET  | `/api/auth/me` | Current user |

### Carbon
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/carbon/calculate` | Calculate & store a footprint |
| GET  | `/api/carbon/history` | Past records |
| GET  | `/api/carbon/prediction` | AI forecast |
| GET  | `/api/carbon/recommendations` | Ranked recommendations |
| GET  | `/api/dashboard` | Aggregated dashboard payload |

### AI
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/ai/assistant` | EcoShield AI Assistant (rate-limited) |

### Profile
| Method | Path | Description |
|--------|------|-------------|
| GET / PUT | `/api/profile` | Read / update profile |
| GET | `/api/profile/notifications` | List notifications |
| POST | `/api/profile/notifications/{id}/read` | Mark read |
| GET | `/api/profile/export` | Export your data (JSON) |
| DELETE | `/api/profile` | Delete your account |

### Security
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/security/events` | Your security events |
| GET | `/api/security/login-history` | Your login history |
| GET | `/api/security/status` | Your security posture |
| POST | `/api/security/report` | Report suspicious activity |

### Admin (RBAC-gated)
| Method | Path | Role |
|--------|------|------|
| GET | `/api/admin/stats` | ADMIN / SECURITY_ADMIN |
| GET | `/api/admin/users` | ADMIN |
| PATCH | `/api/admin/users/{id}` | ADMIN |
| GET | `/api/admin/emission-factors` | ADMIN |
| PUT | `/api/admin/emission-factors/{id}` | ADMIN |
| GET | `/api/admin/security/events` | SECURITY_ADMIN / ADMIN |
| POST | `/api/admin/security/events/{id}/resolve` | SECURITY_ADMIN |
| POST | `/api/admin/security/block/{id}` `/unblock/{id}` | SECURITY_ADMIN |
| GET | `/api/admin/audit-logs` | ADMIN / SECURITY_ADMIN |
| GET | `/api/admin/audit-verify` | Verify audit hash-chain integrity |

---

## Running Tests

```bash
. .venv/Scripts/activate
python -m pytest
```
The suite (33 tests) covers authentication, RBAC, rate limiting, CSRF, the carbon
engine, AI prediction/recommendations, suspicious-login scoring, and audit-chain
integrity. Tests use safe, non-destructive cases only and run against an isolated
test database.

---

## Security Notes

- **Passwords** are stored only as Argon2id salted hashes; bcrypt hashes are
  verified and transparently upgraded on next login.
- **Tokens**: short-lived JWT access tokens; refresh tokens are stored server-side
  as SHA-256 hashes and bound to a session id. Neither is ever returned in errors.
- **AI guardrails**: the assistant receives only aggregate, non-PII context; user
  text is sanitized, length-bounded, and wrapped as untrusted to resist prompt
  injection. The AI has no direct database access — all data flows through
  controlled backend services.
- **Deterministic-first security**: ML anomaly detection augments, and never
  replaces, explicit rules; every alert carries an explainable reason.
- **Audit logs** are hash-chained so tampering is detectable via `/api/admin/audit-verify`.
- **Production**: set `ECOSHIELD_ENVIRONMENT=production`, a strong secret key,
  `ECOSHIELD_COOKIE_SECURE=true`, serve over HTTPS, and change all demo credentials.
  `config.validate_production()` refuses insecure production settings.

---

## Architecture & Diagrams

See [`docs/architecture.md`](docs/architecture.md) for:
- System architecture diagram
- Login / authentication sequence diagram
- Carbon calculation data-flow diagram
- Entity-Relationship (ER) diagram for all 16 tables
- Threat model and mitigation table

---

## Optional: LLM-Enhanced Assistant

By default the assistant uses a local, grounded intent-based engine (no external
calls). To enable an optional LLM backend:
```
ECOSHIELD_LLM_ENABLED=true
ECOSHIELD_OPENAI_API_KEY=sk-...
ECOSHIELD_OPENAI_MODEL=gpt-4o-mini
```
Even when enabled, prompts are hardened against injection and contain only
aggregate footprint context.

---

## License

Educational project. Provided as-is for academic demonstration.
