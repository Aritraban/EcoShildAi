# EcoShield AI — Architecture & Diagrams

This document contains the **system architecture diagram**, **data-flow diagram**,
and **ER diagram** (Mermaid source). Render them in any Mermaid-capable viewer
(GitHub, VS Code "Markdown Preview Mermaid Support", or https://mermaid.live).

---

## 1. System Architecture

```mermaid
flowchart TB
    subgraph Client["Browser (Frontend SPA)"]
        UI["HTML5 / CSS3 / JS<br/>Tailwind + Chart.js"]
    end

    subgraph Edge["FastAPI Application (backend/app.py)"]
        MW["Middleware Stack<br/>CORS · Security Headers · Rate Limit · CSRF"]
        subgraph Routes["Routers (backend/routes)"]
            AUTH["/auth"]
            CARBON["/carbon"]
            DASH["/dashboard"]
            AIR["/ai"]
            SEC["/security"]
            ADMIN["/admin"]
            PROF["/profile"]
        end
        DEPS["Dependencies<br/>JWT auth · RBAC"]
    end

    subgraph Services["Service Layer (controlled boundary)"]
        ENGSVC["Carbon Engine"]
        FACT["Emission Factors"]
        CARBSVC["Carbon Service"]
        SECSVC["Security Service"]
        AUTHSVC["Auth Service"]
    end

    subgraph AI["AI Layer (no direct DB access)"]
        ANOM["Login Anomaly Detector<br/>IsolationForest + rules"]
        PRED["Carbon Forecast<br/>Ridge trend"]
        REC["Recommendation Engine"]
        ASSIST["Eco Assistant<br/>local / optional LLM"]
    end

    subgraph Security["Security Layer"]
        PWH["Argon2id / bcrypt"]
        TOK["JWT tokens"]
        GUARD["Login Guard<br/>deterministic rules"]
        AUDIT["Audit Log<br/>hash chain"]
        RL["Rate Limiter"]
        TOTP["TOTP / MFA"]
    end

    DB[("Database<br/>SQLite / PostgreSQL / MySQL")]

    UI -- "HTTPS + JSON<br/>Bearer + CSRF token" --> MW
    MW --> Routes
    Routes --> DEPS
    DEPS --> Services
    AUTH --> AUTHSVC
    AUTH --> GUARD
    GUARD --> ANOM
    CARBON --> ENGSVC
    ENGSVC --> FACT
    CARBON --> CARBSVC
    DASH --> CARBSVC
    CARBSVC --> PRED
    CARBSVC --> REC
    AIR --> ASSIST
    CARBSVC -. "aggregate, non-PII context" .-> ASSIST
    Services --> DB
    Security --> DB
    AUDIT --> DB
    ANOM --> DB
```

**Key principle:** the AI layer never touches the database directly. Services
prepare *aggregate, non-identifying* context and pass it in — a controlled
boundary that limits data leakage and prompt-injection impact.

---

## 2. Data-Flow Diagram (login + risk evaluation)

```mermaid
sequenceDiagram
    participant B as Browser
    participant M as Middleware
    participant A as /auth/login
    participant G as Login Guard
    participant AI as Anomaly Detector
    participant DB as Database
    participant AU as Audit Log

    B->>M: POST /api/auth/login (email, password, CSRF)
    M->>M: Rate limit + CSRF validate
    M->>A: forward request
    A->>DB: lookup user by email
    A->>A: verify Argon2id hash
    alt credentials invalid
        A->>G: evaluate_login(success=False)
        G->>DB: increment failed count / maybe lock
        G->>AU: write LOGIN_FAILURE (hash-chained)
        A-->>B: 401 generic message
    else credentials valid
        A->>G: evaluate_login(success=True)
        G->>DB: load recent login history
        G->>AI: score(attempt, history)
        AI-->>G: risk_score + explainable reasons
        G->>G: apply deterministic rules<br/>(brute force, impossible travel)
        G->>DB: store LoginEvent (+ SecurityEvent if high risk)
        G->>AU: write LOGIN_SUCCESS
        G-->>A: decision (ALLOW / MFA_REQUIRED / BLOCK)
        A->>DB: create session (sid), store refresh hash
        A-->>B: access token + refresh cookie
    end
```

### Carbon calculation data-flow

```mermaid
flowchart LR
    F["Calculator form"] --> V["Pydantic validation<br/>(range/type bounded)"]
    V --> E["Carbon Engine"]
    EF[("emission_factors")] --> E
    E --> R["CarbonRecord + sub-tables"]
    R --> P["Prediction (Ridge)"]
    R --> RC["Recommendations"]
    R --> D["Dashboard charts"]
    P --> D
    RC --> D
    D --> AGG["Aggregate context (no PII)"]
    AGG --> AS["Eco Assistant"]
```

---

## 3. ER Diagram

```mermaid
erDiagram
    users ||--|| user_profiles : has
    users ||--o{ sessions : owns
    users ||--o{ carbon_records : produces
    users ||--o{ carbon_predictions : has
    users ||--o{ recommendations : receives
    users ||--o{ login_events : generates
    users ||--o{ security_events : triggers
    users ||--o{ notifications : receives
    users ||--o{ audit_logs : attributed

    carbon_records ||--|| transportation : details
    carbon_records ||--|| energy_usage : details
    carbon_records ||--|| food_usage : details
    carbon_records ||--|| shopping_usage : details
    carbon_records ||--|| waste_usage : details

    users {
        int id PK
        string email UK
        string username UK
        string password_hash
        string role
        bool is_active
        bool is_email_verified
        bool mfa_enabled
        int failed_login_count
        datetime locked_until
        datetime created_at
    }
    user_profiles {
        int id PK
        int user_id FK
        string full_name
        string country
        string city
        string timezone
        bool analytics_opt_in
        bool data_sharing_enabled
    }
    sessions {
        int id PK
        int user_id FK
        string sid UK
        string token_hash UK
        string ip_address
        string device_type
        bool revoked
        datetime expires_at
    }
    emission_factors {
        int id PK
        string category
        string key
        float value
        string unit
        string source
        bool is_active
        int updated_by FK
    }
    carbon_records {
        int id PK
        int user_id FK
        string period
        datetime reference_date
        float transport_co2e
        float energy_co2e
        float food_co2e
        float shopping_co2e
        float waste_co2e
        float total_co2e
    }
    transportation {
        int id PK
        int record_id FK
        string vehicle_type
        string fuel_type
        float distance_km
        float fuel_liters
        float public_transport_km
        float flight_km
    }
    energy_usage {
        int id PK
        int record_id FK
        float electricity_kwh
        float lpg_kg
        float natural_gas_m3
        float ac_hours_per_day
        float renewable_kwh
    }
    food_usage {
        int id PK
        int record_id FK
        string diet_type
        float meat_meals_per_week
        float dairy_meals_per_week
        float food_waste_kg
    }
    shopping_usage {
        int id PK
        int record_id FK
        float clothing_spend
        float electronics_spend
        float plastic_items
        float online_orders
    }
    waste_usage {
        int id PK
        int record_id FK
        float household_waste_kg
        float recycling_percent
        float plastic_waste_kg
        float paper_waste_kg
        float organic_waste_kg
    }
    carbon_predictions {
        int id PK
        int user_id FK
        float predicted_next_month
        float predicted_annual
        float confidence_low
        float confidence_high
        float potential_reduction_pct
        string model_version
    }
    recommendations {
        int id PK
        int user_id FK
        string category
        string title
        string detail
        float estimated_reduction_kg
        int rank
    }
    login_events {
        int id PK
        int user_id FK
        string email
        string ip_address
        string device_type
        string browser
        string country
        bool success
        int risk_score
        datetime created_at
    }
    security_events {
        int id PK
        int user_id FK
        string event_type
        string severity
        int risk_score
        string reason
        string action
        bool resolved
        datetime created_at
    }
    audit_logs {
        int id PK
        int user_id FK
        string event
        string ip_address
        string device_info
        string result
        string risk_level
        string prev_hash
        string integrity_hash
        datetime created_at
    }
    notifications {
        int id PK
        int user_id FK
        string type
        string title
        string message
        string severity
        bool read
    }
```

---

## 4. Trust boundaries & threat model (summary)

| Threat | Mitigation |
| --- | --- |
| Credential brute force | Rate limiting + failed-login counter + account lockout + AI/deterministic risk scoring |
| Credential stuffing | Per-IP failure tracking, anomaly detection, generic error messages (no user enumeration) |
| Session hijacking | Short-lived JWT access tokens, server-side revocable sessions, HttpOnly SameSite refresh cookie |
| CSRF | Double-submit CSRF cookie + `X-CSRF-Token` header on all unsafe methods |
| XSS | JSON responses, CSP, `X-Content-Type-Options`, output sanitisation helpers |
| SQL injection | SQLAlchemy parameterised queries throughout (no string-built SQL) |
| Broken access control | Role-Based Access Control dependencies on every privileged route |
| Data leakage via AI | AI receives only aggregate, non-PII context through a service boundary |
| Prompt injection | User text sanitised, length-bounded, wrapped as untrusted data for the LLM path |
| Audit tampering | Append-only, SHA-256 hash-chained audit log with a verification endpoint |
| Sensitive data at rest | Argon2id password hashing; tokens stored only as hashes; export excludes secrets |
