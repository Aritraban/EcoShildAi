-- =====================================================================
--  EcoShield AI - Database Schema (PostgreSQL / MySQL compatible DDL)
-- =====================================================================
--  The application itself uses SQLAlchemy and can run on SQLite by default
--  (see backend/config.py -> database_url). This file is the canonical
--  relational schema for PostgreSQL / MySQL deployments and documents all
--  primary keys, foreign keys, indexes and constraints.
--
--  PostgreSQL: run this file as-is.
--  MySQL 8:    replace SERIAL with INT AUTO_INCREMENT and
--              TIMESTAMP WITH TIME ZONE with DATETIME(6).
-- =====================================================================

DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS security_events CASCADE;
DROP TABLE IF EXISTS login_events CASCADE;
DROP TABLE IF EXISTS recommendations CASCADE;
DROP TABLE IF EXISTS carbon_predictions CASCADE;
DROP TABLE IF EXISTS waste_usage CASCADE;
DROP TABLE IF EXISTS shopping_usage CASCADE;
DROP TABLE IF EXISTS food_usage CASCADE;
DROP TABLE IF EXISTS energy_usage CASCADE;
DROP TABLE IF EXISTS transportation CASCADE;
DROP TABLE IF EXISTS carbon_records CASCADE;
DROP TABLE IF EXISTS emission_factors CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS user_profiles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ----------------------------- users ----------------------------------
CREATE TABLE users (
    id                   SERIAL PRIMARY KEY,
    email                VARCHAR(255) NOT NULL UNIQUE,
    username             VARCHAR(64)  NOT NULL UNIQUE,
    password_hash        VARCHAR(255) NOT NULL,
    role                 VARCHAR(20)  NOT NULL DEFAULT 'USER'
                         CHECK (role IN ('USER','ADMIN','SECURITY_ADMIN')),
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    is_email_verified    BOOLEAN      NOT NULL DEFAULT FALSE,
    email_verify_token   VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP WITH TIME ZONE,
    mfa_enabled          BOOLEAN      NOT NULL DEFAULT FALSE,
    mfa_secret           VARCHAR(64),
    failed_login_count   INTEGER      NOT NULL DEFAULT 0,
    locked_until         TIMESTAMP WITH TIME ZONE,
    last_login_at        TIMESTAMP WITH TIME ZONE,
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_users_email ON users (email);
CREATE INDEX ix_users_role  ON users (role);

-- -------------------------- user_profiles -----------------------------
CREATE TABLE user_profiles (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    full_name           VARCHAR(120),
    country             VARCHAR(80),
    city                VARCHAR(80),
    timezone            VARCHAR(64) NOT NULL DEFAULT 'UTC',
    phone               VARCHAR(32),
    analytics_opt_in    BOOLEAN NOT NULL DEFAULT TRUE,
    data_sharing_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- ----------------------------- sessions -------------------------------
CREATE TABLE sessions (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sid              VARCHAR(64) NOT NULL UNIQUE,
    token_hash       VARCHAR(128) NOT NULL UNIQUE,
    ip_address       VARCHAR(64),
    user_agent       VARCHAR(512),
    device_type      VARCHAR(32),
    is_mfa_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    revoked          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    expires_at       TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX ix_sessions_user_active ON sessions (user_id, revoked);

-- ------------------------- emission_factors ---------------------------
CREATE TABLE emission_factors (
    id          SERIAL PRIMARY KEY,
    category    VARCHAR(40) NOT NULL,
    key         VARCHAR(80) NOT NULL,
    value       DOUBLE PRECISION NOT NULL CHECK (value >= 0),
    unit        VARCHAR(64) NOT NULL,
    description TEXT,
    source      VARCHAR(255),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_factor_category_key UNIQUE (category, key)
);
CREATE INDEX ix_factor_category ON emission_factors (category);

-- -------------------------- carbon_records ----------------------------
CREATE TABLE carbon_records (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period          VARCHAR(10) NOT NULL DEFAULT 'MONTHLY'
                    CHECK (period IN ('DAILY','MONTHLY','ANNUAL')),
    reference_date  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    transport_co2e  DOUBLE PRECISION NOT NULL DEFAULT 0,
    energy_co2e     DOUBLE PRECISION NOT NULL DEFAULT 0,
    food_co2e       DOUBLE PRECISION NOT NULL DEFAULT 0,
    shopping_co2e   DOUBLE PRECISION NOT NULL DEFAULT 0,
    waste_co2e      DOUBLE PRECISION NOT NULL DEFAULT 0,
    total_co2e      DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_records_user_date ON carbon_records (user_id, reference_date);

CREATE TABLE transportation (
    id                  SERIAL PRIMARY KEY,
    record_id           INTEGER NOT NULL UNIQUE REFERENCES carbon_records(id) ON DELETE CASCADE,
    vehicle_type        VARCHAR(40),
    fuel_type           VARCHAR(40),
    distance_km         DOUBLE PRECISION NOT NULL DEFAULT 0,
    distance_period     VARCHAR(10) NOT NULL DEFAULT 'MONTHLY',
    fuel_liters         DOUBLE PRECISION NOT NULL DEFAULT 0,
    public_transport_km DOUBLE PRECISION NOT NULL DEFAULT 0,
    flight_km           DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE energy_usage (
    id                SERIAL PRIMARY KEY,
    record_id         INTEGER NOT NULL UNIQUE REFERENCES carbon_records(id) ON DELETE CASCADE,
    electricity_kwh   DOUBLE PRECISION NOT NULL DEFAULT 0,
    lpg_kg            DOUBLE PRECISION NOT NULL DEFAULT 0,
    natural_gas_m3    DOUBLE PRECISION NOT NULL DEFAULT 0,
    ac_hours_per_day  DOUBLE PRECISION NOT NULL DEFAULT 0,
    heating_kwh       DOUBLE PRECISION NOT NULL DEFAULT 0,
    renewable_kwh     DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE food_usage (
    id                    SERIAL PRIMARY KEY,
    record_id             INTEGER NOT NULL UNIQUE REFERENCES carbon_records(id) ON DELETE CASCADE,
    diet_type             VARCHAR(20) NOT NULL DEFAULT 'mixed',
    meat_meals_per_week   DOUBLE PRECISION NOT NULL DEFAULT 0,
    dairy_meals_per_week  DOUBLE PRECISION NOT NULL DEFAULT 0,
    food_waste_kg         DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE shopping_usage (
    id                 SERIAL PRIMARY KEY,
    record_id          INTEGER NOT NULL UNIQUE REFERENCES carbon_records(id) ON DELETE CASCADE,
    clothing_spend     DOUBLE PRECISION NOT NULL DEFAULT 0,
    electronics_spend  DOUBLE PRECISION NOT NULL DEFAULT 0,
    plastic_items      DOUBLE PRECISION NOT NULL DEFAULT 0,
    online_orders      DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE waste_usage (
    id                  SERIAL PRIMARY KEY,
    record_id           INTEGER NOT NULL UNIQUE REFERENCES carbon_records(id) ON DELETE CASCADE,
    household_waste_kg  DOUBLE PRECISION NOT NULL DEFAULT 0,
    recycling_percent   DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (recycling_percent BETWEEN 0 AND 100),
    plastic_waste_kg    DOUBLE PRECISION NOT NULL DEFAULT 0,
    paper_waste_kg      DOUBLE PRECISION NOT NULL DEFAULT 0,
    organic_waste_kg    DOUBLE PRECISION NOT NULL DEFAULT 0
);

-- ----------------------- carbon_predictions ---------------------------
CREATE TABLE carbon_predictions (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    predicted_next_month    DOUBLE PRECISION NOT NULL,
    predicted_annual        DOUBLE PRECISION NOT NULL,
    confidence_low          DOUBLE PRECISION,
    confidence_high         DOUBLE PRECISION,
    potential_reduction_pct DOUBLE PRECISION,
    model_version           VARCHAR(32) NOT NULL DEFAULT 'v1',
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_predictions_user ON carbon_predictions (user_id, created_at);

-- -------------------------- recommendations ---------------------------
CREATE TABLE recommendations (
    id                       SERIAL PRIMARY KEY,
    user_id                  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category                 VARCHAR(40) NOT NULL,
    title                    VARCHAR(160) NOT NULL,
    detail                   TEXT NOT NULL,
    estimated_reduction_kg   DOUBLE PRECISION NOT NULL DEFAULT 0,
    rank                     INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_recommendations_user ON recommendations (user_id);

-- --------------------------- login_events -----------------------------
CREATE TABLE login_events (
    id             SERIAL PRIMARY KEY,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    email          VARCHAR(255),
    ip_address     VARCHAR(64),
    user_agent     VARCHAR(512),
    device_type    VARCHAR(32),
    browser        VARCHAR(64),
    country        VARCHAR(80),
    success        BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reason VARCHAR(120),
    risk_score     INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_login_user    ON login_events (user_id, created_at);
CREATE INDEX ix_login_ip      ON login_events (ip_address);

-- -------------------------- security_events ---------------------------
CREATE TABLE security_events (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event_type    VARCHAR(80) NOT NULL,
    severity      VARCHAR(10) NOT NULL DEFAULT 'LOW'
                  CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    risk_score    INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    reason        TEXT NOT NULL,
    action        VARCHAR(60),
    ip_address    VARCHAR(64),
    user_agent    VARCHAR(512),
    metadata_json TEXT,
    resolved      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_security_severity ON security_events (severity, created_at);
CREATE INDEX ix_security_user     ON security_events (user_id);

-- ---------------------------- audit_logs ------------------------------
-- Append-only, tamper-evident via a SHA-256 hash chain (prev_hash/integrity_hash).
CREATE TABLE audit_logs (
    id             SERIAL PRIMARY KEY,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event          VARCHAR(80) NOT NULL,
    ip_address     VARCHAR(64),
    device_info    VARCHAR(512),
    result         VARCHAR(20) NOT NULL DEFAULT 'SUCCESS',
    risk_level     VARCHAR(10) NOT NULL DEFAULT 'LOW'
                   CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    details_json   TEXT,
    prev_hash      VARCHAR(64),
    integrity_hash VARCHAR(64) NOT NULL,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_user  ON audit_logs (user_id, created_at);
CREATE INDEX ix_audit_event ON audit_logs (event);

-- --------------------------- notifications ----------------------------
CREATE TABLE notifications (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       VARCHAR(40) NOT NULL DEFAULT 'INFO',
    title      VARCHAR(160) NOT NULL,
    message    TEXT NOT NULL,
    severity   VARCHAR(10) NOT NULL DEFAULT 'LOW',
    read       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_notifications_user ON notifications (user_id, read);
