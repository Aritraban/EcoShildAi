"""Database seeding: emission factors, staff accounts, and sample demo data.

Passwords here are for local demonstration only. In production, set
ECOSHIELD_ADMIN_EMAIL / ECOSHIELD_ADMIN_PASSWORD via the environment and do not
ship default credentials.
"""
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.entities import (
    CarbonRecord,
    EnergyUsage,
    FoodUsage,
    Period,
    Role,
    ShoppingUsage,
    Transportation,
    User,
    UserProfile,
    WasteUsage,
)
from backend.models.schemas import (
    CarbonCalculateRequest,
    EnergyIn,
    FoodIn,
    ShoppingIn,
    TransportationIn,
    WasteIn,
)
from backend.security.password import hash_password
from backend.services import carbon_service
from backend.services.emission_factors import ensure_seeded


def _get_or_create_user(
    db: Session, email: str, username: str, password: str, role: Role, verified: bool = True
) -> User:
    user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()
    if user:
        return user
    user = User(
        email=email.lower(),
        username=username,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        is_email_verified=verified,
    )
    db.add(user)
    db.flush()
    db.add(UserProfile(user_id=user.id, full_name=username.title(), country="India", city="Kolkata"))
    db.commit()
    db.refresh(user)
    return user


def seed_staff(db: Session) -> dict:
    admin_email = os.getenv("ECOSHIELD_ADMIN_EMAIL", "admin@ecoshield.app")
    admin_pass = os.getenv("ECOSHIELD_ADMIN_PASSWORD", "EcoShield#Admin1")
    sec_email = os.getenv("ECOSHIELD_SECURITY_EMAIL", "security@ecoshield.app")
    sec_pass = os.getenv("ECOSHIELD_SECURITY_PASSWORD", "EcoShield#Sec1")

    admin = _get_or_create_user(db, admin_email, "admin", admin_pass, Role.ADMIN)
    sec = _get_or_create_user(db, sec_email, "securityadmin", sec_pass, Role.SECURITY_ADMIN)
    return {"admin": admin, "security_admin": sec}


def seed_demo_user(db: Session, months: int = 8) -> User:
    """Create a demo user with several months of carbon history for the charts."""
    user = _get_or_create_user(db, "user@ecoshield.app", "demouser", "EcoShield#User1", Role.USER)

    existing = db.execute(select(CarbonRecord).where(CarbonRecord.user_id == user.id)).scalars().first()
    if existing:
        return user

    rng = random.Random(42)
    now = datetime.now(timezone.utc)

    # Decreasing trend so the AI forecast shows a realistic "potential reduction".
    for i in range(months, 0, -1):
        ref = now - timedelta(days=30 * i)
        scale = 1.0 + (i * 0.03)  # slightly higher in the past
        payload = CarbonCalculateRequest(
            period=Period.MONTHLY,
            transportation=TransportationIn(
                vehicle_type="car_petrol",
                fuel_type="petrol",
                distance_km=round(600 * scale + rng.uniform(-40, 40), 1),
                fuel_liters=0,
                public_transport_km=round(80 * scale, 1),
                flight_km=round(300 if i % 4 == 0 else 0, 1),
            ),
            energy=EnergyIn(
                electricity_kwh=round(220 * scale + rng.uniform(-15, 15), 1),
                lpg_kg=round(9 * scale, 1),
                ac_hours_per_day=round(3 * scale, 1),
                renewable_kwh=round(20 * (months - i), 1),
            ),
            food=FoodIn(
                diet_type="mixed",
                meat_meals_per_week=round(7 * scale, 1),
                dairy_meals_per_week=5,
                food_waste_kg=round(4 * scale, 1),
            ),
            shopping=ShoppingIn(
                clothing_spend=round(1500 * scale, 2),
                electronics_spend=round(500 * scale, 2),
                plastic_items=round(20 * scale, 1),
                online_orders=round(6 * scale, 1),
            ),
            waste=WasteIn(
                household_waste_kg=round(30 * scale, 1),
                recycling_percent=round(20 + (months - i) * 3, 1),
                plastic_waste_kg=round(5 * scale, 1),
                paper_waste_kg=round(4 * scale, 1),
                organic_waste_kg=round(8 * scale, 1),
            ),
        )
        result = carbon_service.calculate_and_save(db, user, payload)
        rec = db.get(CarbonRecord, result["record_id"])
        if rec:
            rec.reference_date = ref
            db.commit()

    # Re-run AI artefacts now that reference dates are chronological.
    from backend.services.emission_factors import load_factors

    carbon_service.refresh_prediction(db, user)
    carbon_service.refresh_recommendations(db, user, None, load_factors(db))
    return user


def seed_all(db: Session, include_demo: bool = True) -> dict:
    inserted_factors = ensure_seeded(db)
    staff = seed_staff(db)
    demo = seed_demo_user(db) if include_demo else None
    return {"factors_inserted": inserted_factors, "staff": staff, "demo_user": demo}
