"""Carbon service: persists calculations, builds history/dashboard, and wires in
the AI prediction and recommendation engines.

This service is the *only* place that touches carbon data on behalf of the AI
modules - the AI never accesses the database directly (controlled boundary).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.ai import prediction as prediction_ai
from backend.ai import recommendations as rec_ai
from backend.models.entities import (
    CarbonPrediction,
    CarbonRecord,
    EnergyUsage,
    FoodUsage,
    Period,
    Recommendation,
    ShoppingUsage,
    Transportation,
    User,
    WasteUsage,
)
from backend.models.schemas import CarbonCalculateRequest
from backend.services.carbon_engine import calculate
from backend.services.emission_factors import load_factors


def _to_period(value) -> Period:
    if isinstance(value, Period):
        return value
    return Period(str(value).upper())


def calculate_and_save(db: Session, user: User, request: CarbonCalculateRequest) -> dict:
    factors = load_factors(db)
    result = calculate(request, factors)

    record = CarbonRecord(
        user_id=user.id,
        period=_to_period(request.period),
        reference_date=datetime.now(timezone.utc),
        transport_co2e=result["parts"]["transport"],
        energy_co2e=result["parts"]["energy"],
        food_co2e=result["parts"]["food"],
        shopping_co2e=result["parts"]["shopping"],
        waste_co2e=result["parts"]["waste"],
        total_co2e=result["period_total"],
    )
    db.add(record)
    db.flush()  # get record.id

    t = request.transportation
    db.add(
        Transportation(
            record_id=record.id,
            vehicle_type=t.vehicle_type,
            fuel_type=t.fuel_type,
            distance_km=t.distance_km,
            distance_period=_to_period(t.distance_period),
            fuel_liters=t.fuel_liters,
            public_transport_km=t.public_transport_km,
            flight_km=t.flight_km,
        )
    )
    e = request.energy
    db.add(
        EnergyUsage(
            record_id=record.id,
            electricity_kwh=e.electricity_kwh,
            lpg_kg=e.lpg_kg,
            natural_gas_m3=e.natural_gas_m3,
            ac_hours_per_day=e.ac_hours_per_day,
            heating_kwh=e.heating_kwh,
            renewable_kwh=e.renewable_kwh,
        )
    )
    f = request.food
    db.add(
        FoodUsage(
            record_id=record.id,
            diet_type=f.diet_type,
            meat_meals_per_week=f.meat_meals_per_week,
            dairy_meals_per_week=f.dairy_meals_per_week,
            food_waste_kg=f.food_waste_kg,
        )
    )
    s = request.shopping
    db.add(
        ShoppingUsage(
            record_id=record.id,
            clothing_spend=s.clothing_spend,
            electronics_spend=s.electronics_spend,
            plastic_items=s.plastic_items,
            online_orders=s.online_orders,
        )
    )
    w = request.waste
    db.add(
        WasteUsage(
            record_id=record.id,
            household_waste_kg=w.household_waste_kg,
            recycling_percent=w.recycling_percent,
            plastic_waste_kg=w.plastic_waste_kg,
            paper_waste_kg=w.paper_waste_kg,
            organic_waste_kg=w.organic_waste_kg,
        )
    )
    db.commit()
    db.refresh(record)

    # Refresh AI artefacts against the new record.
    refresh_prediction(db, user)
    refresh_recommendations(db, user, record, factors)

    return {
        "record_id": record.id,
        "period": record.period.value if hasattr(record.period, "value") else str(record.period),
        "daily_co2e": result["daily"],
        "monthly_co2e": result["monthly"],
        "annual_co2e": result["annual"],
        "kg_co2e": result["kg"],
        "tons_co2e": result["tons"],
        "breakdown": {
            "transport": result["parts"]["transport"],
            "energy": result["parts"]["energy"],
            "food": result["parts"]["food"],
            "shopping": result["parts"]["shopping"],
            "waste": result["parts"]["waste"],
            "total": result["period_total"],
            "percentages": result["percentages"],
        },
        "emission_factors_used": result["factors_used"],
    }


def get_history(db: Session, user: User, limit: int = 50) -> List[CarbonRecord]:
    return list(
        db.execute(
            select(CarbonRecord)
            .where(CarbonRecord.user_id == user.id)
            .order_by(CarbonRecord.reference_date.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )


def latest_record(db: Session, user: User) -> Optional[CarbonRecord]:
    history = get_history(db, user, limit=1)
    return history[0] if history else None


def refresh_prediction(db: Session, user: User) -> Optional[CarbonPrediction]:
    records = get_history(db, user, limit=60)
    fc = prediction_ai.forecast(records)
    if fc is None:
        return None
    pred = CarbonPrediction(
        user_id=user.id,
        predicted_next_month=fc.predicted_next_month,
        predicted_annual=fc.predicted_annual,
        confidence_low=fc.confidence_low,
        confidence_high=fc.confidence_high,
        potential_reduction_pct=fc.potential_reduction_pct,
        model_version=prediction_ai.MODEL_VERSION,
    )
    db.add(pred)
    db.commit()
    db.refresh(pred)
    return pred


def latest_prediction(db: Session, user: User) -> Optional[CarbonPrediction]:
    return db.execute(
        select(CarbonPrediction)
        .where(CarbonPrediction.user_id == user.id)
        .order_by(CarbonPrediction.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def refresh_recommendations(db: Session, user: User, record: Optional[CarbonRecord], factors: Dict[str, float]) -> List[Recommendation]:
    rec = record or latest_record(db, user)
    if rec is None:
        return []
    # Replace previous recommendations for this user.
    for old in db.execute(select(Recommendation).where(Recommendation.user_id == user.id)).scalars().all():
        db.delete(old)
    db.flush()

    generated = rec_ai.generate(rec, factors)
    stored: List[Recommendation] = []
    for i, g in enumerate(generated):
        row = Recommendation(
            user_id=user.id,
            category=g.category,
            title=g.title,
            detail=g.detail,
            estimated_reduction_kg=g.estimated_reduction_kg,
            rank=i + 1,
        )
        db.add(row)
        stored.append(row)
    db.commit()
    for row in stored:
        db.refresh(row)
    return stored


def top_recommendations(db: Session, user: User, limit: int = 6) -> List[Recommendation]:
    return list(
        db.execute(
            select(Recommendation)
            .where(Recommendation.user_id == user.id)
            .order_by(Recommendation.rank.asc())
            .limit(limit)
        )
        .scalars()
        .all()
    )


def record_to_result(db: Session, rec: CarbonRecord) -> dict:
    total = rec.total_co2e or 0.0
    parts = {
        "transport": rec.transport_co2e or 0.0,
        "energy": rec.energy_co2e or 0.0,
        "food": rec.food_co2e or 0.0,
        "shopping": rec.shopping_co2e or 0.0,
        "waste": rec.waste_co2e or 0.0,
    }
    percentages = {k: round(v / total * 100, 2) if total else 0.0 for k, v in parts.items()}
    period = rec.period.value if hasattr(rec.period, "value") else str(rec.period)
    from backend.services.emission_factors import PERIOD_DAYS

    days = PERIOD_DAYS.get(period, PERIOD_DAYS["MONTHLY"])
    daily = round(total / days, 4) if days else total
    return {
        "record_id": rec.id,
        "period": period,
        "daily_co2e": daily,
        "monthly_co2e": round(daily * PERIOD_DAYS["MONTHLY"], 3),
        "annual_co2e": round(daily * PERIOD_DAYS["ANNUAL"], 3),
        "kg_co2e": round(total, 3),
        "tons_co2e": round(total / 1000.0, 4),
        "breakdown": {**parts, "total": round(total, 3), "percentages": percentages},
        "emission_factors_used": {},
    }


def build_dashboard(db: Session, user: User) -> dict:
    records = get_history(db, user, limit=60)
    rec = records[0] if records else None

    if rec:
        latest = record_to_result(db, rec)
        percentages = latest["breakdown"]["percentages"]
        monthly = latest["monthly_co2e"]
        annual = latest["annual_co2e"]
    else:
        latest = None
        percentages = {"transport": 0, "energy": 0, "food": 0, "shopping": 0, "waste": 0}
        monthly = 0.0
        annual = 0.0

    # Monthly trend (chronological, normalised to monthly totals).
    series = prediction_ai.monthly_series(records)
    trend = [{"month": i + 1, "co2e": v} for i, v in enumerate(series)]

    pred = latest_prediction(db, user)
    recs = top_recommendations(db, user)

    return {
        "total_annual": annual,
        "total_monthly": monthly,
        "category_percentages": percentages,
        "latest_record": latest,
        "monthly_trend": trend,
        "prediction": pred,
        "top_recommendations": recs,
    }


def build_assistant_context(db: Session, user: User) -> dict:
    """Aggregate, NON-identifying context for the assistant (privacy-by-design).

    Contains no email, name, IP, or credentials - only carbon aggregates.
    """
    dash = build_dashboard(db, user)
    pred = dash.get("prediction")
    return {
        "category_percentages": dash["category_percentages"],
        "monthly_co2e": dash["total_monthly"],
        "annual_co2e": dash["total_annual"],
        "prediction": {
            "predicted_next_month": pred.predicted_next_month,
            "predicted_annual": pred.predicted_annual,
            "potential_reduction_pct": pred.potential_reduction_pct,
        }
        if pred
        else None,
        "top_recommendations": [
            {"title": r.title, "estimated_reduction_kg": r.estimated_reduction_kg, "category": r.category}
            for r in dash["top_recommendations"][:4]
        ],
    }
