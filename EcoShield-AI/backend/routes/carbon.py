"""Carbon footprint calculation, history, prediction and recommendation routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.entities import User
from backend.models.schemas import CarbonCalculateRequest, CarbonResultOut, RecommendationOut
from backend.security.audit import write_audit
from backend.security.deps import get_current_user
from backend.services import carbon_service
from backend.services.emission_factors import load_factors
from backend.utils.request_context import build_client_context

router = APIRouter(prefix="/carbon", tags=["carbon"])


@router.post("/calculate", response_model=CarbonResultOut)
def calculate(payload: CarbonCalculateRequest, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ctx = build_client_context(request)
    result = carbon_service.calculate_and_save(db, user, payload)
    write_audit(
        db,
        event="CARBON_CALCULATION",
        user_id=user.id,
        ip_address=ctx.ip_address,
        device_info=ctx.user_agent[:512],
        result="SUCCESS",
        details={"total_co2e": result["kg_co2e"], "period": result["period"]},
    )
    return result


@router.get("/history")
def history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    records = carbon_service.get_history(db, user, limit=100)
    return {"count": len(records), "records": [carbon_service.record_to_result(db, r) for r in records]}


@router.get("/prediction")
def prediction(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pred = carbon_service.latest_prediction(db, user)
    if pred is None:
        pred = carbon_service.refresh_prediction(db, user)
    if pred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not enough data to predict yet. Record a calculation first.")
    return pred


@router.get("/recommendations")
def recommendations(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    recs = carbon_service.top_recommendations(db, user, limit=12)
    if not recs:
        factors = load_factors(db)
        recs = carbon_service.refresh_recommendations(db, user, None, factors)
    return {
        "disclaimer": "Reduction figures are estimates based on typical behavioural changes, not guarantees.",
        "recommendations": [RecommendationOut.model_validate(r) for r in recs],
    }
