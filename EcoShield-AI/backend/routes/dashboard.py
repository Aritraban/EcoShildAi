"""Dashboard aggregation route."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.entities import User
from backend.models.schemas import PredictionOut, RecommendationOut
from backend.security.deps import get_current_user
from backend.services import carbon_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    data = carbon_service.build_dashboard(db, user)
    pred = data.get("prediction")
    return {
        "total_annual": data["total_annual"],
        "total_monthly": data["total_monthly"],
        "category_percentages": data["category_percentages"],
        "latest_record": data["latest_record"],
        "monthly_trend": data["monthly_trend"],
        "prediction": PredictionOut.model_validate(pred) if pred else None,
        "top_recommendations": [RecommendationOut.model_validate(r) for r in data["top_recommendations"]],
    }
