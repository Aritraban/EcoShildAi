"""AI carbon-footprint prediction.

Builds a per-user monthly CO2e time series from stored carbon records and
forecasts next month and the annual total. Uses a simple, robust regressor
(scikit-learn Ridge on a time index plus category features) when enough history
exists, and falls back to a smoothed average otherwise. Always reports an
uncertainty band so predictions are presented honestly.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence

import numpy as np

from backend.models.entities import CarbonRecord, Period
from backend.services.emission_factors import PERIOD_DAYS

MODEL_VERSION = "carbon-forecast-v1"


@dataclass
class Forecast:
    predicted_next_month: float
    predicted_annual: float
    confidence_low: float
    confidence_high: float
    potential_reduction_pct: float
    trend: str  # rising | falling | stable
    n_samples: int
    model_used: str


def record_to_monthly(rec: CarbonRecord) -> float:
    """Normalise any record to a monthly CO2e figure."""
    period = rec.period.value if hasattr(rec.period, "value") else str(rec.period)
    days = PERIOD_DAYS.get(period, PERIOD_DAYS["MONTHLY"])
    if rec.total_co2e is None:
        return 0.0
    return float(rec.total_co2e) / days * PERIOD_DAYS["MONTHLY"]


def monthly_series(records: Sequence[CarbonRecord]) -> List[float]:
    """Aggregate records into chronological monthly totals."""
    if not records:
        return []
    buckets: dict[str, float] = {}
    order: List[str] = []
    for rec in sorted(records, key=lambda r: r.reference_date or r.created_at):
        dt = rec.reference_date or rec.created_at
        key = f"{dt.year}-{dt.month:02d}"
        if key not in buckets:
            order.append(key)
        buckets[key] = buckets.get(key, 0.0) + record_to_monthly(rec)
    return [round(buckets[k], 3) for k in order]


def _potential_reduction(records: Sequence[CarbonRecord]) -> float:
    """Estimate a realistic % reduction from the largest improvable categories."""
    if not records:
        return 0.0
    latest = max(records, key=lambda r: r.reference_date or r.created_at)
    total = latest.total_co2e or sum(
        [latest.transport_co2e, latest.energy_co2e, latest.food_co2e, latest.shopping_co2e, latest.waste_co2e]
    )
    if total <= 0:
        return 0.0
    # Heuristic savings: 15% of transport, 12% of energy, 10% of food,
    # 8% of shopping, 10% of waste (achievable behavioural changes).
    saving = (
        latest.transport_co2e * 0.15
        + latest.energy_co2e * 0.12
        + latest.food_co2e * 0.10
        + latest.shopping_co2e * 0.08
        + latest.waste_co2e * 0.10
    )
    return round(min(saving / total * 100.0, 60.0), 1)


def forecast(records: Sequence[CarbonRecord]) -> Optional[Forecast]:
    series = monthly_series(records)
    if not series:
        return None

    y = np.array(series, dtype=float)
    n = len(y)
    reduction_pct = _potential_reduction(records)

    if n >= 3:
        try:
            from sklearn.linear_model import Ridge

            X = np.arange(n, dtype=float).reshape(-1, 1)
            model = Ridge(alpha=1.0)
            model.fit(X, y)
            next_month = float(model.predict(np.array([[n]]))[0])
            resid = y - model.predict(X)
            sigma = float(np.std(resid)) if len(resid) > 1 else float(np.std(y) or 1.0)
            slope = float(model.coef_[0])
            model_used = "Ridge-trend"
        except Exception:
            next_month = float(np.mean(y[-3:]))
            sigma = float(np.std(y) or 1.0)
            slope = 0.0
            model_used = "mean-fallback(ml-error)"
    else:
        # Too little history: exponential-weighted style smoothing.
        weights = np.array([0.5 ** (n - 1 - i) for i in range(n)])
        weights /= weights.sum()
        next_month = float(np.dot(weights, y))
        sigma = float(np.std(y) or max(next_month * 0.15, 1.0))
        slope = 0.0
        model_used = "smoothed-average"

    next_month = max(next_month, 0.0)
    predicted_annual = next_month * 12.0

    # Apply achievable-reduction potential to the *opportunity* figure only if the
    # trend is not already strongly falling; keep the headline forecast honest.
    low = max(next_month - 1.28 * sigma, 0.0)  # ~80% band
    high = next_month + 1.28 * sigma

    trend = "stable"
    if slope > max(next_month * 0.01, 0.5):
        trend = "rising"
    elif slope < -max(next_month * 0.01, 0.5):
        trend = "falling"

    return Forecast(
        predicted_next_month=round(next_month, 2),
        predicted_annual=round(predicted_annual, 2),
        confidence_low=round(low, 2),
        confidence_high=round(high, 2),
        potential_reduction_pct=reduction_pct,
        trend=trend,
        n_samples=n,
        model_used=model_used,
    )
