"""AI-based suspicious-login detection.

Design principle (per the spec): the model is an *advisory* signal, never the
sole decision-maker. We extract human-interpretable behavioural features, run an
unsupervised anomaly model (IsolationForest) over the user's own login history,
and always emit *explainable* reasons. A deterministic rule engine in
``security/login_guard.py`` combines this score with hard rules to decide the
final action.

The model is fitted per-user on their historical successful logins when enough
data exists; otherwise it degrades gracefully to a population baseline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Sequence

import numpy as np

from backend.config import settings
from backend.models.entities import LoginEvent

MODEL_VERSION = "login-anomaly-v1"
FEATURE_NAMES = [
    "hour_of_day",
    "country_is_new",
    "device_is_new",
    "browser_is_new",
    "recent_failure_ratio",
    "hours_since_last_login",
    "is_night_login",
]


@dataclass
class AnomalyResult:
    risk_score: int              # 0..100 (AI contribution)
    reasons: List[str] = field(default_factory=list)
    features: dict = field(default_factory=dict)
    model_used: str = "baseline"
    confidence: float = 0.0      # 0..1, how much history backed the model


def _safe_hour(dt: Optional[datetime]) -> int:
    if dt is None:
        return 12
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).hour


def _country_of(ev: LoginEvent) -> str:
    return (ev.country or "UNKNOWN").upper()


def build_features(
    attempt: dict,
    history: Sequence[LoginEvent],
) -> tuple[np.ndarray, List[str], float]:
    """Return (feature_vector, explainable_reasons, model_confidence)."""
    reasons: List[str] = []

    successful = [h for h in history if h.success]
    total_hist = len(history)

    hour = attempt.get("hour", _safe_hour(attempt.get("timestamp")))
    country = str(attempt.get("country", "UNKNOWN")).upper()
    device = str(attempt.get("device_type", "unknown")).lower()
    browser = str(attempt.get("browser", "unknown")).lower()
    recent_failures = int(attempt.get("recent_failures", 0))

    known_countries = {_country_of(h) for h in successful}
    known_devices = {(h.device_type or "").lower() for h in successful}
    known_browsers = {(h.browser or "").lower() for h in successful}
    known_hours = [_safe_hour(h.created_at) for h in successful]

    country_new = 1.0 if (known_countries and country not in known_countries) else 0.0
    device_new = 1.0 if (known_devices and device not in known_devices) else 0.0
    browser_new = 1.0 if (known_browsers and browser not in known_browsers) else 0.0
    night = 1.0 if (hour < 5 or hour >= 23) else 0.0

    failure_ratio = (recent_failures / 5.0) if recent_failures else 0.0
    failure_ratio = min(failure_ratio, 1.0)

    last_login = max((_safe_dt(h.created_at) for h in successful), default=None)
    now = attempt.get("timestamp") or datetime.now(timezone.utc)
    now = _safe_dt(now)
    if last_login is None:
        hours_since = 24.0  # neutral default for first-ever login
    else:
        hours_since = min(max((now - last_login).total_seconds() / 3600.0, 0.0), 168.0)

    if country_new:
        reasons.append(f"Login country '{country}' differs from your usual location(s)")
    if device_new:
        reasons.append(f"Unrecognised device type '{device}'")
    if browser_new:
        reasons.append(f"Unrecognised browser '{browser}'")
    if night and known_hours and not any(abs(h - hour) <= 2 for h in known_hours):
        reasons.append("Login at an unusual hour compared with your normal pattern")
    if recent_failures >= 2:
        reasons.append(f"{recent_failures} recent failed attempts before this login")
    if known_hours and abs(hour - int(np.median(known_hours))) > 6:
        reasons.append("Login time is far from your typical login window")

    # Model confidence grows with the amount of successful history available.
    confidence = min(total_hist / 15.0, 1.0)

    vector = np.array(
        [
            hour / 23.0,
            country_new,
            device_new,
            browser_new,
            failure_ratio,
            hours_since / 168.0,
            night,
        ],
        dtype=float,
    )
    return vector, reasons, confidence


def _safe_dt(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class LoginAnomalyDetector:
    """Per-user IsolationForest with a deterministic baseline fallback."""

    def __init__(self, contamination: Optional[float] = None) -> None:
        self.contamination = contamination or settings.anomaly_contamination

    def _history_matrix(self, history: Sequence[LoginEvent]) -> Optional[np.ndarray]:
        successful = [h for h in history if h.success]
        if len(successful) < 8:
            return None
        rows = []
        for h in successful:
            vec, _, _ = build_features(
                {
                    "timestamp": h.created_at,
                    "hour": _safe_hour(h.created_at),
                    "country": _country_of(h),
                    "device_type": h.device_type,
                    "browser": h.browser,
                    "recent_failures": 0,
                },
                [x for x in successful if x.id != h.id],
            )
            rows.append(vec)
        return np.array(rows, dtype=float)

    def _baseline_score(self, vec: np.ndarray) -> float:
        """Weighted heuristic used when there is not enough history to fit ML."""
        hour_n, country_new, device_new, browser_new, fail_ratio, since_n, night = vec
        score = (
            country_new * 34
            + device_new * 20
            + browser_new * 10
            + fail_ratio * 26
            + night * 6
            + min(since_n, 1.0) * 6
        )
        return float(max(0.0, min(100.0, score)))

    def score(self, attempt: dict, history: Sequence[LoginEvent]) -> AnomalyResult:
        vec, reasons, confidence = build_features(attempt, history)

        # The deterministic, explainable baseline is the primary signal.
        base = self._baseline_score(vec)
        risk = base
        model_used = "baseline(no-history)"

        matrix = self._history_matrix(history)
        if matrix is not None:
            try:
                from sklearn.ensemble import IsolationForest

                clf = IsolationForest(
                    n_estimators=100,
                    contamination=self.contamination,
                    random_state=42,
                )
                clf.fit(matrix)
                point = vec.reshape(1, -1)
                raw = float(clf.decision_function(point)[0])
                is_outlier = int(clf.predict(point)[0]) == -1

                # The model can only *raise* risk (additive confirmation); it never
                # dilutes a strong rule-based signal. This keeps decisions
                # explainable and avoids trusting the ML score alone.
                if is_outlier and raw < 0:
                    bump = min(25.0, abs(raw) * 120.0) * (0.5 + 0.5 * confidence)
                    risk = min(100.0, base + bump)
                    model_used = f"IsolationForest+rules(outlier,conf={confidence:.2f})"
                    if not reasons:
                        reasons.append("Statistical anomaly relative to your login history")
                else:
                    model_used = f"IsolationForest+rules(inlier,conf={confidence:.2f})"
            except Exception:
                model_used = "baseline(ml-error)"

        risk = int(round(max(0, min(100, risk))))
        if not reasons and risk >= 31:
            reasons.append("Behaviour differs from your established login pattern")

        return AnomalyResult(
            risk_score=risk,
            reasons=reasons,
            features={name: round(float(v), 3) for name, v in zip(FEATURE_NAMES, vec)},
            model_used=model_used,
            confidence=round(confidence, 2),
        )


# Module-level singleton (stateless across calls; fitted on demand).
detector = LoginAnomalyDetector()
