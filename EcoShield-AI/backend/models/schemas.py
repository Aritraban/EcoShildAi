"""Pydantic v2 request/response schemas with strict input validation.

Validation here is the first line of defence against injection and malformed
input. All numeric fields are range-bounded; strings are length-bounded.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from backend.models.entities import Period, Role, Severity

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., max_length=255)
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = Field(None, max_length=120)
    country: Optional[str] = Field(None, max_length=80)
    city: Optional[str] = Field(None, max_length=80)

    @field_validator("password")
    @classmethod
    def _strong(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain a digit")
        return v


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


class MFACodeRequest(BaseModel):
    code: str = Field(..., pattern=r"^\d{6}$")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr = Field(..., max_length=255)


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10, max_length=255)
    new_password: str = Field(..., min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    requires_mfa: bool = False
    role: Optional[Role] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    username: str
    role: Role
    is_active: bool
    is_email_verified: bool
    mfa_enabled: bool
    created_at: datetime


class ProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    full_name: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    timezone: str = "UTC"
    phone: Optional[str] = None
    analytics_opt_in: bool = True
    data_sharing_enabled: bool = False


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(None, max_length=120)
    country: Optional[str] = Field(None, max_length=80)
    city: Optional[str] = Field(None, max_length=80)
    timezone: Optional[str] = Field(None, max_length=64)
    phone: Optional[str] = Field(None, max_length=32)
    analytics_opt_in: Optional[bool] = None
    data_sharing_enabled: Optional[bool] = None


# --------------------------------------------------------------------------- #
# Carbon calculator inputs
# --------------------------------------------------------------------------- #
class TransportationIn(BaseModel):
    vehicle_type: Optional[str] = Field(None, max_length=40)
    fuel_type: Optional[str] = Field(None, max_length=40)
    distance_km: float = Field(0.0, ge=0, le=1_000_000)
    distance_period: Period = Period.MONTHLY
    fuel_liters: float = Field(0.0, ge=0, le=100_000)
    public_transport_km: float = Field(0.0, ge=0, le=1_000_000)
    flight_km: float = Field(0.0, ge=0, le=1_000_000)


class EnergyIn(BaseModel):
    electricity_kwh: float = Field(0.0, ge=0, le=1_000_000)
    lpg_kg: float = Field(0.0, ge=0, le=100_000)
    natural_gas_m3: float = Field(0.0, ge=0, le=1_000_000)
    ac_hours_per_day: float = Field(0.0, ge=0, le=24)
    heating_kwh: float = Field(0.0, ge=0, le=1_000_000)
    renewable_kwh: float = Field(0.0, ge=0, le=1_000_000)


class FoodIn(BaseModel):
    diet_type: str = Field("mixed", max_length=20)
    meat_meals_per_week: float = Field(0.0, ge=0, le=200)
    dairy_meals_per_week: float = Field(0.0, ge=0, le=200)
    food_waste_kg: float = Field(0.0, ge=0, le=10_000)

    @field_validator("diet_type")
    @classmethod
    def _diet(cls, v: str) -> str:
        allowed = {"vegetarian", "vegan", "mixed", "pescatarian"}
        v = v.lower().strip()
        if v not in allowed:
            raise ValueError(f"diet_type must be one of {sorted(allowed)}")
        return v


class ShoppingIn(BaseModel):
    clothing_spend: float = Field(0.0, ge=0, le=1_000_000)
    electronics_spend: float = Field(0.0, ge=0, le=1_000_000)
    plastic_items: float = Field(0.0, ge=0, le=1_000_000)
    online_orders: float = Field(0.0, ge=0, le=1_000_000)


class WasteIn(BaseModel):
    household_waste_kg: float = Field(0.0, ge=0, le=100_000)
    recycling_percent: float = Field(0.0, ge=0, le=100)
    plastic_waste_kg: float = Field(0.0, ge=0, le=100_000)
    paper_waste_kg: float = Field(0.0, ge=0, le=100_000)
    organic_waste_kg: float = Field(0.0, ge=0, le=100_000)


class CarbonCalculateRequest(BaseModel):
    period: Period = Period.MONTHLY
    transportation: TransportationIn = Field(default_factory=TransportationIn)
    energy: EnergyIn = Field(default_factory=EnergyIn)
    food: FoodIn = Field(default_factory=FoodIn)
    shopping: ShoppingIn = Field(default_factory=ShoppingIn)
    waste: WasteIn = Field(default_factory=WasteIn)


class CategoryBreakdown(BaseModel):
    transport: float
    energy: float
    food: float
    shopping: float
    waste: float
    total: float
    percentages: dict


class CarbonResultOut(BaseModel):
    record_id: int
    period: Period
    daily_co2e: float
    monthly_co2e: float
    annual_co2e: float
    kg_co2e: float
    tons_co2e: float
    breakdown: CategoryBreakdown
    emission_factors_used: dict


# --------------------------------------------------------------------------- #
# Emission factors (admin)
# --------------------------------------------------------------------------- #
class EmissionFactorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category: str
    key: str
    value: float
    unit: str
    description: Optional[str] = None
    source: Optional[str] = None
    is_active: bool
    updated_at: datetime


class EmissionFactorUpdate(BaseModel):
    value: float = Field(..., ge=0, le=1_000_000)
    unit: Optional[str] = Field(None, max_length=64)
    description: Optional[str] = Field(None, max_length=2000)
    source: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = None


# --------------------------------------------------------------------------- #
# AI outputs
# --------------------------------------------------------------------------- #
class PredictionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    predicted_next_month: float
    predicted_annual: float
    confidence_low: Optional[float] = None
    confidence_high: Optional[float] = None
    potential_reduction_pct: Optional[float] = None
    model_version: str
    created_at: datetime


class RecommendationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    category: str
    title: str
    detail: str
    estimated_reduction_kg: float
    rank: int


class AssistantRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)


class AssistantResponse(BaseModel):
    reply: str
    grounded_on_user_data: bool
    model: str


# --------------------------------------------------------------------------- #
# Security / admin
# --------------------------------------------------------------------------- #
class LoginEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    email: Optional[str] = None
    ip_address: Optional[str] = None
    device_type: Optional[str] = None
    browser: Optional[str] = None
    country: Optional[str] = None
    success: bool
    failure_reason: Optional[str] = None
    risk_score: int
    created_at: datetime


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    event_type: str
    severity: Severity
    risk_score: int
    reason: str
    action: Optional[str] = None
    ip_address: Optional[str] = None
    resolved: bool
    created_at: datetime


class SecurityReportRequest(BaseModel):
    event_type: str = Field(..., max_length=80)
    description: str = Field(..., max_length=2000)
    target_user_id: Optional[int] = None


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    event: str
    ip_address: Optional[str] = None
    device_info: Optional[str] = None
    result: str
    risk_level: Severity
    integrity_hash: str
    created_at: datetime


class DashboardOut(BaseModel):
    total_annual: float
    total_monthly: float
    category_percentages: dict
    latest_record: Optional[CarbonResultOut] = None
    monthly_trend: List[dict]
    prediction: Optional[PredictionOut] = None
    top_recommendations: List[RecommendationOut]


class AdminStatsOut(BaseModel):
    total_users: int
    active_sessions: int
    failed_logins: int
    suspicious_logins: int
    high_risk_events: int
    blocked_ips: int
    security_alerts: int
    recent_audit_logs: List[AuditLogOut]
    system_status: str
