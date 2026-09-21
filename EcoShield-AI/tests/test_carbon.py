"""Carbon calculation engine (unit) and API (integration) tests."""
from __future__ import annotations

from backend.models.schemas import CarbonCalculateRequest, EnergyIn, FoodIn, TransportationIn, WasteIn
from backend.services.carbon_engine import calculate
from backend.services.emission_factors import DEFAULT_FACTORS
from conftest import auth_headers, csrf

FACTORS = {f"{c}.{k}": v for c, k, v, *_ in DEFAULT_FACTORS}


def test_engine_uses_configurable_factors():
    req = CarbonCalculateRequest(
        period="MONTHLY",
        transportation=TransportationIn(fuel_type="petrol", fuel_liters=50),
        energy=EnergyIn(electricity_kwh=100),
    )
    result = calculate(req, FACTORS)
    expected_transport = 50 * FACTORS["transport.fuel.petrol"]
    expected_energy = 100 * FACTORS["energy.electricity.grid"]
    assert abs(result["parts"]["transport"] - expected_transport) < 0.01
    assert abs(result["parts"]["energy"] - expected_energy) < 0.01
    assert result["period_total"] > 0


def test_engine_renewable_offsets_grid():
    base = calculate(
        CarbonCalculateRequest(period="MONTHLY", energy=EnergyIn(electricity_kwh=200)), FACTORS
    )
    with_solar = calculate(
        CarbonCalculateRequest(period="MONTHLY", energy=EnergyIn(electricity_kwh=200, renewable_kwh=200)), FACTORS
    )
    assert with_solar["parts"]["energy"] < base["parts"]["energy"]


def test_engine_recycling_reduces_waste():
    low = calculate(CarbonCalculateRequest(period="MONTHLY", waste=WasteIn(household_waste_kg=50, recycling_percent=0)), FACTORS)
    high = calculate(CarbonCalculateRequest(period="MONTHLY", waste=WasteIn(household_waste_kg=50, recycling_percent=80)), FACTORS)
    assert high["parts"]["waste"] < low["parts"]["waste"]


def test_normalisation_daily_monthly_annual():
    req = CarbonCalculateRequest(period="MONTHLY", food=FoodIn(diet_type="mixed"))
    r = calculate(req, FACTORS)
    assert r["annual"] > r["monthly"] > r["daily"]
    # Monthly and annual are the daily figure scaled by the standard month/year.
    assert abs(r["monthly"] - r["daily"] * 30.4375) < 0.01
    assert abs(r["annual"] - r["daily"] * 365.25) < 0.05
    assert abs(r["tons"] - r["period_total"] / 1000.0) < 1e-3


def test_calculate_api_persists_and_returns_breakdown(client, user_headers):
    payload = {
        "period": "MONTHLY",
        "transportation": {"vehicle_type": "car_petrol", "distance_km": 500},
        "energy": {"electricity_kwh": 200},
        "food": {"diet_type": "mixed", "meat_meals_per_week": 5},
    }
    r = client.post("/api/carbon/calculate", json=payload, headers=user_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["record_id"] > 0
    assert body["breakdown"]["total"] > 0
    assert set(body["breakdown"]["percentages"]) == {"transport", "energy", "food", "shopping", "waste"}

    hist = client.get("/api/carbon/history", headers=user_headers).json()
    assert hist["count"] >= 1


def test_input_validation_rejects_negative(client, user_headers):
    payload = {"period": "MONTHLY", "energy": {"electricity_kwh": -50}}
    r = client.post("/api/carbon/calculate", json=payload, headers=user_headers)
    assert r.status_code == 422
