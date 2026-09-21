"""Modular carbon-footprint calculation engine.

Each category is an independent, pure function of (inputs, emission factors).
Nothing is hard-coded: every multiplier comes from the configurable factor
registry, so administrators can change values without touching code.

Inputs are interpreted for the request ``period`` (DAILY/MONTHLY/ANNUAL) and the
result is normalised to daily, monthly and annual CO2e.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from backend.models.schemas import CarbonCalculateRequest
from backend.services.emission_factors import PERIOD_DAYS, get_factor


@dataclass
class CategoryResult:
    co2e: float
    factors_used: Dict[str, float]


def _period_days(period: str) -> float:
    return PERIOD_DAYS.get(period.upper(), PERIOD_DAYS["MONTHLY"])


def calc_transportation(inp, factors: Dict[str, float], days: float) -> CategoryResult:
    used: Dict[str, float] = {}
    total = 0.0

    # Private vehicle: prefer explicit fuel volume, else distance x vehicle factor.
    fuel_type = (inp.fuel_type or "").lower()
    if inp.fuel_liters > 0 and fuel_type in ("petrol", "diesel"):
        f = get_factor(factors, f"transport.fuel.{fuel_type}")
        total += inp.fuel_liters * f
        used[f"transport.fuel.{fuel_type}"] = f
    elif inp.distance_km > 0:
        vehicle = (inp.vehicle_type or "car_petrol").lower()
        key = f"transport.vehicle.{vehicle}"
        f = get_factor(factors, key, get_factor(factors, "transport.vehicle.car_petrol", 0.171))
        total += inp.distance_km * f
        used[key] = f

    if inp.public_transport_km > 0:
        # Assume a bus/train blend if not otherwise specified.
        f_bus = get_factor(factors, "transport.public.bus")
        total += inp.public_transport_km * f_bus
        used["transport.public.bus"] = f_bus

    if inp.flight_km > 0:
        f_flight = get_factor(factors, "transport.flight.long_haul")
        total += inp.flight_km * f_flight
        used["transport.flight.long_haul"] = f_flight

    return CategoryResult(round(total, 3), used)


def calc_energy(inp, factors: Dict[str, float], days: float) -> CategoryResult:
    used: Dict[str, float] = {}
    total = 0.0

    f_grid = get_factor(factors, "energy.electricity.grid")
    if inp.electricity_kwh > 0:
        total += inp.electricity_kwh * f_grid
        used["energy.electricity.grid"] = f_grid

    if inp.lpg_kg > 0:
        f = get_factor(factors, "energy.lpg")
        total += inp.lpg_kg * f
        used["energy.lpg"] = f

    if inp.natural_gas_m3 > 0:
        f = get_factor(factors, "energy.natural_gas")
        total += inp.natural_gas_m3 * f
        used["energy.natural_gas"] = f

    if inp.ac_hours_per_day > 0:
        f_kwh = get_factor(factors, "energy.ac.kwh_per_hour")
        ac_kwh = inp.ac_hours_per_day * f_kwh * days
        total += ac_kwh * f_grid
        used["energy.ac.kwh_per_hour"] = f_kwh

    if inp.heating_kwh > 0:
        f = get_factor(factors, "energy.heating.electric")
        total += inp.heating_kwh * f
        used["energy.heating.electric"] = f

    # Renewable self-generation offsets grid consumption.
    if inp.renewable_kwh > 0:
        f_grid_used = used.get("energy.electricity.grid", f_grid)
        offset = min(inp.renewable_kwh, inp.electricity_kwh) * f_grid_used
        total -= offset
        f_ren = get_factor(factors, "energy.electricity.renewable")
        total += inp.renewable_kwh * f_ren
        used["energy.electricity.renewable"] = f_ren

    return CategoryResult(round(max(total, 0.0), 3), used)


def calc_food(inp, factors: Dict[str, float], days: float) -> CategoryResult:
    used: Dict[str, float] = {}
    diet_key = f"food.diet.{inp.diet_type}"
    f_base = get_factor(factors, diet_key, get_factor(factors, "food.diet.mixed", 3.3))
    total = f_base * days
    used[diet_key] = f_base

    weeks = days / 7.0
    if inp.meat_meals_per_week > 0:
        f = get_factor(factors, "food.meat.meal_extra")
        total += inp.meat_meals_per_week * weeks * f
        used["food.meat.meal_extra"] = f
    if inp.dairy_meals_per_week > 0:
        f = get_factor(factors, "food.dairy.meal_extra")
        total += inp.dairy_meals_per_week * weeks * f
        used["food.dairy.meal_extra"] = f
    if inp.food_waste_kg > 0:
        f = get_factor(factors, "food.waste.per_kg")
        total += inp.food_waste_kg * f
        used["food.waste.per_kg"] = f

    return CategoryResult(round(max(total, 0.0), 3), used)


def calc_shopping(inp, factors: Dict[str, float], days: float) -> CategoryResult:
    used: Dict[str, float] = {}
    total = 0.0
    if inp.clothing_spend > 0:
        f = get_factor(factors, "shopping.clothing.per_currency")
        total += inp.clothing_spend * f
        used["shopping.clothing.per_currency"] = f
    if inp.electronics_spend > 0:
        f = get_factor(factors, "shopping.electronics.per_currency")
        total += inp.electronics_spend * f
        used["shopping.electronics.per_currency"] = f
    if inp.plastic_items > 0:
        f = get_factor(factors, "shopping.plastic.per_item")
        total += inp.plastic_items * f
        used["shopping.plastic.per_item"] = f
    if inp.online_orders > 0:
        f = get_factor(factors, "shopping.online.per_order")
        total += inp.online_orders * f
        used["shopping.online.per_order"] = f
    return CategoryResult(round(max(total, 0.0), 3), used)


def calc_waste(inp, factors: Dict[str, float], days: float) -> CategoryResult:
    used: Dict[str, float] = {}
    recycled_fraction = min(max(inp.recycling_percent, 0.0), 100.0) / 100.0
    landfill_fraction = 1.0 - recycled_fraction
    offset = get_factor(factors, "waste.recycling.offset")
    used["waste.recycling.offset"] = offset

    total = 0.0
    specs = [
        (inp.household_waste_kg, "waste.household.per_kg"),
        (inp.plastic_waste_kg, "waste.plastic.per_kg"),
        (inp.paper_waste_kg, "waste.paper.per_kg"),
        (inp.organic_waste_kg, "waste.organic.per_kg"),
    ]
    for amount, key in specs:
        if amount > 0:
            f = get_factor(factors, key)
            total += amount * f * landfill_fraction
            used[key] = f
    return CategoryResult(round(max(total, 0.0), 3), used)


def calculate(request: CarbonCalculateRequest, factors: Dict[str, float]) -> dict:
    """Compute the full breakdown for a request. Returns a plain dict."""
    period = request.period.value if hasattr(request.period, "value") else str(request.period)
    days = _period_days(period)

    t = calc_transportation(request.transportation, factors, days)
    e = calc_energy(request.energy, factors, days)
    f = calc_food(request.food, factors, days)
    s = calc_shopping(request.shopping, factors, days)
    w = calc_waste(request.waste, factors, days)

    period_total = round(t.co2e + e.co2e + f.co2e + s.co2e + w.co2e, 3)

    daily = round(period_total / days, 4) if days else period_total
    monthly = round(daily * PERIOD_DAYS["MONTHLY"], 3)
    annual = round(daily * PERIOD_DAYS["ANNUAL"], 3)

    parts = {"transport": t.co2e, "energy": e.co2e, "food": f.co2e, "shopping": s.co2e, "waste": w.co2e}
    percentages = {
        k: round((v / period_total) * 100, 2) if period_total > 0 else 0.0
        for k, v in parts.items()
    }

    factors_used = {}
    for res in (t, e, f, s, w):
        factors_used.update(res.factors_used)

    return {
        "period": period,
        "parts": parts,
        "period_total": period_total,
        "daily": daily,
        "monthly": monthly,
        "annual": annual,
        "kg": period_total,
        "tons": round(period_total / 1000.0, 4),
        "percentages": percentages,
        "factors_used": factors_used,
    }
