"""Configurable emission-factor registry.

Emission factors are stored in the database (table ``emission_factors``) and are
admin-editable - they are NOT hard-coded across the application. The defaults
below seed the database on first run and are clearly labelled with units and a
reference source. Values are illustrative averages; administrators should replace
them with authoritative regional factors.
"""
from __future__ import annotations

from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.entities import EmissionFactor

# (category, key, value, unit, description, source)
DEFAULT_FACTORS: list[tuple[str, str, float, str, str, str]] = [
    # --- Transportation ---
    ("transport", "fuel.petrol", 2.31, "kg CO2e / liter", "Combustion of petrol", "EPA/DfT average"),
    ("transport", "fuel.diesel", 2.68, "kg CO2e / liter", "Combustion of diesel", "EPA/DfT average"),
    ("transport", "fuel.electric", 0.0, "kg CO2e / km", "EV tailpipe (grid handled in energy)", "IEA"),
    ("transport", "vehicle.car_petrol", 0.171, "kg CO2e / km", "Average petrol car per km", "DfT 2023"),
    ("transport", "vehicle.car_diesel", 0.168, "kg CO2e / km", "Average diesel car per km", "DfT 2023"),
    ("transport", "vehicle.motorbike", 0.103, "kg CO2e / km", "Average motorbike per km", "DfT 2023"),
    ("transport", "vehicle.ev", 0.053, "kg CO2e / km", "Average EV per km (grid mix)", "ICCT"),
    ("transport", "public.bus", 0.105, "kg CO2e / passenger-km", "Local bus", "DfT 2023"),
    ("transport", "public.train", 0.041, "kg CO2e / passenger-km", "National rail", "DfT 2023"),
    ("transport", "flight.domestic", 0.246, "kg CO2e / passenger-km", "Short-haul incl. radiative forcing", "ICAO"),
    ("transport", "flight.long_haul", 0.147, "kg CO2e / passenger-km", "Long-haul incl. radiative forcing", "ICAO"),
    # --- Home energy ---
    ("energy", "electricity.grid", 0.42, "kg CO2e / kWh", "Grid electricity average", "IEA 2023"),
    ("energy", "electricity.renewable", 0.02, "kg CO2e / kWh", "Self-generated renewable", "IPCC"),
    ("energy", "lpg", 1.51, "kg CO2e / kg", "LPG combustion", "IPCC"),
    ("energy", "natural_gas", 2.02, "kg CO2e / m3", "Natural gas combustion", "IPCC"),
    ("energy", "ac.kwh_per_hour", 1.0, "kWh / hour", "Typical split AC draw", "Energy Star"),
    ("energy", "heating.electric", 0.42, "kg CO2e / kWh", "Electric resistance heating", "IEA"),
    # --- Food ---
    ("food", "diet.vegan", 1.5, "kg CO2e / day", "Vegan diet baseline", "Poore & Nemecek 2018"),
    ("food", "diet.vegetarian", 2.0, "kg CO2e / day", "Vegetarian baseline", "Poore & Nemecek 2018"),
    ("food", "diet.pescatarian", 2.6, "kg CO2e / day", "Pescatarian baseline", "Poore & Nemecek 2018"),
    ("food", "diet.mixed", 3.3, "kg CO2e / day", "Mixed/omnivore baseline", "Poore & Nemecek 2018"),
    ("food", "meat.meal_extra", 1.5, "kg CO2e / meal", "Extra per meat meal over baseline", "Poore & Nemecek 2018"),
    ("food", "dairy.meal_extra", 0.6, "kg CO2e / meal", "Extra per dairy meal", "Poore & Nemecek 2018"),
    ("food", "waste.per_kg", 2.5, "kg CO2e / kg", "Food waste (landfill methane)", "FAO"),
    # --- Shopping ---
    ("shopping", "clothing.per_currency", 0.03, "kg CO2e / currency unit", "Apparel spend intensity", "Ellen MacArthur Fdn"),
    ("shopping", "electronics.per_currency", 0.05, "kg CO2e / currency unit", "Electronics spend intensity", "UNU"),
    ("shopping", "plastic.per_item", 0.08, "kg CO2e / item", "Single-use plastic item", "WRAP"),
    ("shopping", "online.per_order", 0.20, "kg CO2e / order", "Packaging + last-mile delivery", "MIT"),
    # --- Waste ---
    ("waste", "household.per_kg", 0.40, "kg CO2e / kg", "Mixed household waste to landfill", "EPA WARM"),
    ("waste", "plastic.per_kg", 0.70, "kg CO2e / kg", "Plastic waste", "EPA WARM"),
    ("waste", "paper.per_kg", 0.30, "kg CO2e / kg", "Paper waste", "EPA WARM"),
    ("waste", "organic.per_kg", 0.50, "kg CO2e / kg", "Organic waste (landfill)", "EPA WARM"),
    ("waste", "recycling.offset", 0.60, "fraction avoided", "Emissions avoided by recycling", "EPA WARM"),
]

# Period normalisation constants
PERIOD_DAYS = {"DAILY": 1.0, "MONTHLY": 30.4375, "ANNUAL": 365.25}


def ensure_seeded(db: Session) -> int:
    """Insert default emission factors if missing. Returns number inserted."""
    existing = {
        (row.category, row.key)
        for row in db.execute(select(EmissionFactor.category, EmissionFactor.key)).all()
    }
    inserted = 0
    for category, key, value, unit, description, source in DEFAULT_FACTORS:
        if (category, key) in existing:
            continue
        db.add(
            EmissionFactor(
                category=category,
                key=key,
                value=value,
                unit=unit,
                description=description,
                source=source,
                is_active=True,
            )
        )
        inserted += 1
    if inserted:
        db.commit()
    return inserted


def load_factors(db: Session) -> Dict[str, float]:
    """Load active factors into a ``category.key -> value`` map for the engine."""
    rows = db.execute(select(EmissionFactor).where(EmissionFactor.is_active.is_(True))).scalars().all()
    return {f"{r.category}.{r.key}": r.value for r in rows}


def get_factor(factors: Dict[str, float], key: str, default: float = 0.0) -> float:
    return float(factors.get(key, default))
