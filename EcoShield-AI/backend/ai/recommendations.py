"""Personalised, ranked recommendation engine.

Analyses the latest carbon breakdown, identifies the largest contributors, and
generates actionable recommendations. Each recommendation carries an *estimated*
CO2e reduction (clearly labelled as an estimate) and the list is ranked by that
value so users see the highest-impact changes first.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from backend.models.entities import CarbonRecord
from backend.services.emission_factors import get_factor


@dataclass
class Rec:
    category: str
    title: str
    detail: str
    estimated_reduction_kg: float


def _monthly_value(record_value: float, period: str) -> float:
    from backend.services.emission_factors import PERIOD_DAYS

    days = PERIOD_DAYS.get(period.upper(), PERIOD_DAYS["MONTHLY"])
    return record_value / days * PERIOD_DAYS["MONTHLY"]


def generate(latest: CarbonRecord, factors: Dict[str, float]) -> List[Rec]:
    period = latest.period.value if hasattr(latest.period, "value") else str(latest.period)

    transport = _monthly_value(latest.transport_co2e, period)
    energy = _monthly_value(latest.energy_co2e, period)
    food = _monthly_value(latest.food_co2e, period)
    shopping = _monthly_value(latest.shopping_co2e, period)
    waste = _monthly_value(latest.waste_co2e, period)
    total = transport + energy + food + shopping + waste

    recs: List[Rec] = []
    if total <= 0:
        recs.append(
            Rec(
                "general",
                "Record your first footprint",
                "Add transportation, energy, food, shopping and waste data to unlock personalised advice.",
                0.0,
            )
        )
        return recs

    def pct(part: float) -> float:
        return round(part / total * 100, 1)

    # --- Transportation ---
    if transport > 0:
        p = pct(transport)
        recs.append(
            Rec(
                "transportation",
                f"Transportation is {p}% of your footprint",
                "Shift short trips to walking/cycling, use public transport, and carpool where possible.",
                round(transport * 0.20, 2),
            )
        )
        if transport >= total * 0.3:
            recs.append(
                Rec(
                    "transportation",
                    "Combine or remove one car trip per week",
                    "Trip-chaining and one fewer drive per week meaningfully cuts fuel use.",
                    round(transport * 0.10, 2),
                )
            )
        recs.append(
            Rec(
                "transportation",
                "Consider low-emission vehicles for replacement",
                "If replacing a vehicle, an EV or hybrid reduces per-km emissions substantially.",
                round(transport * 0.12, 2),
            )
        )

    # --- Energy ---
    if energy > 0:
        p = pct(energy)
        recs.append(
            Rec(
                "energy",
                f"Home energy is {p}% of your footprint",
                "Switch to LED lighting, unplug idle electronics, and improve appliance efficiency.",
                round(energy * 0.12, 2),
            )
        )
        recs.append(
            Rec(
                "energy",
                "Optimise AC and heating",
                "Raise AC set-point by 1-2C and reduce heating; seal drafts to cut consumption.",
                round(energy * 0.15, 2),
            )
        )
        recs.append(
            Rec(
                "energy",
                "Switch to renewable electricity",
                "A rooftop solar system or green tariff can eliminate most grid-emission impact.",
                round(energy * 0.35, 2),
            )
        )

    # --- Food ---
    if food > 0:
        p = pct(food)
        recs.append(
            Rec(
                "food",
                f"Food is {p}% of your footprint",
                "Add plant-based meals, reduce red meat, and cut food waste through meal planning.",
                round(food * 0.18, 2),
            )
        )
        recs.append(
            Rec(
                "food",
                "Reduce food waste",
                "Plan portions and store food properly; wasted food carries all its embedded emissions.",
                round(food * 0.10, 2),
            )
        )

    # --- Shopping ---
    if shopping > 0:
        p = pct(shopping)
        recs.append(
            Rec(
                "shopping",
                f"Shopping is {p}% of your footprint",
                "Buy fewer, higher-quality items, choose second-hand, and consolidate online orders.",
                round(shopping * 0.15, 2),
            )
        )

    # --- Waste ---
    if waste > 0:
        p = pct(waste)
        offset = get_factor(factors, "waste.recycling.offset", 0.6)
        recs.append(
            Rec(
                "waste",
                f"Waste is {p}% of your footprint",
                "Recycle more and compost organic waste to divert it from landfill methane.",
                round(waste * offset * 0.5, 2),
            )
        )

    # Rank by estimated reduction, descending.
    recs.sort(key=lambda r: r.estimated_reduction_kg, reverse=True)
    return recs
