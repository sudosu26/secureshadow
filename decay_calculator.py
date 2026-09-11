"""
SECURESHADOW - Phase 5: Protection Decay Score
Quantifies how much security protection has eroded and explains why.
"""

from datetime import datetime
from data_model import (
    Asset, SecurityControl, Assumption, SecurityProperty,
    CommunicationPath, create_demo_scenario
)
from graph_engine import SecurityGraph
from drift_detection import DriftDetector, AssumptionAnalyzer, ChangeEvent


# ============================================================
# DECAY CONTRIBUTOR
# ============================================================

class DecayContributor:
    """
    A single reason why protection decreased.
    Links a change to a specific assumption and the impact.
    """
    def __init__(self, assumption_id: str, assumption_desc: str, change_desc: str, impact_percent: float):
        self.assumption_id = assumption_id
        self.assumption_desc = assumption_desc
        self.change_desc = change_desc
        self.impact_percent = impact_percent  # How much this contributed to decay (e.g., 15.0)

    def __repr__(self):
        return f"Contributor({self.assumption_id}: -{self.impact_percent:.1f}%)"


# ============================================================
# DECAY RESULT
# ============================================================

class DecayResult:
    """
    The complete result of a protection decay calculation.
    """
    def __init__(self, property_id: str, property_desc: str):
        self.property_id = property_id
        self.property_desc = property_desc
        self.baseline_protection = 100.0
        self.current_protection = 100.0
        self.decay_percent = 0.0
        self.contributors: list[DecayContributor] = []
        self.broken_assumptions: list[str] = []
        self.timestamp = datetime.now()

    def add_contributor(self, contributor: DecayContributor):
        """Add a decay contributor and recalculate."""
        self.contributors.append(contributor)
        # Recalculate current protection
        total_impact = sum(c.impact_percent for c in self.contributors)
        self.current_protection = max(0.0, self.baseline_protection - total_impact)
        self.decay_percent = self.baseline_protection - self.current_protection

    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = []
        lines.append(f"Security Property: {self.property_desc}")
        lines.append(f"Baseline Protection: {self.baseline_protection:.0f}%")
        lines.append(f"Current Protection:  {self.current_protection:.0f}%")
        lines.append(f"Protection Decay:    {self.decay_percent:.0f}%")
        lines.append("")

        if self.contributors:
            lines.append("Contributors:")
            for c in self.contributors:
                lines.append(f"  - {c.change_desc}")
                lines.append(f"    Broken assumption: {c.assumption_desc}")
                lines.append(f"    Impact: -{c.impact_percent:.1f}%")
                lines.append("")
        else:
            lines.append("No decay contributors. Protection is intact.")

        return "\n".join(lines)

    def get_health_label(self) -> str:
        """Return a health label based on current protection."""
        if self.current_protection >= 90:
            return "🟢 HEALTHY"
        elif self.current_protection >= 70:
            return "🟡 DEGRADED"
        elif self.current_protection >= 40:
            return "🟠 AT RISK"
        else:
            return "🔴 CRITICAL"


# ============================================================
# DECAY CALCULATOR
# ============================================================

class DecayCalculator:
    """
    Calculates the Protection Decay Score based on:
    - Number of broken assumptions
    - Severity of the security property
    - Number of changes that triggered the break
    - Whether new communication paths bypass controls
    """

    # Impact weights for different types of changes
    IMPACT_WEIGHTS = {
        "new_communication_path": 25.0,   # New bypass path is very serious
        "new_asset": 10.0,               # New asset might create risk
        "removed_control": 30.0,         # Losing a control is critical
        "removed_path": 5.0,             # Removing a path might be good or bad
        "new_relationship": 8.0,         # New relationship needs review
        "default": 15.0                  # Unknown changes
    }

    # Severity multipliers
    SEVERITY_MULTIPLIERS = {
        "critical": 1.5,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.5
    }

    def __init__(self):
        pass

    def calculate(self, security_property: SecurityProperty,
                  analyzed_changes: list[ChangeEvent]) -> DecayResult:
        """
        Calculate the decay score for a security property.
        
        Args:
            security_property: The SecurityProperty to evaluate
            analyzed_changes: List of ChangeEvents already analyzed for assumption violations
        
        Returns:
            DecayResult with full breakdown
        """
        result = DecayResult(
            property_id=security_property.property_id,
            property_desc=security_property.description
        )

        # Get severity multiplier
        severity_mult = self.SEVERITY_MULTIPLIERS.get(
            security_property.severity, 1.0
        )

        # Find changes that break assumptions related to this property
        for change in analyzed_changes:
            if change.potentially_breaks_assumptions:
                # Check if this change affects an assumption linked to this property
                affected_asm_id = getattr(change, 'affected_assumption_id', None)
                
                # Check if this assumption belongs to this property
                property_assumption_ids = [a.assumption_id for a in security_property.assumptions]
                
                if affected_asm_id in property_assumption_ids:
                    # Calculate impact
                    base_impact = self.IMPACT_WEIGHTS.get(
                        change.change_type,
                        self.IMPACT_WEIGHTS["default"]
                    )
                    weighted_impact = base_impact * severity_mult

                    # Cap individual impact at 50% to prevent one change from destroying everything
                    weighted_impact = min(weighted_impact, 50.0)

                    contributor = DecayContributor(
                        assumption_id=affected_asm_id,
                        assumption_desc=getattr(change, 'affected_assumption_desc', 'Unknown assumption'),
                        change_desc=change.description,
                        impact_percent=weighted_impact
                    )
                    result.add_contributor(contributor)
                    result.broken_assumptions.append(affected_asm_id)

        # Also check assumptions directly
        for assumption in security_property.assumptions:
            if not assumption.is_valid:
                # If the assumption was invalidated but we haven't counted it yet
                if assumption.assumption_id not in result.broken_assumptions:
                    contributor = DecayContributor(
                        assumption_id=assumption.assumption_id,
                        assumption_desc=assumption.description,
                        change_desc="Assumption manually invalidated",
                        impact_percent=15.0 * severity_mult
                    )
                    result.add_contributor(contributor)
                    result.broken_assumptions.append(assumption.assumption_id)

        return result


# ============================================================
# DEMO: Full Decay Calculation
# ============================================================

def demo_decay_calculation():
    """
    Walk through the complete decay calculation scenario.
    """

    print("=" * 60)
    print("SECURESHADOW - Protection Decay Score Demo")
    print("=" * 60)
    print()

    # ---- Setup: Same as drift detection demo ----
    print("STEP 1: Building baseline and introducing drift...")
    print()

    baseline_data = create_demo_scenario()
    security_property = baseline_data["properties"][0]  # Our main property

    # Baseline graph
    baseline_graph = SecurityGraph()
    for asset in baseline_data["assets"]:
        baseline_graph.add_asset(asset)
    for control in baseline_data["controls"]:
        baseline_graph.add_control(control)
    for assumption in baseline_data["assumptions"]:
        baseline_graph.add_assumption(assumption)
    for path in baseline_data["paths"]:
        baseline_graph.add_path(path)

    # Drift detector
    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    # Introduce drift
    ai_service = Asset("asset-003", "AI Analytics Service", "service", "10.0.3.20")
    new_path = CommunicationPath("path-003", ai_service, baseline_data["assets"][1], "HTTPS")

    current_graph = SecurityGraph()
    for asset in baseline_data["assets"]:
        current_graph.add_asset(asset)
    current_graph.add_asset(ai_service)
    for control in baseline_data["controls"]:
        current_graph.add_control(control)
    for assumption in baseline_data["assumptions"]:
        current_graph.add_assumption(assumption)
    for path in baseline_data["paths"]:
        current_graph.add_path(path)
    current_graph.add_path(new_path)

    # Detect and analyze
    changes = detector.detect_drift(current_graph)
    analyzer = AssumptionAnalyzer(baseline_data["assumptions"])
    analyzed_changes = analyzer.analyze(changes)

    print("   Drift introduced and detected.")
    print()

    # ---- Step 2: Calculate Decay ----
    print("STEP 2: Calculating Protection Decay Score...")
    print()

    calculator = DecayCalculator()
    decay_result = calculator.calculate(security_property, analyzed_changes)

    # ---- Step 3: Display Results ----
    print("=" * 60)
    print("PROTECTION DECAY REPORT")
    print("=" * 60)
    print()

    print(f"Property:     {decay_result.property_desc}")
    print(f"Severity:     {security_property.severity.upper()}")
    print()
    print(f"Baseline:     {decay_result.baseline_protection:.0f}% ████████████████████")
    print(f"Current:      {decay_result.current_protection:.0f}% ", end="")

    # Visual bar for current protection
    bar_length = int(decay_result.current_protection / 5)  # 20 blocks max
    print("█" * bar_length + "░" * (20 - bar_length))

    print()
    print(f"Decay:        {decay_result.decay_percent:.0f}%")
    print(f"Health:       {decay_result.get_health_label()}")
    print()
    print("-" * 60)
    print()

    if decay_result.contributors:
        print("DECAY BREAKDOWN:")
        print()
        for i, contributor in enumerate(decay_result.contributors, 1):
            print(f"  Contributor #{i}:")
            print(f"    Change:    {contributor.change_desc}")
            print(f"    Assumption: {contributor.assumption_desc}")
            print(f"    Impact:    -{contributor.impact_percent:.1f}%")
            print()
    else:
        print("No decay detected. All assumptions hold.")
    print()

    # ---- Step 4: Show the math ----
    print("-" * 60)
    print("CALCULATION DETAILS:")
    print()
    print(f"  Formula: Protection = Baseline - Sum(Impacts)")
    print(f"  Baseline: 100%")
    for c in decay_result.contributors:
        print(f"  - {c.change_desc[:50]}... = -{c.impact_percent:.1f}%")
    print(f"  ─────────────────────────────")
    print(f"  Current: {decay_result.current_protection:.0f}%")
    print()
    print("=" * 60)

    return decay_result


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    result = demo_decay_calculation()
    input("\nPress Enter to close...")
