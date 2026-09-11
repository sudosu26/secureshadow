"""
SECURESHADOW - Phase 6: Minimum-Cost Repair Engine
Generates and ranks repair candidates, selecting the minimum-cost fix
that restores the intended security property.
"""

from datetime import datetime
from data_model import (
    Asset, SecurityControl, Assumption, SecurityProperty,
    CommunicationPath, create_demo_scenario
)
from graph_engine import SecurityGraph
from drift_detection import DriftDetector, AssumptionAnalyzer, ChangeEvent
from decay_calculator import DecayCalculator, DecayResult


# ============================================================
# REPAIR CANDIDATE
# ============================================================

class RepairCandidate:
    """
    A single possible fix for a broken security property.
    """
    def __init__(self, repair_id: str, description: str, action_type: str):
        self.repair_id = repair_id
        self.description = description
        self.action_type = action_type  # "add_control", "remove_path", "add_policy", "restrict_access", etc.
        
        # Cost factors (0-100, lower = cheaper/better)
        self.implementation_cost = 0     # Effort to implement
        self.business_impact = 0         # Disruption to business
        self.operational_risk = 0        # Risk of the repair itself
        self.implementation_time = 0     # How long it takes
        
        # Effectiveness
        self.security_improvement = 0    # How much protection is restored (0-100)
        self.restored_assumptions: list[str] = []
        
        # Calculated
        self.total_cost = 0
        self.cost_effectiveness_ratio = 0

    def calculate_total_cost(self):
        """
        Total cost is a weighted sum of all cost factors.
        Lower total cost = better.
        """
        weights = {
            "implementation_cost": 0.35,
            "business_impact": 0.30,
            "operational_risk": 0.25,
            "implementation_time": 0.10
        }
        self.total_cost = (
            self.implementation_cost * weights["implementation_cost"] +
            self.business_impact * weights["business_impact"] +
            self.operational_risk * weights["operational_risk"] +
            self.implementation_time * weights["implementation_time"]
        )
        
        # Cost-effectiveness: security improvement per unit cost
        if self.total_cost > 0:
            self.cost_effectiveness_ratio = self.security_improvement / self.total_cost
        else:
            self.cost_effectiveness_ratio = float('inf')

    def __repr__(self):
        return (f"Repair({self.repair_id}: {self.description[:50]}... "
                f"cost={self.total_cost:.1f}, improves={self.security_improvement:.0f}%)")


# ============================================================
# REPAIR OPTIMIZER
# ============================================================

class RepairOptimizer:
    """
    Generates candidate repairs for a decay result, assigns costs,
    and selects the minimum-cost effective repair.
    """

    def __init__(self):
        self.candidates: list[RepairCandidate] = []

    def generate_candidates(self, decay_result: DecayResult, 
                            analyzed_changes: list[ChangeEvent],
                            current_graph: SecurityGraph) -> list[RepairCandidate]:
        """
        Generate all possible repair candidates based on the decay result.
        """
        self.candidates = []
        counter = 1

        for change in analyzed_changes:
            if not change.potentially_breaks_assumptions:
                continue

            # ---- Candidate 1: Remove the bypass path ----
            if change.change_type == "new_communication_path":
                r = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description=f"Remove or block the new communication path: {change.description}",
                    action_type="remove_path"
                )
                r.implementation_cost = 20      # Easy: just delete the route/firewall rule
                r.business_impact = 40          # Might disrupt the new service
                r.operational_risk = 10         # Low risk
                r.implementation_time = 15      # Quick to implement
                r.security_improvement = 100    # Fully restores original state
                r.restored_assumptions = [getattr(change, 'affected_assumption_id', 'unknown')]
                self.candidates.append(r)
                counter += 1

                # ---- Candidate 2: Add a security control on the new path ----
                r = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description=f"Add a WAF/Firewall on the new path to protect the traffic",
                    action_type="add_control"
                )
                r.implementation_cost = 40      # Need to configure new control
                r.business_impact = 15          # Minimal disruption
                r.operational_risk = 20         # New control might have bugs
                r.implementation_time = 40      # Takes longer to deploy
                r.security_improvement = 95     # Almost fully restores protection
                r.restored_assumptions = [getattr(change, 'affected_assumption_id', 'unknown')]
                self.candidates.append(r)
                counter += 1

                # ---- Candidate 3: Restrict the new service's access ----
                r = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description=f"Restrict the new service to only access necessary data (least privilege)",
                    action_type="restrict_access"
                )
                r.implementation_cost = 30      # Moderate IAM/policy work
                r.business_impact = 25          # Service still works, just limited
                r.operational_risk = 15         # Policy might be too restrictive
                r.implementation_time = 25      # Moderate
                r.security_improvement = 80     # Reduces risk but path still exists
                r.restored_assumptions = [getattr(change, 'affected_assumption_id', 'unknown')]
                self.candidates.append(r)
                counter += 1

                # ---- Candidate 4: Add encryption on the new path ----
                r = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description=f"Add end-to-end encryption on the new communication path",
                    action_type="add_encryption"
                )
                r.implementation_cost = 25      # Configure TLS
                r.business_impact = 10          # Transparent to users
                r.operational_risk = 10         # Low risk
                r.implementation_time = 20      # Quick
                r.security_improvement = 45     # Protects data in transit but doesn't restore WAF protection
                r.restored_assumptions = []     # Doesn't fully restore the original assumption
                self.candidates.append(r)
                counter += 1

            # ---- Candidate for new assets ----
            elif change.change_type == "new_asset":
                r = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description=f"Conduct security review and apply controls for new asset: {change.description}",
                    action_type="add_control"
                )
                r.implementation_cost = 50
                r.business_impact = 20
                r.operational_risk = 15
                r.implementation_time = 50
                r.security_improvement = 85
                r.restored_assumptions = [getattr(change, 'affected_assumption_id', 'unknown')]
                self.candidates.append(r)
                counter += 1

        # ---- Candidate: Do nothing (always an option) ----
        r = RepairCandidate(
            repair_id=f"REPAIR-{counter:03d}",
            description="Accept the risk and do nothing (document the exception)",
            action_type="accept_risk"
        )
        r.implementation_cost = 0
        r.business_impact = 0
        r.operational_risk = 80        # Very risky to do nothing
        r.implementation_time = 0
        r.security_improvement = 0     # Doesn't fix anything
        self.candidates.append(r)

        # Calculate total costs for all candidates
        for candidate in self.candidates:
            candidate.calculate_total_cost()

        return self.candidates

    def find_minimum_cost_repair(self, min_security_improvement: float = 50.0) -> RepairCandidate:
        """
        Find the repair with the lowest total cost that meets the minimum
        security improvement threshold.
        
        Args:
            min_security_improvement: Minimum percentage improvement required (0-100)
        
        Returns:
            The best RepairCandidate, or None if no candidate meets the threshold.
        """
        # Filter candidates that meet the security improvement threshold
        effective_candidates = [
            c for c in self.candidates 
            if c.security_improvement >= min_security_improvement
        ]

        if not effective_candidates:
            return None

        # Sort by total cost (ascending), then by security improvement (descending)
        effective_candidates.sort(
            key=lambda c: (c.total_cost, -c.security_improvement)
        )

        return effective_candidates[0]

    def rank_all_candidates(self) -> list[RepairCandidate]:
        """
        Return all candidates ranked from best to worst.
        Best = lowest total cost with highest security improvement.
        """
        ranked = sorted(
            self.candidates,
            key=lambda c: (c.total_cost, -c.security_improvement)
        )
        return ranked


# ============================================================
# DEMO: Full Repair Workflow
# ============================================================

def demo_repair_engine():
    """
    Complete demo: Baseline → Drift → Decay → Repairs → Selection
    """

    print("=" * 60)
    print("SECURESHADOW - Minimum-Cost Repair Engine Demo")
    print("=" * 60)
    print()

    # ---- Setup: Run the full pipeline ----
    print("PHASE 1: Running detection and decay analysis...")
    print()

    baseline_data = create_demo_scenario()
    security_property = baseline_data["properties"][0]

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

    changes = detector.detect_drift(current_graph)
    analyzer = AssumptionAnalyzer(baseline_data["assumptions"])
    analyzed_changes = analyzer.analyze(changes)

    calculator = DecayCalculator()
    decay_result = calculator.calculate(security_property, analyzed_changes)

    print(f"   Decay detected: {decay_result.decay_percent:.0f}% protection lost")
    print()

    # ---- Generate Repairs ----
    print("PHASE 2: Generating repair candidates...")
    print()

    optimizer = RepairOptimizer()
    candidates = optimizer.generate_candidates(decay_result, analyzed_changes, current_graph)

    print(f"   Generated {len(candidates)} repair candidates")
    print()

    # ---- Display All Candidates ----
    print("=" * 60)
    print("ALL REPAIR CANDIDATES")
    print("=" * 60)
    print()

    ranked = optimizer.rank_all_candidates()
    for i, candidate in enumerate(ranked, 1):
        # Determine rank badge
        if candidate.action_type == "accept_risk":
            badge = "❌"
        elif i == 1:
            badge = "🥇"
        elif i == 2:
            badge = "🥈"
        elif i == 3:
            badge = "🥉"
        else:
            badge = f"  "

        print(f"{badge} RANK #{i}: {candidate.description}")
        print(f"     Action Type:        {candidate.action_type.replace('_', ' ').title()}")
        print(f"     Implementation Cost: {candidate.implementation_cost}/100")
        print(f"     Business Impact:     {candidate.business_impact}/100")
        print(f"     Operational Risk:    {candidate.operational_risk}/100")
        print(f"     Implementation Time: {candidate.implementation_time}/100")
        print(f"     ─────────────────────────────────")
        print(f"     Total Cost:          {candidate.total_cost:.1f}")
        print(f"     Security Improvement: {candidate.security_improvement}%")
        print(f"     Cost-Effectiveness:  {candidate.cost_effectiveness_ratio:.2f}")
        print()

    # ---- Find Best Repair ----
    print("-" * 60)
    print("MINIMUM-COST REPAIR (meeting >= 50% improvement threshold)")
    print("-" * 60)
    print()

    best = optimizer.find_minimum_cost_repair(min_security_improvement=50.0)

    if best:
        print(f"🏆 RECOMMENDED REPAIR:")
        print(f"   {best.description}")
        print(f"   Total Cost:          {best.total_cost:.1f}")
        print(f"   Security Improvement: {best.security_improvement}%")
        print(f"   Restores Assumptions: {best.restored_assumptions}")
        print()
        print(f"Why this repair?")
        print(f"  - Lowest total cost among effective repairs")
        print(f"  - Restores {best.security_improvement}% of lost protection")
        print(f"  - Minimal business disruption")
    else:
        print("No repair meets the minimum improvement threshold.")

    print()
    print("-" * 60)
    print("BEFORE vs AFTER COMPARISON")
    print("-" * 60)
    print()
    print(f"  BEFORE repair: {decay_result.current_protection:.0f}% protection")
    print(f"  AFTER repair:  {min(100, decay_result.current_protection + best.security_improvement):.0f}% protection")
    print(f"  Improvement:   +{best.security_improvement}%")
    print()
    print("=" * 60)
    print("REPAIR ANALYSIS COMPLETE")
    print("=" * 60)

    return optimizer, best, decay_result


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    optimizer, best_repair, decay = demo_repair_engine()
    input("\nPress Enter to close...")