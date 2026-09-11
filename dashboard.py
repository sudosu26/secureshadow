"""
SECURESHADOW - Phase 7: Unified Dashboard
Complete end-to-end pipeline in one runnable script.
"""

import sys
from datetime import datetime

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

from data_model import (
    Asset, SecurityControl, Assumption, SecurityProperty,
    CommunicationPath, create_demo_scenario
)
from graph_engine import SecurityGraph
from drift_detection import DriftDetector, AssumptionAnalyzer
from decay_calculator import DecayCalculator
from repair_engine import RepairOptimizer


# ============================================================
# COLOR HELPERS
# ============================================================

def green(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def red(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def yellow(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def cyan(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def bold(text):
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}" if HAS_COLOR else text

def dim(text):
    return f"{Style.DIM}{text}{Style.RESET_ALL}" if HAS_COLOR else text


# ============================================================
# DASHBOARD COMPONENTS
# ============================================================

def print_banner():
    """Print the SECURESHADOW banner."""
    print()
    print(bold("╔══════════════════════════════════════════════════════════╗"))
    print(bold("║") + bold("  SECURESHADOW — Security Shadow Protection System     ") + bold("║"))
    print(bold("║") + dim("  Detecting silently degraded security controls        ") + bold("║"))
    print(bold("╚══════════════════════════════════════════════════════════╝"))
    print()


def print_section(title):
    """Print a section header."""
    print()
    print(bold(f"┌─ {title} "))
    print(bold("│"))


def print_section_end():
    """End a section."""
    print(bold("└─────────────────────────────────────────────────────────"))


def print_separator():
    """Print a thin separator."""
    print(dim("  · · · · · · · · · · · · · · · · · · · · · · · · · · ·"))


def print_status(label, value, status="info"):
    """Print a labeled status line."""
    if status == "good":
        symbol = green("✔")
    elif status == "bad":
        symbol = red("✘")
    elif status == "warning":
        symbol = yellow("⚠")
    else:
        symbol = cyan("•")
    
    print(f"  {symbol} {label}: {bold(str(value))}")


def print_progress_bar(label, percentage, width=30):
    """Print a labeled progress bar."""
    filled = int(percentage / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    
    if percentage >= 80:
        color_bar = green(bar)
    elif percentage >= 50:
        color_bar = yellow(bar)
    else:
        color_bar = red(bar)
    
    print(f"  {label}: {color_bar} {percentage:.0f}%")


# ============================================================
# SCENARIO SETUP
# ============================================================

class SecureShadowDemo:
    """Runs the complete SECURESHADOW demo end-to-end."""

    def __init__(self):
        self.baseline_data = None
        self.baseline_graph = None
        self.current_graph = None
        self.detector = None
        self.changes = []
        self.analyzed_changes = []
        self.decay_result = None
        self.repair_candidates = []
        self.best_repair = None
        self.security_property = None

    def setup_baseline(self):
        """Phase 1: Build the baseline architecture."""
        self.baseline_data = create_demo_scenario()
        self.security_property = self.baseline_data["properties"][0]

        self.baseline_graph = SecurityGraph()
        for asset in self.baseline_data["assets"]:
            self.baseline_graph.add_asset(asset)
        for control in self.baseline_data["controls"]:
            self.baseline_graph.add_control(control)
        for assumption in self.baseline_data["assumptions"]:
            self.baseline_graph.add_assumption(assumption)
        for path in self.baseline_data["paths"]:
            self.baseline_graph.add_path(path)

        self.detector = DriftDetector()
        self.detector.set_baseline(self.baseline_graph)

    def introduce_drift(self):
        """Phase 2: Introduce architectural drift."""
        ai_service = Asset("asset-003", "AI Analytics Service", "service", "10.0.3.20")
        new_path = CommunicationPath("path-003", ai_service, 
                                      self.baseline_data["assets"][1], "HTTPS")

        self.current_graph = SecurityGraph()
        for asset in self.baseline_data["assets"]:
            self.current_graph.add_asset(asset)
        self.current_graph.add_asset(ai_service)
        for control in self.baseline_data["controls"]:
            self.current_graph.add_control(control)
        for assumption in self.baseline_data["assumptions"]:
            self.current_graph.add_assumption(assumption)
        for path in self.baseline_data["paths"]:
            self.current_graph.add_path(path)
        self.current_graph.add_path(new_path)

    def detect_drift(self):
        """Phase 3: Detect and analyze drift."""
        self.changes = self.detector.detect_drift(self.current_graph)
        analyzer = AssumptionAnalyzer(self.baseline_data["assumptions"])
        self.analyzed_changes = analyzer.analyze(self.changes)

    def calculate_decay(self):
        """Phase 4: Calculate protection decay."""
        calculator = DecayCalculator()
        self.decay_result = calculator.calculate(
            self.security_property, 
            self.analyzed_changes
        )

    def find_repairs(self):
        """Phase 5: Generate and rank repairs."""
        optimizer = RepairOptimizer()
        self.repair_candidates = optimizer.generate_candidates(
            self.decay_result, 
            self.analyzed_changes, 
            self.current_graph
        )
        self.best_repair = optimizer.find_minimum_cost_repair(
            min_security_improvement=50.0
        )

    def run_all(self):
        """Run the complete pipeline."""
        self.setup_baseline()
        self.introduce_drift()
        self.detect_drift()
        self.calculate_decay()
        self.find_repairs()

    def show_dashboard(self):
        """Display the complete SECURESHADOW dashboard."""

        print_banner()
        print(f"  Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Demo scenario: WAF protecting Customer API → Database")

        # ── SECTION 1: SYSTEM OVERVIEW ──
        print_section("SYSTEM OVERVIEW")

        total_assets = len(self.baseline_data["assets"]) + 1  # +1 for new AI service
        total_controls = len(self.baseline_data["controls"])
        total_properties = len(self.baseline_data["properties"])
        total_assumptions = len(self.baseline_data["assumptions"])
        broken_assumptions = len([c for c in self.analyzed_changes 
                                  if c.potentially_breaks_assumptions])

        print_status("Total Assets", total_assets)
        print_status("Security Controls", total_controls)
        print_status("Security Properties", total_properties)
        print_status("Assumptions (Total)", total_assumptions)
        print_status("Assumptions (At Risk)", broken_assumptions, 
                     "warning" if broken_assumptions > 0 else "good")
        print_section_end()

        # ── SECTION 2: ARCHITECTURE MAP ──
        print_section("ARCHITECTURE MAP")
        print()
        print("  BASELINE (Safe State):")
        print("    Internet ──→ [WAF] ──→ Customer API ──→ Customer Database")
        print()
        print("  CURRENT (Drifted State):")
        print("    Internet ──→ [WAF] ──→ Customer API ──→ Customer Database")
        print("    AI Analytics Service ──────────────→ Customer Database  " + red("← BYPASS"))
        print_section_end()

        # ── SECTION 3: DRIFT DETECTION ──
        print_section("DRIFT DETECTION")

        if not self.changes:
            print_status("Changes Detected", "None", "good")
        else:
            for change in self.changes:
                if change.potentially_breaks_assumptions:
                    icon = "bad"
                elif change.severity == "critical":
                    icon = "warning"
                else:
                    icon = "info"
                print_status(
                    f"[{change.severity.upper()}] {change.change_type}",
                    change.description,
                    icon
                )
        print_section_end()

        # ── SECTION 4: ASSUMPTION ANALYSIS ──
        print_section("SECURITY ASSUMPTION ANALYSIS")

        for assumption in self.baseline_data["assumptions"]:
            # Check if this assumption is broken
            is_broken = any(
                getattr(c, 'affected_assumption_id', None) == assumption.assumption_id
                for c in self.analyzed_changes
                if c.potentially_breaks_assumptions
            )

            if is_broken:
                print_status(
                    f"Assumption {assumption.assumption_id}",
                    assumption.description,
                    "bad"
                )
                print(f"      {red('Status: VIOLATED')}")
                
                # Show which change violated it
                for change in self.analyzed_changes:
                    if getattr(change, 'affected_assumption_id', None) == assumption.assumption_id:
                        print(f"      Cause: {change.description}")
            else:
                print_status(
                    f"Assumption {assumption.assumption_id}",
                    assumption.description,
                    "good"
                )
                print(f"      {green('Status: VALID')}")
        print_section_end()

        # ── SECTION 5: PROTECTION DECAY SCORE ──
        print_section("PROTECTION DECAY SCORE")

        if self.decay_result:
            print()
            print(f"  Security Property: {self.decay_result.property_desc}")
            print()
            
            print_progress_bar("Baseline Protection", 
                              self.decay_result.baseline_protection)
            print_progress_bar("Current Protection ", 
                              self.decay_result.current_protection)
            print()
            
            print_status("Protection Decay", 
                        f"{self.decay_result.decay_percent:.0f}%", 
                        "bad" if self.decay_result.decay_percent > 0 else "good")
            print_status("Health Status", 
                        self.decay_result.get_health_label(),
                        "bad" if "CRITICAL" in self.decay_result.get_health_label() or "AT RISK" in self.decay_result.get_health_label() 
                        else "warning" if "DEGRADED" in self.decay_result.get_health_label()
                        else "good")
            
            if self.decay_result.contributors:
                print()
                print("  " + bold("Decay Breakdown:"))
                for c in self.decay_result.contributors:
                    print(f"    -{c.impact_percent:.1f}% : {c.change_desc}")
                    print(f"            Broken: {c.assumption_desc}")

        print_section_end()

        # ── SECTION 6: REPAIR RECOMMENDATION ──
        print_section("REPAIR RECOMMENDATION")

        if self.best_repair:
            print()
            print(f"  {bold('🏆 Recommended Repair:')}")
            print(f"  {self.best_repair.description}")
            print()
            
            # Cost breakdown
            print(f"  Cost Breakdown:")
            print(f"    Implementation Cost:  {self.best_repair.implementation_cost}/100")
            print(f"    Business Impact:      {self.best_repair.business_impact}/100")
            print(f"    Operational Risk:     {self.best_repair.operational_risk}/100")
            print(f"    Implementation Time:  {self.best_repair.implementation_time}/100")
            print(f"    ─────────────────────────────")
            print(f"    Total Cost:           {self.best_repair.total_cost:.1f}")
            print(f"    Security Improvement: {self.best_repair.security_improvement}%")
            print()

            # Before/After
            before = self.decay_result.current_protection
            after = min(100, before + self.best_repair.security_improvement)
            
            print(f"  Before Repair: {before:.0f}% {red('█' * int(before/5) + '░' * (20 - int(before/5)))}")
            print(f"  After Repair:  {after:.0f}% {green('█' * int(after/5) + '░' * (20 - int(after/5)))}")
            print(f"  Improvement:   {green('+' + str(self.best_repair.security_improvement) + '%')}")
            print()

            # Other options
            print(f"  {bold('Alternative Repairs:')}")
            ranked = sorted(self.repair_candidates, 
                          key=lambda c: (c.total_cost, -c.security_improvement))
            for i, candidate in enumerate(ranked):
                if candidate != self.best_repair and i < 3:
                    print(f"    {i+1}. {candidate.description}")
                    print(f"       Cost: {candidate.total_cost:.1f} | "
                          f"Improvement: {candidate.security_improvement}%")

        else:
            print_status("No repair found", 
                        "No repair meets the minimum improvement threshold",
                        "warning")

        print_section_end()

        # ── SECTION 7: VERDICT ──
        print_section("FINAL VERDICT")
        print()
        
        if self.decay_result and self.decay_result.decay_percent > 0:
            print(f"  The WAF is still {green('ACTIVE')} and {green('CONFIGURED CORRECTLY')}.")
            print(f"  However, a new communication path has {red('BYPASSED')} it.")
            print(f"  Traditional scanners would show: {green('ALL CONTROLS HEALTHY')}")
            print(f"  SECURESHADOW detected:        {red('PROTECTION DEGRADED')}")
            print()
            print(f"  {bold('Result:')} Protection decay of {self.decay_result.decay_percent:.0f}% detected.")
            print(f"  {bold('Action:')} {self.best_repair.description}")
        else:
            print(f"  {green('All security properties intact. No drift detected.')}")

        print_section_end()

        # ── FOOTER ──
        print()
        print(bold("╔══════════════════════════════════════════════════════════╗"))
        print(bold("║") + "  Demo complete. SECURESHADOW pipeline functional.    " + bold("║"))
        print(bold("╚══════════════════════════════════════════════════════════╝"))
        print()


# ============================================================
# MAIN
# ============================================================

def main():
    """Run the complete SECURESHADOW dashboard demo."""

    demo = SecureShadowDemo()

    print()
    print(cyan("Running SECURESHADOW pipeline..."))
    print(cyan("This simulates: Baseline → Drift → Detection → Decay → Repair"))

    # Run all phases
    demo.run_all()

    # Clear screen for clean dashboard (optional)
    print("\n" * 2)

    # Show the dashboard
    demo.show_dashboard()


if __name__ == "__main__":
    main()
    input("Press Enter to close...")
