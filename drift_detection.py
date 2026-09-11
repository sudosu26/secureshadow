"""
SECURESHADOW - Phase 4: Drift Detection Engine
Detects architectural changes that may silently break security.
"""

from datetime import datetime
from data_model import Asset, SecurityControl, CommunicationPath, create_demo_scenario
from graph_engine import SecurityGraph


# ============================================================
# CHANGE EVENT
# ============================================================

class ChangeEvent:
    """
    Represents a single detected change between baseline and current state.
    """
    def __init__(self, change_type: str, description: str, affected_entities: list, severity: str = "info"):
        self.change_type = change_type      # "new_asset", "new_path", "removed_control", etc.
        self.description = description
        self.affected_entities = affected_entities
        self.severity = severity            # "info", "warning", "critical"
        self.timestamp = datetime.now()
        self.potentially_breaks_assumptions = False  # Will be set by analyzer

    def __repr__(self):
        return f"[{self.severity.upper()}] {self.change_type}: {self.description}"


# ============================================================
# DRIFT DETECTOR
# ============================================================

class DriftDetector:
    """
    Compares a baseline SecurityGraph with a current SecurityGraph
    and produces a list of ChangeEvents.
    """

    def __init__(self):
        self.baseline_graph: SecurityGraph = None
        self.baseline_snapshot: dict = None

    def set_baseline(self, graph: SecurityGraph):
        """
        Save the current state as the 'known good' baseline.
        We snapshot node IDs, edge information, and control statuses.
        """
        self.baseline_graph = graph
        self.baseline_snapshot = self._snapshot(graph)
        print(f"[BASELINE] Snapshot taken at {datetime.now().strftime('%H:%M:%S')}")
        print(f"[BASELINE] Nodes: {len(self.baseline_snapshot['nodes'])} | Edges: {len(self.baseline_snapshot['edges'])}")

    def detect_drift(self, current_graph: SecurityGraph) -> list[ChangeEvent]:
        """
        Compare current graph against baseline and return all changes.
        """
        if self.baseline_snapshot is None:
            raise ValueError("Baseline not set. Call set_baseline() first.")

        current_snapshot = self._snapshot(current_graph)
        changes = []

        # ---- Detect NEW nodes ----
        baseline_nodes = set(self.baseline_snapshot["nodes"].keys())
        current_nodes = set(current_snapshot["nodes"].keys())

        new_nodes = current_nodes - baseline_nodes
        removed_nodes = baseline_nodes - current_nodes

        for node_id in new_nodes:
            node_data = current_snapshot["nodes"][node_id]
            node_type = node_data.get("type", "unknown")
            node_name = node_data.get("name", node_id)
            changes.append(ChangeEvent(
                change_type=f"new_{node_type}",
                description=f"New {node_type} added: '{node_name}' (ID: {node_id})",
                affected_entities=[node_id],
                severity="warning"
            ))

        for node_id in removed_nodes:
            node_data = self.baseline_snapshot["nodes"][node_id]
            node_type = node_data.get("type", "unknown")
            node_name = node_data.get("name", node_id)
            changes.append(ChangeEvent(
                change_type=f"removed_{node_type}",
                description=f"{node_type.capitalize()} removed: '{node_name}' (ID: {node_id})",
                affected_entities=[node_id],
                severity="critical"
            ))

        # ---- Detect NEW edges (communication paths) ----
        baseline_edges = set(self.baseline_snapshot["edges"].keys())
        current_edges = set(current_snapshot["edges"].keys())

        new_edges = current_edges - baseline_edges
        removed_edges = baseline_edges - current_edges

        for edge_key in new_edges:
            edge_data = current_snapshot["edges"][edge_key]
            source_id, target_id = edge_key.split("->")
            rel = edge_data.get("relationship", "unknown")

            # Get readable names
            source_name = current_snapshot["nodes"].get(source_id, {}).get("name", source_id)
            target_name = current_snapshot["nodes"].get(target_id, {}).get("name", target_id)

            if rel == "COMMUNICATES":
                severity = "critical"  # New communication paths are the most dangerous
                changes.append(ChangeEvent(
                    change_type="new_communication_path",
                    description=f"New data flow: {source_name} -> {target_name}",
                    affected_entities=[source_id, target_id],
                    severity=severity
                ))
            else:
                changes.append(ChangeEvent(
                    change_type=f"new_{rel.lower()}_relationship",
                    description=f"New {rel} relationship: {source_name} -> {target_name}",
                    affected_entities=[source_id, target_id],
                    severity="info"
                ))

        for edge_key in removed_edges:
            edge_data = self.baseline_snapshot["edges"][edge_key]
            source_id, target_id = edge_key.split("->")
            source_name = self.baseline_snapshot["nodes"].get(source_id, {}).get("name", source_id)
            target_name = self.baseline_snapshot["nodes"].get(target_id, {}).get("name", target_id)
            changes.append(ChangeEvent(
                change_type="removed_path",
                description=f"Path removed: {source_name} -> {target_name}",
                affected_entities=[source_id, target_id],
                severity="warning"
            ))

        # ---- Sort by severity ----
        severity_order = {"critical": 0, "warning": 1, "info": 2}
        changes.sort(key=lambda c: severity_order.get(c.severity, 99))

        return changes

    def _snapshot(self, graph: SecurityGraph) -> dict:
        """
        Take a snapshot of the graph's current state.
        Returns a dictionary with nodes and edges.
        """
        nodes = {}
        for node_id, data in graph.graph.nodes(data=True):
            nodes[node_id] = {
                "type": data.get("type", "unknown"),
                "name": data.get("name", node_id),
                "status": data.get("status", "unknown")
            }

        edges = {}
        for u, v, data in graph.graph.edges(data=True):
            edge_key = f"{u}->{v}"
            edges[edge_key] = {
                "relationship": data.get("relationship", "unknown"),
                "protocol": data.get("protocol", ""),
                "path_id": data.get("path_id", "")
            }

        return {"nodes": nodes, "edges": edges}


# ============================================================
# ASSUMPTION ANALYZER
# ============================================================

class AssumptionAnalyzer:
    """
    Analyzes ChangeEvents to determine if they violate any security assumptions.
    This is the 'intelligence' that connects drift to broken security properties.
    """

    def __init__(self, assumptions: list):
        """
        assumptions: list of Assumption objects from the data model.
        """
        self.assumptions = assumptions
        # Map each assumption to what kind of change would break it
        self.assumption_triggers = self._build_triggers()

    def _build_triggers(self) -> dict:
        """
        For each assumption, define what change types could break it.
        This is intentionally simple for the MVP. A real system would use
        the full property graph.
        """
        triggers = {}
        for asm in self.assumptions:
            # Default: new communication paths are dangerous for all assumptions
            triggers[asm.assumption_id] = {
                "assumption": asm,
                "triggered_by": ["new_communication_path", "new_asset"],
                "description": asm.description
            }
        return triggers

    def analyze(self, changes: list[ChangeEvent]) -> list[ChangeEvent]:
        """
        For each change, check if it potentially breaks any assumption.
        Marks the change event with `potentially_breaks_assumptions = True`.
        """
        for change in changes:
            for asm_id, trigger_info in self.assumption_triggers.items():
                if change.change_type in trigger_info["triggered_by"]:
                    # Check if the affected entities overlap with the assumption's concern
                    change.potentially_breaks_assumptions = True
                    change.affected_assumption_id = asm_id
                    change.affected_assumption_desc = trigger_info["description"]
                    change.severity = "critical"  # Escalate
                    break

        return changes


# ============================================================
# DEMO: Baseline vs Drifted Architecture
# ============================================================

def demo_drift_detection():
    """
    Demonstrate:
    1. Create baseline architecture (WAF protects API)
    2. Introduce a new API that bypasses the WAF
    3. Detect the drift
    4. Flag the broken assumption
    """

    print("=" * 60)
    print("SECURESHADOW - Drift Detection Demo")
    print("=" * 60)
    print()

    # ---- PART 1: Build Baseline ----
    print("PHASE 1: Establishing baseline architecture...")
    print()

    baseline_data = create_demo_scenario()

    # Build baseline graph
    baseline_graph = SecurityGraph()
    for asset in baseline_data["assets"]:
        baseline_graph.add_asset(asset)
    for control in baseline_data["controls"]:
        baseline_graph.add_control(control)
    for assumption in baseline_data["assumptions"]:
        baseline_graph.add_assumption(assumption)
    for path in baseline_data["paths"]:
        baseline_graph.add_path(path)

    # Initialize detector and set baseline
    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    print()
    print("Baseline paths to Customer API:")
    for path in baseline_graph.find_paths_between("asset-ext", "asset-001"):
        named = [baseline_graph.graph.nodes[n].get("name", n) for n in path]
        print(f"  ✅ {' -> '.join(named)}")
    print()

    # ---- PART 2: Introduce Drift ----
    print("-" * 60)
    print("PHASE 2: Introducing architectural drift...")
    print()

    # Create a NEW asset: an AI Analytics Service that was added without security review
    ai_service = Asset("asset-003", "AI Analytics Service", "service", "10.0.3.20")
    new_path = CommunicationPath("path-003", ai_service, baseline_data["assets"][1], "HTTPS")
    # NOTE: This path does NOT pass through the WAF!

    # Build current graph (baseline + changes)
    current_graph = SecurityGraph()
    for asset in baseline_data["assets"]:
        current_graph.add_asset(asset)
    current_graph.add_asset(ai_service)  # NEW
    for control in baseline_data["controls"]:
        current_graph.add_control(control)
    for assumption in baseline_data["assumptions"]:
        current_graph.add_assumption(assumption)
    for path in baseline_data["paths"]:
        current_graph.add_path(path)
    current_graph.add_path(new_path)  # NEW BYPASS PATH

    print(f"Change introduced:")
    print(f"  + New Asset: {ai_service.name}")
    print(f"  + New Path:  {ai_service.name} -> {baseline_data['assets'][1].name}")
    print(f"  ⚠️  This path does NOT pass through the WAF!")
    print()

    # ---- PART 3: Detect Drift ----
    print("-" * 60)
    print("PHASE 3: Detecting drift...")
    print()

    changes = detector.detect_drift(current_graph)

    if changes:
        print(f"Detected {len(changes)} change(s):")
        print()
        for i, change in enumerate(changes, 1):
            symbol = "🔴" if change.severity == "critical" else "🟡" if change.severity == "warning" else "🔵"
            print(f"  {symbol} Change {i}: [{change.severity.upper()}]")
            print(f"     Type: {change.change_type}")
            print(f"     Description: {change.description}")
            print(f"     Entities: {change.affected_entities}")
            print()
    else:
        print("No changes detected.")
    print()

    # ---- PART 4: Analyze Assumptions ----
    print("-" * 60)
    print("PHASE 4: Checking security assumptions...")
    print()

    analyzer = AssumptionAnalyzer(baseline_data["assumptions"])
    analyzed_changes = analyzer.analyze(changes)

    broken_found = False
    for change in analyzed_changes:
        if change.potentially_breaks_assumptions:
            broken_found = True
            print(f"  🔴 ASSUMPTION MAY BE BROKEN!")
            print(f"     Change: {change.description}")
            print(f"     Assumption: {change.affected_assumption_desc}")
            print()

    if not broken_found:
        print("  ✅ No assumptions appear to be broken.")
    print()

    # ---- PART 5: Show New Bypass Path ----
    print("-" * 60)
    print("PHASE 5: Updated paths to Customer Database...")
    print()

    db_paths = current_graph.find_all_paths_to_asset("asset-002")
    for i, path in enumerate(db_paths, 1):
        named = []
        passes_waf = False
        for node_id in path:
            node_data = current_graph.graph.nodes.get(node_id, {})
            named.append(node_data.get("name", node_id))
            if node_data.get("control_type") == "waf":
                passes_waf = True

        if passes_waf:
            print(f"  ✅ Path {i}: {' -> '.join(named)} [Protected]")
        else:
            print(f"  🔴 Path {i}: {' -> '.join(named)} [BYPASS - No WAF!]")

    print()
    print("=" * 60)
    print("DRIFT DETECTION COMPLETE")
    print("=" * 60)

    return detector, changes


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    detector, changes = demo_drift_detection()
    input("\nPress Enter to close...")