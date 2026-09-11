"""
SECURESHADOW - Phase 3: Graph Engine
Builds and queries the architecture/security graph using NetworkX.
"""

import networkx as nx
from datetime import datetime
from data_model import (
    Asset, SecurityControl, Assumption, SecurityProperty, CommunicationPath,
    create_demo_scenario
)

# ============================================================
# GRAPH BUILDER
# ============================================================

class SecurityGraph:
    """
    A typed graph that represents:
    - Assets (nodes)
    - Security Controls (nodes)
    - Communication paths (edges)
    - Protection relationships (edges)
    - Assumption dependencies (edges)
    """

    def __init__(self):
        self.graph = nx.DiGraph()  # Directed graph
        self.build_time = datetime.now()

    def add_asset(self, asset: Asset):
        """Add an asset node to the graph."""
        self.graph.add_node(
            asset.asset_id,
            type="asset",
            name=asset.name,
            asset_type=asset.asset_type,
            ip=asset.ip_address,
            label=f"{asset.name}\n({asset.asset_type})"
        )

    def add_control(self, control: SecurityControl):
        """Add a security control node to the graph."""
        self.graph.add_node(
            control.control_id,
            type="control",
            name=control.name,
            control_type=control.control_type,
            status=control.status,
            label=f"{control.name}\n({control.control_type})"
        )
        # Add edges from control to each protected asset
        for asset in control.protects:
            self.graph.add_edge(
                control.control_id,
                asset.asset_id,
                relationship="PROTECTS",
                label="PROTECTS"
            )

    def add_assumption(self, assumption: Assumption):
        """Add an assumption node and link it to its control."""
        node_id = assumption.assumption_id
        self.graph.add_node(
            node_id,
            type="assumption",
            description=assumption.description,
            is_valid=assumption.is_valid,
            label=f"Assumption:\n{assumption.description[:40]}..."
        )
        self.graph.add_edge(
            node_id,
            assumption.related_control_id,
            relationship="DEPENDS_ON",
            label="DEPENDS_ON"
        )

    def add_path(self, path: CommunicationPath):
        """Add a communication path as an edge between assets."""
        self.graph.add_edge(
            path.source.asset_id,
            path.destination.asset_id,
            relationship="COMMUNICATES",
            protocol=path.protocol,
            path_id=path.path_id,
            label=f"{path.protocol}"
        )
        # Mark which controls are on this path
        for control in path.passes_through:
            self.graph.add_edge(
                path.source.asset_id,
                control.control_id,
                relationship="PASSES_THROUGH",
                label="PASSES_THROUGH"
            )

    # ---- QUERY METHODS ----

    def find_paths_between(self, source_id: str, target_id: str):
        """
        Find all communication paths between two assets.
        This is how we detect bypass paths.
        """
        try:
            paths = list(nx.all_simple_paths(self.graph, source_id, target_id, cutoff=5))
            return paths
        except nx.NetworkXNoPath:
            return []

    def find_controls_protecting(self, asset_id: str) -> list:
        """Find all security controls that protect a given asset."""
        controls = []
        for predecessor in self.graph.predecessors(asset_id):
            node_data = self.graph.nodes[predecessor]
            if node_data.get("type") == "control":
                controls.append(predecessor)
        return controls

    def get_protection_summary(self, asset_id: str) -> dict:
        """Get a summary of what protects an asset."""
        controls = self.find_controls_protecting(asset_id)
        return {
            "asset": self.graph.nodes[asset_id].get("name", asset_id),
            "protecting_controls": [
                self.graph.nodes[c].get("name", c) for c in controls
            ],
            "control_count": len(controls)
        }

    def find_all_paths_to_asset(self, asset_id: str, cutoff: int = 5) -> list:
        """
        Find ALL paths from any node to a target asset.
        Useful for detecting new access paths.
        """
        all_paths = []
        for node in self.graph.nodes:
            if node != asset_id:
                try:
                    paths = list(nx.all_simple_paths(self.graph, node, asset_id, cutoff=cutoff))
                    all_paths.extend(paths)
                except nx.NetworkXNoPath:
                    pass
        return all_paths

    def get_graph_stats(self) -> dict:
        """Return basic statistics about the graph."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": self._count_node_types(),
            "edge_relationships": self._count_edge_types()
        }

    def _count_node_types(self) -> dict:
        """Count nodes by type."""
        types = {}
        for node, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")
            types[node_type] = types.get(node_type, 0) + 1
        return types

    def _count_edge_types(self) -> dict:
        """Count edges by relationship type."""
        rels = {}
        for u, v, data in self.graph.edges(data=True):
            rel = data.get("relationship", "unknown")
            rels[rel] = rels.get(rel, 0) + 1
        return rels


# ============================================================
# DEMO: Build and query the graph
# ============================================================

def demo_graph():
    """Build the graph from our demo scenario and run queries."""

    # Get the demo data from our data model
    scenario = create_demo_scenario()

    # Build the graph
    sg = SecurityGraph()

    print("Building graph...")
    for asset in scenario["assets"]:
        sg.add_asset(asset)

    for control in scenario["controls"]:
        sg.add_control(control)

    for assumption in scenario["assumptions"]:
        sg.add_assumption(assumption)

    for path in scenario["paths"]:
        sg.add_path(path)

    print("Graph built successfully.\n")

    # ---- QUERIES ----

    print("=" * 60)
    print("GRAPH QUERIES")
    print("=" * 60)
    print()

    # Stats
    stats = sg.get_graph_stats()
    print("Graph Statistics:")
    print(f"  Total Nodes: {stats['total_nodes']}")
    print(f"  Total Edges: {stats['total_edges']}")
    print(f"  Node Types:  {stats['node_types']}")
    print(f"  Edge Types:  {stats['edge_relationships']}")
    print()

    # Protection summary
    print("-" * 60)
    print("PROTECTION SUMMARY")
    print("-" * 60)
    for asset in scenario["assets"]:
        summary = sg.get_protection_summary(asset.asset_id)
        print(f"  {summary['asset']}:")
        if summary['protecting_controls']:
            for ctrl in summary['protecting_controls']:
                print(f"    - Protected by: {ctrl}")
        else:
            print(f"    - NO PROTECTING CONTROLS")
    print()

    # Find paths to the database
    print("-" * 60)
    print("ALL PATHS TO DATABASE")
    print("-" * 60)
    db_paths = sg.find_all_paths_to_asset("asset-002")
    if db_paths:
        for i, path in enumerate(db_paths, 1):
            # Convert node IDs to names for readability
            named_path = []
            for node_id in path:
                if node_id in sg.graph.nodes:
                    named_path.append(sg.graph.nodes[node_id].get("name", node_id))
                else:
                    named_path.append(node_id)
            print(f"  Path {i}: {' -> '.join(named_path)}")
    else:
        print("  No paths found to database.")
    print()

    # Find paths that bypass the WAF
    print("-" * 60)
    print("PATHS FROM INTERNET TO CUSTOMER API")
    print("-" * 60)
    api_paths = sg.find_paths_between("asset-ext", "asset-001")
    if api_paths:
        for i, path in enumerate(api_paths, 1):
            named_path = []
            has_waf = False
            for node_id in path:
                node_data = sg.graph.nodes.get(node_id, {})
                named_path.append(node_data.get("name", node_id))
                if node_data.get("control_type") == "waf":
                    has_waf = True
            status = "✅ SAFE" if has_waf else "⚠️  BYPASS"
            print(f"  {status} Path {i}: {' -> '.join(named_path)}")
    print()

    print("Graph engine working correctly.")
    print()

    return sg


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    graph = demo_graph()
    input("Press Enter to close...")
