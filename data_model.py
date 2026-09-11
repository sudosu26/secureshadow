"""
SECURESHADOW - Phase 2: Core Data Model
Defines the fundamental entities of the system.
"""

from datetime import datetime
from typing import Optional

# ============================================================
# ENTITY DEFINITIONS
# ============================================================

class Asset:
    """
    Represents any thing that needs protection.
    Examples: a database, an API server, a microservice, a file store.
    """
    def __init__(self, asset_id: str, name: str, asset_type: str, ip_address: Optional[str] = None):
        self.asset_id = asset_id
        self.name = name
        self.asset_type = asset_type    # e.g., "database", "api", "service", "storage"
        self.ip_address = ip_address
        self.created_at = datetime.now()

    def __repr__(self):
        return f"Asset({self.asset_id}: {self.name}, type={self.asset_type})"


class SecurityControl:
    """
    Represents a security mechanism in place.
    Examples: WAF, Firewall, IAM policy, MFA, Encryption.
    """
    def __init__(self, control_id: str, name: str, control_type: str, status: str = "active"):
        self.control_id = control_id
        self.name = name
        self.control_type = control_type  # e.g., "waf", "firewall", "iam", "mfa", "encryption"
        self.status = status              # "active", "inactive", "misconfigured"
        self.protects: list[Asset] = []   # Assets this control protects
        self.created_at = datetime.now()

    def add_protected_asset(self, asset: Asset):
        """Link an asset that this control protects."""
        self.protects.append(asset)

    def __repr__(self):
        return f"SecurityControl({self.control_id}: {self.name}, type={self.control_type}, status={self.status})"


class Assumption:
    """
    A condition that must be true for a security control to be effective.
    Example: "All external traffic passes through the WAF"
    """
    def __init__(self, assumption_id: str, description: str, related_control_id: str):
        self.assumption_id = assumption_id
        self.description = description
        self.related_control_id = related_control_id
        self.is_valid = True  # Initially assume the assumption holds
        self.last_checked = None

    def invalidate(self):
        """Mark this assumption as broken."""
        self.is_valid = False
        self.last_checked = datetime.now()

    def validate(self):
        """Mark this assumption as valid."""
        self.is_valid = True
        self.last_checked = datetime.now()

    def __repr__(self):
        status = "VALID" if self.is_valid else "BROKEN"
        return f"Assumption({self.assumption_id}: [{status}] {self.description})"


class SecurityProperty:
    """
    The intended security guarantee a control is supposed to provide.
    Example: "Only authorized employees can access customer data"
    """
    def __init__(self, property_id: str, description: str, control_id: str, severity: str = "high"):
        self.property_id = property_id
        self.description = description
        self.control_id = control_id
        self.severity = severity          # "critical", "high", "medium", "low"
        self.assumptions: list[Assumption] = []
        self.protection_level = 100.0     # Starts at 100% (fully protected)
        self.created_at = datetime.now()

    def add_assumption(self, assumption: Assumption):
        """Link an assumption required for this property to hold."""
        self.assumptions.append(assumption)

    def recalculate_protection(self):
        """
        Simple recalculation: each broken assumption reduces protection.
        If no assumptions, protection stays at 100%.
        """
        if len(self.assumptions) == 0:
            self.protection_level = 100.0
            return

        valid_count = sum(1 for a in self.assumptions if a.is_valid)
        self.protection_level = (valid_count / len(self.assumptions)) * 100.0

    def __repr__(self):
        return f"SecurityProperty({self.property_id}: {self.description[:50]}... [{self.protection_level:.0f}%])"


class CommunicationPath:
    """
    Represents a data flow or network path between two assets.
    This is how services talk to each other.
    """
    def __init__(self, path_id: str, source: Asset, destination: Asset, protocol: str = "HTTPS"):
        self.path_id = path_id
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.passes_through: list[SecurityControl] = []  # Controls on this path
        self.created_at = datetime.now()

    def add_control(self, control: SecurityControl):
        """Add a security control that sits on this path."""
        self.passes_through.append(control)

    def __repr__(self):
        controls = [c.name for c in self.passes_through]
        return f"Path({self.path_id}: {self.source.name} -> {self.destination.name}, controls={controls})"


# ============================================================
# DEMO: Create a realistic scenario
# ============================================================

def create_demo_scenario():
    """
    Build a small enterprise scenario:
    - An API that serves customer data
    - A database storing that data
    - A WAF protecting the API
    - An assumption that all traffic goes through the WAF
    """

    print("=" * 60)
    print("SECURESHADOW - Core Data Model Demo")
    print("=" * 60)
    print()

    # ---- Assets ----
    customer_api = Asset("asset-001", "Customer API", "api", "10.0.1.5")
    customer_db = Asset("asset-002", "Customer Database", "database", "10.0.2.10")

    print("Assets created:")
    print(f"  {customer_api}")
    print(f"  {customer_db}")
    print()

    # ---- Security Control: WAF ----
    waf = SecurityControl("ctrl-001", "Web Application Firewall", "waf", "active")
    waf.add_protected_asset(customer_api)

    print("Security Control created:")
    print(f"  {waf}")
    print(f"  Protects: {[a.name for a in waf.protects]}")
    print()

    # ---- Assumption ----
    all_traffic_through_waf = Assumption(
        "asm-001",
        "All external HTTP traffic to Customer API must pass through the WAF",
        "ctrl-001"
    )

    print("Assumption created:")
    print(f"  {all_traffic_through_waf}")
    print()

    # ---- Security Property ----
    protect_customer_data = SecurityProperty(
        "prop-001",
        "Only authenticated and authorized users can access customer PII data",
        "ctrl-001",
        severity="critical"
    )
    protect_customer_data.add_assumption(all_traffic_through_waf)

    print("Security Property created:")
    print(f"  {protect_customer_data}")
    print(f"  Severity: {protect_customer_data.severity}")
    print()

    # ---- Communication Path ----
    internet_to_api = CommunicationPath("path-001", 
                                         Asset("asset-ext", "Internet", "external"),
                                         customer_api,
                                         "HTTPS")
    internet_to_api.add_control(waf)

    api_to_db = CommunicationPath("path-002", customer_api, customer_db, "TCP")

    print("Communication Paths created:")
    print(f"  {internet_to_api}")
    print(f"  {api_to_db}")
    print()

    # ---- Summary ----
    print("-" * 60)
    print("SCENARIO SUMMARY")
    print("-" * 60)
    print(f"  Assets:            {customer_api.name}, {customer_db.name}")
    print(f"  Security Control:  {waf.name} ({waf.status})")
    print(f"  Security Property: {protect_customer_data.description}")
    print(f"  Protection Level:  {protect_customer_data.protection_level:.0f}%")
    print(f"  Assumption:        {all_traffic_through_waf.description}")
    print(f"  Assumption Valid:  {all_traffic_through_waf.is_valid}")
    print()
    print("Data model is working correctly.")
    print()

    return {
        "assets": [customer_api, customer_db],
        "controls": [waf],
        "assumptions": [all_traffic_through_waf],
        "properties": [protect_customer_data],
        "paths": [internet_to_api, api_to_db]
    }


# ============================================================
# RUN THE DEMO
# ============================================================

if __name__ == "__main__":
    scenario = create_demo_scenario()
    
    # Keep the window open
    input("Press Enter to close...")
