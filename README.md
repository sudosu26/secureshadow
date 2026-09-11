# SECURESHADOW

**Detecting security controls that become ineffective without actually failing.**

Traditional security tools ask: "Is this control configured correctly?"  
SECURESHADOW asks: "Does this control still enforce the security property it was designed to enforce?"

When the environment changes—a new API, a new microservice, a new data path—a control can remain perfectly configured but silently lose its protective power. SECURESHADOW detects that silent decay.

## How It Works

1. **Model** — Every security control gets a formal Security Property with explicit Assumptions and Dependencies.
2. **Graph** — The entire architecture (assets, communication paths, controls) is represented as a live graph.
3. **Baseline** — A "known good" snapshot is taken.
4. **Drift Detection** — The current state is continuously compared against the baseline.
5. **Assumption Analysis** — Changes are checked against security assumptions.
6. **Protection Decay Score** — A deterministic, explainable score shows how much protection has eroded and why.
7. **Repair Engine** — Multiple repair candidates are generated, costed, and ranked. The minimum-cost effective repair is recommended.

## Project Structure

| File | Purpose |
|------|---------|
| `data_model.py` | Core entities: Asset, SecurityControl, Assumption, SecurityProperty, CommunicationPath |
| `graph_engine.py` | Builds and queries the typed architecture/security graph using NetworkX |
| `drift_detection.py` | Compares baseline vs current graph, produces ChangeEvents, flags broken assumptions |
| `decay_calculator.py` | Calculates deterministic Protection Decay Score with full attribution |
| `repair_engine.py` | Generates, costs, and ranks repair candidates; selects minimum-cost effective repair |
| `dashboard.py` | Unified console dashboard running the complete pipeline |

## Requirements

- Python 3.12+
- NetworkX (`pip install networkx`)
- Colorama (`pip install colorama`) — optional, for colored dashboard output

## How to Run the Full Demo

1. Open the project folder.
2. Right-click on `dashboard.py`.
3. Select **Open with → Python 3.12**.
4. The complete dashboard will appear showing baseline, drift, detection, decay, and repair.

You can also run individual components:
- `data_model.py` — tests the core data model
- `graph_engine.py` — builds and queries the graph
- `drift_detection.py` — detects and analyzes drift
- `decay_calculator.py` — calculates protection decay
- `repair_engine.py` — generates and ranks repairs

## Demo Scenario

A Web Application Firewall (WAF) protects a Customer API that connects to a Customer Database. The security property is: "Only authenticated and authorized users can access customer PII data." The assumption is: "All external HTTP traffic passes through the WAF."

An AI Analytics Service is added that connects directly to the database, bypassing the WAF. The WAF remains active and correctly configured. Traditional scanners show everything green. SECURESHADOW detects the bypass, calculates a 37% protection decay, and recommends the minimum-cost repair (least-privilege access restriction).

## Limitations (MVP)

- Graph is synthetic and in-memory (not persistent)
- Assumption triggers are rule-based, not ML
- Repair costs are heuristics for demonstration
- No real-time monitoring; manual snapshot comparison
- Single-node deployment, no authentication

## Future Roadmap

- Persistent graph database (Neo4j)
- Real-time change feed (cloud APIs, IaC scanning)
- Machine learning for assumption inference
- UI dashboard (Streamlit or web)
- Multi-cloud support
- CI/CD integration

---

*Built as a prototype to demonstrate the concept of silent security control degradation detection.*