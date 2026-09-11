"""
SECURESHADOW - Streamlit Web Dashboard
Professional, interactive UI for the silent security decay detection system.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime

# Import our core engines
from data_model import (
    Asset, SecurityControl, Assumption, SecurityProperty,
    CommunicationPath, create_demo_scenario
)
from graph_engine import SecurityGraph
from drift_detection import DriftDetector, AssumptionAnalyzer
from decay_calculator import DecayCalculator
from repair_engine import RepairOptimizer


# ============================================================
# PAGE CONFIG & STYLING
# ============================================================

st.set_page_config(
    page_title="SECURESHADOW",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional dark theme
st.markdown("""
<style>
    /* Dark cyber theme */
    .stApp {
        background: linear-gradient(135deg, #0f1117 0%, #1a1d24 100%);
    }
    .main .block-container {
        padding-top: 2rem;
    }
    h1, h2, h3, h4, h5, h6 {
        color: #00d4ff;
    }
    .stButton>button {
        background: linear-gradient(90deg, #00d4ff, #0072ff);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 2rem;
        font-weight: bold;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        transform: scale(1.02);
        box-shadow: 0 0 20px #00d4ff80;
    }
    .metric-card {
        background: #1e2130;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 4px solid #00d4ff;
    }
    .metric-card.warning {
        border-left-color: #ffaa00;
    }
    .metric-card.danger {
        border-left-color: #ff4444;
    }
    .metric-card.success {
        border-left-color: #00ff88;
    }
    .big-number {
        font-size: 3rem;
        font-weight: bold;
    }
    .section-title {
        font-size: 1.3rem;
        font-weight: bold;
        color: #00d4ff;
        margin-top: 2rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #2a2d3a;
    }
    .stMarkdown {
        color: #c0c5d0;
    }
    .repair-highlight {
        background: #1e3a2f;
        border-radius: 10px;
        padding: 1rem;
        border: 1px solid #00ff88;
        margin: 1rem 0;
    }
    [data-testid="stMetricValue"] {
        color: #00d4ff;
    }
    .stMetricLabel {
        color: #8a8f9d !important;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================

if 'pipeline_run' not in st.session_state:
    st.session_state.pipeline_run = False
    st.session_state.baseline_data = None
    st.session_state.decay_result = None
    st.session_state.analyzed_changes = None
    st.session_state.best_repair = None
    st.session_state.candidates = None
    st.session_state.security_property = None
    st.session_state.current_protection = None
    st.session_state.baseline_protection = 100.0


# ============================================================
# PIPELINE EXECUTION FUNCTION
# ============================================================

def run_pipeline():
    """Execute the full SECURESHADOW pipeline and store results in session state."""
    # Setup
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

    # Introduce drift (AI Analytics Service bypasses WAF)
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

    # Detect drift
    changes = detector.detect_drift(current_graph)
    analyzer = AssumptionAnalyzer(baseline_data["assumptions"])
    analyzed_changes = analyzer.analyze(changes)

    # Calculate decay
    calculator = DecayCalculator()
    decay_result = calculator.calculate(security_property, analyzed_changes)

    # Find repairs
    optimizer = RepairOptimizer()
    candidates = optimizer.generate_candidates(decay_result, analyzed_changes, current_graph)
    best_repair = optimizer.find_minimum_cost_repair(min_security_improvement=50.0)

    # Store in session state
    st.session_state.baseline_data = baseline_data
    st.session_state.decay_result = decay_result
    st.session_state.analyzed_changes = analyzed_changes
    st.session_state.best_repair = best_repair
    st.session_state.candidates = candidates
    st.session_state.security_property = security_property
    st.session_state.current_protection = decay_result.current_protection
    st.session_state.baseline_protection = decay_result.baseline_protection
    st.session_state.pipeline_run = True


# ============================================================
# UI COMPONENTS
# ============================================================

def protection_gauge(value, title):
    """Create a Plotly gauge chart for protection level."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        number={"suffix": "%", "font": {"size": 40, "color": "#00d4ff"}},
        delta={"reference": 100, "increasing": {"color": "red"}, "decreasing": {"color": "green"}},
        title={"text": title, "font": {"size": 16, "color": "#8a8f9d"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8a8f9d"},
            "bar": {"color": "#00d4ff" if value >= 80 else "#ffaa00" if value >= 50 else "#ff4444"},
            "bgcolor": "#1e2130",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 50], "color": "#331a1a"},
                {"range": [50, 80], "color": "#332b1a"},
                {"range": [80, 100], "color": "#1a3325"}
            ],
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#c0c5d0"},
        height=300,
        margin=dict(t=40, b=20, l=20, r=20)
    )
    return fig


def decay_breakdown_chart(contributors):
    """Create a horizontal bar chart for decay contributors."""
    if not contributors:
        return None
    names = [c.change_desc[:40] + "..." for c in contributors]
    impacts = [c.impact_percent for c in contributors]
    df = pd.DataFrame({"Change": names, "Impact (%)": impacts})
    fig = px.bar(
        df, x="Impact (%)", y="Change", orientation="h",
        color="Impact (%)", color_continuous_scale=["#ffaa00", "#ff4444"],
        title="Decay Contributors"
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#c0c5d0"},
        yaxis={"categoryorder": "total ascending"},
        height=200 + len(contributors) * 30,
        margin=dict(t=40, b=20, l=20, r=20)
    )
    return fig


def repair_table(candidates, best_repair):
    """Display repair candidates as a styled dataframe."""
    data = []
    for c in candidates:
        data.append({
            "Description": c.description[:60] + ("..." if len(c.description) > 60 else ""),
            "Action Type": c.action_type.replace("_", " ").title(),
            "Total Cost": f"{c.total_cost:.1f}",
            "Security Improvement": f"{c.security_improvement}%",
            "Recommended": "⭐" if c == best_repair else ""
        })
    df = pd.DataFrame(data)
    return df


# ============================================================
# MAIN APP LAYOUT
# ============================================================

# Header
st.title("🛡️ SECURESHADOW")
st.markdown("#### Detection of silently degraded security controls")
st.markdown("---")

# Sidebar
with st.sidebar:
    st.markdown("## 🧠 About")
    st.markdown("""
    SECURESHADOW models **security intent**, not just configurations.
    It detects when a perfectly functioning control silently loses its
    protective power because the environment changed.
    """)
    st.markdown("---")
    st.markdown("### 📊 Demo Scenario")
    st.markdown("""
    - WAF protects Customer API → Database
    - New AI service added, connecting directly to DB
    - WAF still green, but assumption violated
    """)
    st.markdown("---")
    st.markdown("### 🔧 Controls")
    run_button = st.button("▶️ Run Full Pipeline", use_container_width=True)
    if run_button:
        with st.spinner("Running SECURESHADOW pipeline..."):
            run_pipeline()
        st.success("Pipeline complete!")

# Main content area
if not st.session_state.pipeline_run:
    st.markdown("""
    ## Welcome to SECURESHADOW
    
    **Click the ▶️ Run Full Pipeline button in the sidebar** to see the demo.
    
    The system will:
    1. Build a baseline architecture with a WAF-protected API
    2. Introduce a new AI service that bypasses the WAF
    3. Detect the drift
    4. Calculate the Protection Decay Score
    5. Recommend the minimum-cost repair
    
    The WAF remains **active and correctly configured** — traditional tools would
    show everything green. SECURESHADOW reveals the silent decay.
    """)
else:
    # ---- Architecture Section ----
    st.markdown('<div class="section-title">🏗️ Architecture Map</div>', unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Baseline (Safe State)**")
        st.code("Internet → [WAF] → Customer API → Customer Database", language="")
    with col2:
        st.markdown("**Current (Drifted State)**")
        st.code("Internet → [WAF] → Customer API → Customer Database\nAI Analytics Service ─────────→ Customer Database 🚨 BYPASS", language="")

    # ---- Drift Detection ----
    st.markdown('<div class="section-title">🔍 Drift Detection</div>', unsafe_allow_html=True)
    if st.session_state.analyzed_changes:
        for change in st.session_state.analyzed_changes:
            severity_color = "#ff4444" if change.severity == "critical" else "#ffaa00" if change.severity == "warning" else "#00d4ff"
            st.markdown(f"""
            <div class="metric-card {"danger" if change.severity=="critical" else "warning" if change.severity=="warning" else ""}">
                <span style="color:{severity_color}; font-weight:bold;">[{change.severity.upper()}]</span> 
                <strong>{change.change_type.replace('_',' ').title()}</strong>: {change.description}
            </div>
            """, unsafe_allow_html=True)

    # ---- Assumption Analysis ----
    st.markdown('<div class="section-title">⚠️ Security Assumption Analysis</div>', unsafe_allow_html=True)
    for assumption in st.session_state.baseline_data["assumptions"]:
        is_broken = any(
            getattr(c, 'affected_assumption_id', None) == assumption.assumption_id
            for c in st.session_state.analyzed_changes
            if c.potentially_breaks_assumptions
        )
        if is_broken:
            st.markdown(f"""
            <div class="metric-card danger">
                <span style="color:#ff4444;">🔴 VIOLATED</span> — {assumption.description}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="metric-card success">
                <span style="color:#00ff88;">✅ VALID</span> — {assumption.description}
            </div>
            """, unsafe_allow_html=True)

    # ---- Protection Decay Score ----
    st.markdown('<div class="section-title">📉 Protection Decay Score</div>', unsafe_allow_html=True)
    col1, col2 = st.columns([1, 2])
    with col1:
        gauge_fig = protection_gauge(
            st.session_state.current_protection,
            "Current Protection"
        )
        st.plotly_chart(gauge_fig, use_container_width=True)
    with col2:
        dr = st.session_state.decay_result
        st.markdown(f"""
        <div class="metric-card">
            <strong>Security Property:</strong><br>
            {dr.property_desc}<br><br>
            <strong>Baseline Protection:</strong> {dr.baseline_protection:.0f}%<br>
            <strong>Current Protection:</strong> {dr.current_protection:.0f}%<br>
            <strong style="color:#ff4444;">Protection Decay:</strong> {dr.decay_percent:.0f}%<br>
            <strong>Health:</strong> {dr.get_health_label()}
        </div>
        """, unsafe_allow_html=True)
        if dr.contributors:
            chart = decay_breakdown_chart(dr.contributors)
            st.plotly_chart(chart, use_container_width=True)

    # ---- Repair Recommendation ----
    st.markdown('<div class="section-title">🔧 Repair Recommendation</div>', unsafe_allow_html=True)
    best = st.session_state.best_repair
    if best:
        st.markdown(f"""
        <div class="repair-highlight">
            <h3 style="color:#00ff88;">🏆 Recommended Repair</h3>
            <p style="font-size:1.1rem;">{best.description}</p>
            <table style="width:100%; color:#c0c5d0;">
                <tr><td>Implementation Cost:</td><td>{best.implementation_cost}/100</td></tr>
                <tr><td>Business Impact:</td><td>{best.business_impact}/100</td></tr>
                <tr><td>Operational Risk:</td><td>{best.operational_risk}/100</td></tr>
                <tr><td>Implementation Time:</td><td>{best.implementation_time}/100</td></tr>
                <tr style="border-top:1px solid #2a2d3a;"><td><strong>Total Cost:</strong></td><td><strong>{best.total_cost:.1f}</strong></td></tr>
                <tr><td><strong>Security Improvement:</strong></td><td><strong style="color:#00ff88;">+{best.security_improvement}%</strong></td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

    # Before/After comparison
    st.markdown("**Before vs After Repair**")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Before", f"{st.session_state.current_protection:.0f}%")
    with col2:
        after = min(100, st.session_state.current_protection + best.security_improvement)
        st.metric("After", f"{after:.0f}%", delta=f"+{best.security_improvement}%")

    # All candidates table
    st.markdown("**All Repair Candidates**")
    df = repair_table(st.session_state.candidates, best)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Final Verdict
    st.markdown('<div class="section-title">📋 Final Verdict</div>', unsafe_allow_html=True)
    st.markdown(f"""
    > The WAF is still **ACTIVE** and **CORRECTLY CONFIGURED**.  
    > Traditional scanners would show: 🟢 **ALL CONTROLS HEALTHY**  
    > SECURESHADOW detected: 🔴 **PROTECTION DEGRADED ({st.session_state.decay_result.decay_percent:.0f}%)**  
    >  
    > **Action:** {best.description}
    """)

    # Footer timestamp
    st.markdown(f"<p style='text-align:right; color:#5a5e6b;'>Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>", unsafe_allow_html=True)


# ============================================================
# RUN INSTRUCTIONS (hidden in app)
# ============================================================
# To run: streamlit run streamlit_app.py
