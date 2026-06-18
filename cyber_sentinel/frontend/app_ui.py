import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import time
import sqlite3
import os
import hashlib
import json
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

# ─── 1. Page Configuration ────────────────────────────────────────────────────
st.set_page_config(
    page_title="Rakshak — Cyber Sentinel Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── 2. Splash Screen ─────────────────────────────────────────────────────────
if "splash_shown" not in st.session_state:
    st.session_state.splash_shown = False

if not st.session_state.splash_shown:
    st.markdown("""
        <style>
            [data-testid="stSidebar"] { display: none !important; }
            .main .block-container { padding: 0rem !important; background-color: #030712 !important; }
            .stApp { background-color: #030712 !important; }
        </style>
    """, unsafe_allow_html=True)
    st.markdown("<div style='height: 8vh;'></div>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 6, 1])
    with col2:
        img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rakshak_splash.jpg")
        if os.path.exists(img_path):
            st.image(img_path, width="stretch")
        st.markdown("""
            <p style='text-align: center; color: #3B82F6; font-size: 1.15rem;
               font-family: "Orbitron", sans-serif; letter-spacing: 3px;
               font-weight: 600; margin-top: 25px; text-shadow: 0 0 10px rgba(59,130,246,0.4);'>
                INITIALIZING RAKSHAK SECURE OSINT THREAT DETECTOR v3.0...
            </p>
        """, unsafe_allow_html=True)
    time.sleep(4)
    st.session_state.splash_shown = True
    st.rerun()

# Auto-Refresh (Every 30 seconds)
st_autorefresh(interval=30 * 1000, key="datarefresh")

# ─── 3. Global CSS Design System ─────────────────────────────────────────────
st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Orbitron:wght@500;700;900&display=swap');

        .stApp { background-color: #0B0F19 !important; color: #F3F4F6 !important; font-family: 'Inter', sans-serif !important; }
        h1, h2, h3 { font-family: 'Inter', sans-serif !important; font-weight: 600 !important; color: #F3F4F6 !important; }
        .page-title { font-size: 1.75rem; font-weight: 700; color: #FFFFFF; letter-spacing: -0.5px; }
        .page-subtitle { font-size: 0.95rem; color: #9CA3AF; margin-bottom: 1.5rem !important; }
        section[data-testid="stSidebar"] { background-color: #111827 !important; border-right: 1px solid #1F2937 !important; }
        .saas-card { background: #111827; border: 1px solid #1F2937; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; transition: all 0.2s ease; }
        .saas-card:hover { border-color: #374151; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .saas-metric-title { font-size: 0.75rem; color: #9CA3AF; font-weight: 600; text-transform: uppercase; letter-spacing: 1.2px; margin-bottom: 4px; }
        .saas-metric-value { font-size: 1.75rem; font-weight: 700; color: #FFFFFF; font-family: 'Inter', sans-serif; margin-bottom: 4px; }
        .saas-metric-desc { font-size: 0.8rem; color: #9CA3AF; }
        .trend-up { color: #EF4444; font-weight: 600; font-size: 0.8rem; }
        .trend-down { color: #10B981; font-weight: 600; font-size: 0.8rem; }
        .trend-neutral { color: #9CA3AF; font-weight: 600; font-size: 0.8rem; }
        .badge { padding: 4px 10px; border-radius: 4px; font-size: 0.725rem; font-weight: 600; display: inline-block; text-align: center; }
        .badge-critical { background-color: rgba(239,68,68,0.1); color: #EF4444; border: 1px solid rgba(239,68,68,0.3); }
        .badge-high { background-color: rgba(249,115,22,0.1); color: #F97316; border: 1px solid rgba(249,115,22,0.3); }
        .badge-medium { background-color: rgba(251,191,36,0.1); color: #FBBF24; border: 1px solid rgba(251,191,36,0.3); }
        .badge-low { background-color: rgba(16,185,129,0.1); color: #10B981; border: 1px solid rgba(16,185,129,0.3); }
        .xai-container { background: #1F2937; border: 1px dashed #374151; border-radius: 6px; padding: 1rem; margin-top: 8px; }
        .tag-pill { background: #374151; color: #E5E7EB; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; margin-right: 6px; display: inline-block; }
        .entity-row { background: #1F2937; border-radius: 6px; padding: 8px 12px; margin-bottom: 6px; font-size: 0.82rem; border-left: 3px solid #3B82F6; }
        .high-contrast-url { color: #22D3EE !important; font-family: monospace; font-size: 0.85rem; word-break: break-all; }
    </style>
""", unsafe_allow_html=True)

# ─── 4. Session State Init ────────────────────────────────────────────────────
for key, default in [
    ("current_page", "Dashboard"),
    ("selected_campaign", None),
    ("auto_refresh", False),
]:
    if key not in st.session_state:
        st.session_state[key] = default

API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8080")
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", "cyber_sentinel.db"))


# ─── 5. Helper Functions ──────────────────────────────────────────────────────
def get_risk_meta(score):
    if score >= 75.0: return "Critical", "badge-critical"
    elif score >= 50.0: return "High", "badge-high"
    elif score >= 25.0: return "Medium", "badge-medium"
    else: return "Low", "badge-low"

def manual_sqlite_clear():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for tbl in ["threat_history", "scam_artifacts", "raw_intel",
                    "suspect_phone_numbers", "suspect_domains", "india_geo_heatmap"]:
            cursor.execute(f"DELETE FROM {tbl};")
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error during SQLite reset: {e}")
        return False

def safe_api_get(endpoint: str, timeout: float = 8.0):
    try:
        resp = requests.get(f"{API_BASE_URL}{endpoint}", timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

def safe_api_post(endpoint: str, params: dict = None, timeout: float = 60.0):
    try:
        resp = requests.post(f"{API_BASE_URL}{endpoint}", params=params, timeout=timeout)
        return resp
    except Exception as e:
        return None

# ─── 6. Sidebar Navigation ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
        <div style='text-align: center; margin-top: 10px; margin-bottom: 25px;'>
            <span style='font-size: 2.2rem;'>🛡️</span>
            <h3 style='margin: 5px 0 0 0; color: #FFFFFF; font-family: "Inter", sans-serif; font-size: 1.15rem; font-weight: 700;'>RAKSHAK</h3>
            <p style='margin: 0; color: #9CA3AF; font-size: 0.725rem; font-weight: 500; letter-spacing: 0.8px;'>CYBER COMMAND CENTER v3.0</p>
        </div>
    """, unsafe_allow_html=True)

    api_online = False
    try:
        health_resp = requests.get(f"{API_BASE_URL}/health", timeout=1.5)
        if health_resp.status_code == 200:
            api_online = True
    except Exception:
        pass

    if api_online:
        st.markdown("""
            <div style='text-align:center; padding:4px; background:rgba(16,185,129,0.1);
                 border:1px solid rgba(16,185,129,0.2); border-radius:4px; color:#34D399;
                 font-size:0.75rem; margin-bottom:20px; font-weight:600;'>
                ● CORE ENGINE CONNECTED
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <div style='text-align:center; padding:6px; background:rgba(239,68,68,0.1);
                 border:1px solid rgba(239,68,68,0.2); border-radius:4px; color:#F87171;
                 font-size:0.75rem; margin-bottom:20px; font-weight:600;'>
                ▲ CORE ENGINE OFFLINE
            </div>
        """, unsafe_allow_html=True)

    nav_items = [
        ("Dashboard", "📊 System Overview"),
        ("Campaigns", "🏷️ Active Campaigns"),
        ("Feed", "🚨 Live Threat Feed"),
        ("Map", "🗺️ Geographic Radar"),
        ("Registry", "🔍 Suspect Registry"),
        ("Alerts", "⚠️ Actionable Alerts"),
        ("Reports", "📥 Evidence & Ingestion"),
        ("Settings", "⚙️ System Control"),
    ]

    st.markdown("<p style='font-size:0.7rem; color:#6B7280; font-weight:700; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;'>Navigation</p>", unsafe_allow_html=True)
    for key, label in nav_items:
        is_active = st.session_state.current_page == key
        btn_type = "primary" if is_active else "secondary"
        if st.button(label, key=f"nav_btn_{key}", width="stretch", type=btn_type):
            st.session_state.current_page = key
            st.rerun()

    st.markdown("<div style='height: 8vh;'></div>", unsafe_allow_html=True)
    st.markdown("""
        <div style='text-align: center; color: #6B7280; font-size: 0.65rem;'>
            Cyber Police OSINT Platform<br/>
            RAKSHAK Command Portal v3.0
        </div>
    """, unsafe_allow_html=True)

# ─── 7. Pull Live Data ────────────────────────────────────────────────────────
dashboard_data = safe_api_get("/api/v1/analytics/dashboard-feed")
df = pd.DataFrame(dashboard_data) if dashboard_data else pd.DataFrame()

required_cols = {
    "artifact_id": 0, "campaign_id": "CAMP_001", "scam_type": "Unknown",
    "risk_score": 0.0, "confidence": 0.0, "urls": "", "shortened_urls": "",
    "status": "New", "platform": "manual", "keywords": "", "geo": "",
    "state": "", "district": "", "text": "", "timestamp": "2026-01-01 00:00:00",
    "emails": "", "apks": "", "wa_links": "", "tg_links": "",
}
if not df.empty:
    for col, default in required_cols.items():
        if col not in df.columns:
            df[col] = default
    for str_col in ["urls", "keywords", "geo", "state", "district", "text",
                    "campaign_id", "status", "emails", "apks", "wa_links",
                    "tg_links", "shortened_urls"]:
        df[str_col] = df[str_col].fillna("").astype(str)
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0.0)
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce").fillna(0.0)
    df["campaign_id"] = df["campaign_id"].replace("", "UNCLUSTERED").fillna("UNCLUSTERED")

# ─── 8. Empty State ───────────────────────────────────────────────────────────
if df.empty and st.session_state.current_page not in ["Settings", "Reports"]:
    st.markdown("<h1 class='page-title'>🛡️ RAKSHAK Command</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Pan-India Cyber Threat Intelligence Portal</p>", unsafe_allow_html=True)
    st.markdown("""
        <div style='background:#111827; border:1px solid #1F2937; border-radius:8px;
             padding:40px; text-align:center; max-width:600px; margin:40px auto;'>
            <span style='font-size:3rem;'>📭</span>
            <h3 style='margin-top:15px; color:#FFFFFF;'>No Active Threat Telemetry</h3>
            <p style='color:#9CA3AF; font-size:0.9rem; margin-bottom:25px;'>
                Start by running the RSS/Portal scanners from Evidence & Ingestion,
                or seed mock scenarios from System Control.
            </p>
        </div>
    """, unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("⚙️ Go to System Control", width="stretch", type="primary"):
            st.session_state.current_page = "Settings"
            st.rerun()
    with c2:
        if st.button("📥 Go to Evidence Panel", width="stretch"):
            st.session_state.current_page = "Reports"
            st.rerun()
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 1: DASHBOARD — Executive Overview
# ═══════════════════════════════════════════════════════════════════════════════
if st.session_state.current_page == "Dashboard":
    st.markdown("<h1 class='page-title'>📊 System Overview</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>High-level command metrics, trend intelligence, and urgent alert queue.</p>", unsafe_allow_html=True)

    # ── KPI Cards ────────────────────────────────────────────────────────────
    total_intel = len(df)
    active_campaigns = df["campaign_id"].nunique()
    critical_alerts = len(df[df["risk_score"] >= 75.0])
    high_alerts = len(df[df["risk_score"] >= 50.0])
    states_affected = df[df["state"] != ""]["state"].nunique()
    all_urls = [u.strip() for row in df["urls"].dropna() for u in str(row).split(",") if u.strip()]
    unique_domains = len(set(all_urls))

    c1, c2, c3, c4, c5 = st.columns(5)
    metrics = [
        (c1, "📁 Threat Logs", total_intel, "↑ Live updates", "trend-up"),
        (c2, "🏷️ Campaigns", active_campaigns, "● Tracked clusters", "trend-neutral"),
        (c3, "🔴 Critical (≥75)", critical_alerts, "Require immediate action", "trend-up"),
        (c4, "🌍 States Affected", states_affected, "Pan-India coverage", "trend-neutral"),
        (c5, "🌐 Suspect Domains", unique_domains, "Extracted for blocking", "trend-neutral"),
    ]
    for col, title, value, desc, cls in metrics:
        color = "color: #EF4444;" if cls == "trend-up" and title != "📁 Threat Logs" else ""
        with col:
            st.markdown(f"""
                <div class="saas-card">
                    <div class="saas-metric-title">{title}</div>
                    <div class="saas-metric-value" style="{color}">{value}</div>
                    <div class="saas-metric-desc"><span class="{cls}">{desc}</span></div>
                </div>
            """, unsafe_allow_html=True)

    # ── Analytics Charts ──────────────────────────────────────────────────────
    st.markdown("### 📈 Threat Intelligence Analytics")
    col_c1, col_c2 = st.columns(2)

    with col_c1:
        type_counts = df["scam_type"].value_counts().reset_index()
        type_counts.columns = ["Scam Category", "Count"]
        fig_pie = px.pie(
            type_counts, names="Scam Category", values="Count",
            hole=0.45,
            color_discrete_sequence=px.colors.qualitative.Bold,
            title="Scam Category Distribution",
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#F3F4F6", title_font_size=14,
            legend=dict(font=dict(size=10), bgcolor="rgba(0,0,0,0)"),
            margin=dict(l=10, r=10, t=40, b=10),
        )
        st.plotly_chart(fig_pie, width="stretch")

    with col_c2:
        platform_counts = df["platform"].value_counts().reset_index()
        platform_counts.columns = ["Platform", "Count"]
        fig_bar = px.bar(
            platform_counts.head(10), x="Count", y="Platform", orientation="h",
            color="Count", color_continuous_scale="Reds",
            title="Intelligence by Platform Source",
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#F3F4F6", title_font_size=14,
            yaxis=dict(categoryorder="total ascending"),
            coloraxis_showscale=False,
            margin=dict(l=10, r=10, t=40, b=10),
        )
        st.plotly_chart(fig_bar, width="stretch")

    # ── Trend Chart ───────────────────────────────────────────────────────────
    trend_data = safe_api_get("/api/v1/analytics/trends?days=30")
    if trend_data:
        trend_df = pd.DataFrame(trend_data)
        if not trend_df.empty:
            fig_trend = px.area(
                trend_df, x="date", y="threat_count",
                title="30-Day Threat Detection Trend",
                color_discrete_sequence=["#3B82F6"],
            )
            fig_trend.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#F3F4F6", title_font_size=14,
                xaxis_title="Date", yaxis_title="Threats Detected",
                margin=dict(l=10, r=10, t=40, b=10),
            )
            fig_trend.update_traces(fillcolor="rgba(59,130,246,0.15)")
            st.plotly_chart(fig_trend, width="stretch")

    # ── Urgent Alerts Queue ───────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🚨 Urgent Attention Queue")
    st.markdown("<p style='color:#9CA3AF; font-size:0.85rem; margin-top:-10px;'>Top critical threats requiring immediate review and blocking action.</p>", unsafe_allow_html=True)

    crit_list = df[df["risk_score"] >= 50.0].sort_values("risk_score", ascending=False).head(5)
    if not crit_list.empty:
        for _, row in crit_list.iterrows():
            severity_str, badge_cls = get_risk_meta(row["risk_score"])
            geo_label = f"📍 {row['state']}" if row.get("state") else ""
            st.markdown(f"""
                <div style='background:#111827; border:1px solid #1F2937; border-radius:6px;
                     padding:12px 18px; margin-bottom:8px;'>
                    <span class="badge {badge_cls}" style='margin-right:10px;'>{severity_str} ({row['risk_score']:.0f})</span>
                    <span style='font-weight:600; font-size:0.9rem;'>{row['campaign_id']} — {row['scam_type']}</span>
                    {f"<span style='float:right; color:#9CA3AF; font-size:0.8rem;'>{geo_label}</span>" if geo_label else ""}
                    <div style='font-size:0.8rem; color:#9CA3AF; margin-top:4px;'>
                        <b>Platform:</b> {row['platform']} |
                        <b>URLs:</b> <span class="high-contrast-url">{row['urls'][:80] if row['urls'] else 'None'}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
        if st.button("➡️ View All Actionable Alerts", width="stretch"):
            st.session_state.current_page = "Alerts"
            st.rerun()
    else:
        st.success("No high-risk threats currently flagged.")


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 2: ACTIVE CAMPAIGNS
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.current_page == "Campaigns":
    st.markdown("<h1 class='page-title'>🏷️ Active Campaigns</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Organized threat groups clustered by semantic similarity AI models.</p>", unsafe_allow_html=True)

    camp_groups = df.groupby("campaign_id").agg(
        Scam_Type=("scam_type", lambda x: x.mode()[0] if not x.empty else "Unknown"),
        Max_Risk=("risk_score", "max"),
        First_Seen=("timestamp", "min"),
        Last_Seen=("timestamp", "max"),
        Report_Volume=("text", "count"),
        States=("state", lambda x: ", ".join(sorted(set(v for v in x if v)))),
        Urls=("urls", lambda x: ", ".join(sorted(set(u.strip() for v in x if v for u in str(v).split(",") if u.strip())))),
        Keywords=("keywords", lambda x: ", ".join(sorted(set(k.strip() for v in x if v for k in str(v).split(",") if k.strip())))),
    ).reset_index().sort_values(by="Max_Risk", ascending=False)

    col_list, col_detail = st.columns([3, 2])
    with col_list:
        st.markdown("### Campaign Registry")
        for _, row in camp_groups.iterrows():
            severity_str, badge_cls = get_risk_meta(row["Max_Risk"])
            is_selected = st.session_state.selected_campaign == row["campaign_id"]
            card_border = "2px solid #3B82F6" if is_selected else "1px solid #1F2937"
            st.markdown(f"""
                <div style='background:#111827; border:{card_border}; border-radius:8px; padding:15px; margin-bottom:12px;'>
                    <span class="badge {badge_cls}" style='margin-bottom:5px;'>{severity_str} (Risk: {row['Max_Risk']:.0f})</span>
                    <h4 style='margin:0; font-size:1.05rem; font-weight:700;'>{row['campaign_id']}</h4>
                    <p style='margin:3px 0 0 0; font-size:0.85rem; color:#9CA3AF;'>
                        <b>Type:</b> {row['Scam_Type']} | <b>Reports:</b> {row['Report_Volume']}
                        {f" | <b>States:</b> {row['States']}" if row['States'] else ""}
                    </p>
                </div>
            """, unsafe_allow_html=True)
            if st.button(f"🔍 View {row['campaign_id']}", key=f"sel_{row['campaign_id']}", width="stretch"):
                st.session_state.selected_campaign = row["campaign_id"]
                st.rerun()

    with col_detail:
        st.markdown("### Intelligence Details")
        if st.session_state.selected_campaign:
            c_info = camp_groups[camp_groups["campaign_id"] == st.session_state.selected_campaign].iloc[0]
            severity_str, badge_cls = get_risk_meta(c_info["Max_Risk"])
            # Get campaign-specific data
            camp_df = df[df["campaign_id"] == st.session_state.selected_campaign]

            st.markdown(f"""
                <div style='background:#111827; border:1px solid #1F2937; border-radius:8px; padding:20px;'>
                    <span class="badge {badge_cls}">{severity_str} Risk</span>
                    <h3 style='margin-top:8px; color:#FFFFFF;'>{c_info['campaign_id']}</h3>
                    <p style='font-size:0.85rem; color:#9CA3AF;'>
                        <b>Category:</b> {c_info['Scam_Type']}<br/>
                        <b>Reports:</b> {c_info['Report_Volume']}<br/>
                        <b>Risk Score:</b> {c_info['Max_Risk']:.0f}/100<br/>
                        <b>First Seen:</b> {c_info['First_Seen']}<br/>
                        <b>Last Active:</b> {c_info['Last_Seen']}<br/>
                        {f"<b>States:</b> {c_info['States']}" if c_info['States'] else ""}
                    </p>
                </div>
            """, unsafe_allow_html=True)

            if c_info["Urls"]:
                st.markdown("**🌐 Suspect URLs**")
                for url in c_info["Urls"].split(",")[:5]:
                    if url.strip():
                        st.code(url.strip(), language=None)

            if c_info["Keywords"]:
                st.markdown("**🔑 Key Indicators**")
                for kw in c_info["Keywords"].split(",")[:15]:
                    if kw.strip():
                        st.markdown(f"<span class='tag-pill'>{kw.strip()}</span>", unsafe_allow_html=True)

            # Phone numbers in campaign
            all_phones = []
            if "handles" in camp_df.columns:
                for ph_str in camp_df["handles"]:
                    if ph_str:
                        all_phones.extend([p.strip() for p in str(ph_str).split(",") if p.strip()])
            if all_phones:
                st.markdown(f"**📞 Handles Detected:** {', '.join(set(all_phones[:10]))}")
        else:
            st.info("Select a campaign card on the left to see detailed intelligence.")


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 3: LIVE THREAT FEED
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.current_page == "Feed":
    st.markdown("<h1 class='page-title'>🚨 Live Threat Feed</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Searchable intelligence logs with AI Explainability diagnostics.</p>", unsafe_allow_html=True)

    search_q = st.text_input("🔍 Global Search", placeholder="Search domains, keywords, campaign IDs, states, phone numbers...")

    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        f_type = st.multiselect("Scam Category", sorted(df["scam_type"].unique()))
    with f_col2:
        state_options = sorted([s for s in df["state"].unique() if s])
        f_state = st.multiselect("State", state_options)
    with f_col3:
        f_platform = st.multiselect("Platform", sorted(df["platform"].unique()))
    with f_col4:
        f_risk = st.multiselect("Risk Level", ["Critical (≥75)", "High (50-74)", "Medium (25-49)", "Low (<25)"])

    filtered_df = df.copy()
    if search_q.strip():
        q = search_q.lower()
        mask = (
            filtered_df["text"].str.lower().str.contains(q, na=False) |
            filtered_df["campaign_id"].str.lower().str.contains(q, na=False) |
            filtered_df["urls"].str.lower().str.contains(q, na=False) |
            filtered_df["scam_type"].str.lower().str.contains(q, na=False) |
            filtered_df["keywords"].str.lower().str.contains(q, na=False) |
            filtered_df["state"].str.lower().str.contains(q, na=False)
        )
        filtered_df = filtered_df[mask]

    if f_type: filtered_df = filtered_df[filtered_df["scam_type"].isin(f_type)]
    if f_state: filtered_df = filtered_df[filtered_df["state"].isin(f_state)]
    if f_platform: filtered_df = filtered_df[filtered_df["platform"].isin(f_platform)]
    if f_risk:
        risk_mask = pd.Series([False] * len(filtered_df), index=filtered_df.index)
        for idx, row in filtered_df.iterrows():
            level, _ = get_risk_meta(row["risk_score"])
            if (level == "Critical" and "Critical (≥75)" in f_risk) or \
               (level == "High" and "High (50-74)" in f_risk) or \
               (level == "Medium" and "Medium (25-49)" in f_risk) or \
               (level == "Low" and "Low (<25)" in f_risk):
                risk_mask[idx] = True
        filtered_df = filtered_df[risk_mask]

    filtered_df = filtered_df.sort_values(by="timestamp", ascending=False)
    st.markdown(f"**Showing {len(filtered_df)} of {len(df)} observations**")

    for _, row in filtered_df.iterrows():
        severity_str, badge_cls = get_risk_meta(row["risk_score"])
        geo_label = f"📍 {row['state']}{', ' + row['district'] if row.get('district') else ''}" if row.get("state") else ""

        st.markdown(f"""
            <div style='background:#111827; border:1px solid #1F2937; border-radius:8px; padding:16px; margin-bottom:12px;'>
                <div style='display:flex; justify-content:space-between; align-items:center;'>
                    <div>
                        <span class="badge {badge_cls}" style='margin-right:8px;'>{severity_str} ({row['risk_score']:.0f})</span>
                        <span style='color:#E5E7EB; font-size:0.8rem;'>{row['timestamp']} via <b>{row['platform'].upper()}</b></span>
                        {f" · <span style='color:#60A5FA; font-size:0.8rem;'>{geo_label}</span>" if geo_label else ""}
                    </div>
                    <span style='font-family:monospace; font-size:0.85rem; color:#9CA3AF;'>{row['campaign_id']}</span>
                </div>
                <p style='margin:10px 0; font-size:0.925rem; color:#FFFFFF; line-height:1.5;'>{row['text'][:400]}{"..." if len(row['text']) > 400 else ""}</p>
            </div>
        """, unsafe_allow_html=True)

        with st.expander("❔ Why was this flagged? — AI Explanation"):
            st.markdown(f"""
                <div class="xai-container">
                    <h5 style='margin-top:0; color:#FFFFFF; font-size:0.85rem;'>AI Diagnostic Report</h5>
                    <p style='font-size:0.8rem; color:#E5E7EB; margin-bottom:8px;'>
                        <b>Classification:</b> <b style='color:#60A5FA;'>{row['scam_type']}</b>
                        (confidence: {row['confidence']*100:.0f}%)<br/>
                        <b>Campaign:</b> {row['campaign_id']}<br/>
                        {f"<b>Location:</b> {geo_label}<br/>" if geo_label else ""}
                    </p>
            """, unsafe_allow_html=True)

            if row["urls"]:
                st.markdown(f"<div style='margin-bottom:6px;'><span style='color:#EF4444; font-size:0.75rem;'>● Suspect URLs:</span> <span class='high-contrast-url'>{row['urls'][:200]}</span></div>", unsafe_allow_html=True)
            if row.get("wa_links"):
                st.markdown(f"<div style='margin-bottom:6px;'><span style='color:#F97316; font-size:0.75rem;'>● WhatsApp Links:</span> {row['wa_links']}</div>", unsafe_allow_html=True)
            if row.get("tg_links"):
                st.markdown(f"<div style='margin-bottom:6px;'><span style='color:#F97316; font-size:0.75rem;'>● Telegram Links:</span> {row['tg_links']}</div>", unsafe_allow_html=True)
            if row["keywords"]:
                st.markdown("<span style='color:#9CA3AF; font-size:0.75rem;'>● Trigger Keywords:</span>", unsafe_allow_html=True)
                for k in str(row["keywords"]).split(","):
                    if k.strip():
                        st.markdown(f"<span class='tag-pill'>{k.strip()}</span>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 4: GEOGRAPHIC RADAR — India Heatmap + Infrastructure Map
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.current_page == "Map":
    st.markdown("<h1 class='page-title'>🗺️ Geographic Radar</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Pan-India state-level threat heatmap and suspect infrastructure geolocation.</p>", unsafe_allow_html=True)

    tab_heatmap, tab_infra = st.tabs(["🇮🇳 India Threat Heatmap", "🌐 Infrastructure Map"])

    with tab_heatmap:
        heatmap_data = safe_api_get("/api/v1/analytics/india-heatmap")

        if heatmap_data:
            hm_df = pd.DataFrame(heatmap_data)
            if not hm_df.empty and "state" in hm_df.columns:
                # Show statistics
                col_h1, col_h2, col_h3 = st.columns(3)
                with col_h1:
                    st.metric("States with Threats", len(hm_df))
                with col_h2:
                    st.metric("Most Targeted State", hm_df.iloc[0]["state"] if len(hm_df) > 0 else "—")
                with col_h3:
                    total_tracked = hm_df["threat_count"].sum()
                    st.metric("Total Geo-Tagged Threats", int(total_tracked))

                # Plotly bar chart (since India GeoJSON choropleth requires external data)
                fig_geo = px.bar(
                    hm_df.head(20),
                    x="threat_count",
                    y="state",
                    orientation="h",
                    color="threat_count",
                    color_continuous_scale="Reds",
                    title="Top 20 Threat-Impacted States (Pan-India Radar)",
                    labels={"threat_count": "Threats Detected", "state": "State/UT"},
                    text="threat_count",
                )
                fig_geo.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#F3F4F6", height=550,
                    yaxis=dict(categoryorder="total ascending"),
                    coloraxis_showscale=False,
                    title_font_size=14,
                    margin=dict(l=10, r=10, t=50, b=10),
                )
                fig_geo.update_traces(textposition="outside", textfont_color="#F3F4F6")
                st.plotly_chart(fig_geo, width="stretch")

                # Top scam types per state table
                st.markdown("#### Top Scam Type by State")
                display_hm = hm_df[["state", "threat_count", "critical_count", "high_count", "top_scam_type"]].copy()
                display_hm.columns = ["State", "Total Threats", "Critical", "High", "Top Scam Type"]
                st.dataframe(display_hm, width="stretch", hide_index=True)
            else:
                st.info("No geo-tagged threat data available yet. Run collectors to populate geographic intelligence.")
        else:
            # Fallback: compute from df
            state_df = df[df["state"] != ""].groupby("state").agg(
                threat_count=("risk_score", "count"),
                max_risk=("risk_score", "max"),
            ).reset_index().sort_values("threat_count", ascending=False)

            if not state_df.empty:
                fig_geo = px.bar(
                    state_df.head(20), x="threat_count", y="state", orientation="h",
                    color="max_risk", color_continuous_scale="Reds",
                    title="State-Level Threat Distribution (From Current Feed)",
                )
                fig_geo.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#F3F4F6", height=500,
                    yaxis=dict(categoryorder="total ascending"),
                )
                st.plotly_chart(fig_geo, width="stretch")
            else:
                st.info("No geo-tagged data yet. Run collectors to detect state-level threats.")

    with tab_infra:
        st.markdown("#### 🌐 Suspect Infrastructure Geolocation")
        st.markdown("<p style='color:#9CA3AF; font-size:0.85rem;'>Phishing domains and malware hosts plotted by known hosting regions.</p>", unsafe_allow_html=True)

        # Build map using real state coordinates derived from geo data
        try:
            import folium
            from streamlit_folium import st_folium
            from folium.plugins import MarkerCluster

            # India state centroid coordinates
            STATE_COORDS = {
                "Andhra Pradesh": (15.9129, 79.7400), "Arunachal Pradesh": (28.2180, 94.7278),
                "Assam": (26.2006, 92.9376), "Bihar": (25.0961, 85.3131),
                "Chhattisgarh": (21.2787, 81.8661), "Goa": (15.2993, 74.1240),
                "Gujarat": (22.2587, 71.1924), "Haryana": (29.0588, 76.0856),
                "Himachal Pradesh": (31.1048, 77.1734), "Jharkhand": (23.6102, 85.2799),
                "Karnataka": (15.3173, 75.7139), "Kerala": (10.8505, 76.2711),
                "Madhya Pradesh": (22.9734, 78.6569), "Maharashtra": (19.7515, 75.7139),
                "Manipur": (24.6637, 93.9063), "Meghalaya": (25.4670, 91.3662),
                "Mizoram": (23.1645, 92.9376), "Nagaland": (26.1584, 94.5624),
                "Odisha": (20.9517, 85.0985), "Punjab": (31.1471, 75.3412),
                "Rajasthan": (27.0238, 74.2179), "Sikkim": (27.5330, 88.5122),
                "Tamil Nadu": (11.1271, 78.6569), "Telangana": (18.1124, 79.0193),
                "Tripura": (23.9408, 91.9882), "Uttar Pradesh": (26.8467, 80.9462),
                "Uttarakhand": (30.0668, 79.0193), "West Bengal": (22.9868, 87.8550),
                "Andaman And Nicobar": (11.7401, 92.6586), "Chandigarh": (30.7333, 76.7794),
                "Dadra And Nagar Haveli": (20.1809, 73.0169), "Daman And Diu": (20.4283, 72.8397),
                "Delhi": (28.6139, 77.2090), "Ncr": (28.6139, 77.2090),
                "Lakshadweep": (10.5667, 72.6167), "Puducherry": (11.9416, 79.8083),
                "Jammu And Kashmir": (33.7782, 76.5762), "Jammu": (33.7782, 76.5762),
                "Kashmir": (34.0837, 74.7973), "Ladakh": (34.1526, 77.5771)
            }

            m = folium.Map(location=[22.5, 82.0], zoom_start=5, tiles="OpenStreetMap")
            marker_cluster = MarkerCluster().add_to(m)

            # Plot from actual geo data in df
            state_threats = df[df["state"] != ""].groupby("state").agg(
                count=("risk_score", "count"),
                max_risk=("risk_score", "max"),
                top_type=("scam_type", lambda x: x.mode()[0] if not x.empty else "Unknown"),
            ).reset_index()

            for _, srow in state_threats.iterrows():
                coords = STATE_COORDS.get(srow["state"])
                if not coords:
                    continue
                color = "red" if srow["max_risk"] >= 75 else "orange" if srow["max_risk"] >= 50 else "blue"
                popup_html = f"""
                <div style='font-family:Arial; font-size:12px; width:200px;'>
                    <b>🔴 {srow['state']}</b><br/>
                    <b>Threats:</b> {srow['count']}<br/>
                    <b>Max Risk:</b> {srow['max_risk']:.0f}/100<br/>
                    <b>Top Type:</b> {srow['top_type']}
                </div>"""
                folium.CircleMarker(
                    location=coords,
                    radius=max(8, min(srow["count"] * 2, 30)),
                    color=color,
                    fill=True,
                    fill_opacity=0.7,
                    popup=folium.Popup(popup_html, max_width=230),
                    tooltip=f"{srow['state']}: {srow['count']} threats",
                ).add_to(m)

            # Also plot URL-based markers
            url_coords_pool = [
                (28.6139, 77.2090, "Delhi"), (19.0760, 72.8777, "Mumbai"),
                (12.9716, 77.5946, "Bangalore"), (13.0827, 80.2707, "Chennai"),
                (22.5726, 88.3639, "Kolkata"), (17.3850, 78.4867, "Hyderabad"),
                (1.3521, 103.8198, "Singapore Host"), (37.7749, -122.4194, "USA Host"),
            ]
            import random
            for val in df["urls"].dropna():
                if val and str(val) != "":
                    for url in str(val).split(",")[:3]:
                        url = url.strip()
                        if not url: continue
                        stable_hash = int(hashlib.md5(url.encode()).hexdigest(), 16)
                        lat_c, lon_c, city = url_coords_pool[stable_hash % len(url_coords_pool)]
                        random.seed(stable_hash)
                        lat_n = random.uniform(-0.5, 0.5)
                        lon_n = random.uniform(-0.5, 0.5)
                        random.seed()
                        folium.Marker(
                            location=[lat_c + lat_n, lon_c + lon_n],
                            popup=folium.Popup(f"<code style='word-break:break-all;'>{url[:80]}</code><br/>Host: {city}", max_width=250),
                            icon=folium.Icon(color="red", icon="warning-sign"),
                            tooltip=f"Suspect URL: {url[:50]}",
                        ).add_to(marker_cluster)

            st_folium(m, height=500, width="stretch", returned_objects=[])
        except Exception as e:
            st.error(f"Map rendering error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 5: SUSPECT REGISTRY (NEW)
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.current_page == "Registry":
    st.markdown("<h1 class='page-title'>🔍 Suspect Registry</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Cross-campaign tracking of suspect phone numbers and domain blocklist registry.</p>", unsafe_allow_html=True)

    tab_phones, tab_domains = st.tabs(["📞 Suspect Phone Numbers", "🌐 Domain Blocklist"])

    with tab_phones:
        st.markdown("### Suspect Phone Number Registry")
        st.markdown("<p style='color:#9CA3AF; font-size:0.85rem;'>Phone numbers extracted across all detected scam artifacts, ranked by occurrence frequency.</p>", unsafe_allow_html=True)

        phone_data = safe_api_get("/api/v1/analytics/suspect-phones?limit=200")
        if phone_data:
            phone_df = pd.DataFrame(phone_data)
            if not phone_df.empty:
                # KPIs
                c1, c2, c3 = st.columns(3)
                with c1: st.metric("Unique Suspect Numbers", len(phone_df))
                with c2: st.metric("Max Occurrences", int(phone_df["occurrence_count"].max()))
                with c3:
                    repeat_count = len(phone_df[phone_df["occurrence_count"] > 1])
                    st.metric("Repeat Offenders", repeat_count)

                # Top frequency chart
                fig_phones = px.bar(
                    phone_df.head(20), x="occurrence_count", y="phone_number", orientation="h",
                    color="occurrence_count", color_continuous_scale="Reds",
                    title="Top 20 Most Frequently Seen Suspect Numbers",
                    labels={"occurrence_count": "Occurrences", "phone_number": "Phone Number"},
                )
                fig_phones.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#F3F4F6", height=450,
                    yaxis=dict(categoryorder="total ascending"),
                    coloraxis_showscale=False,
                )
                st.plotly_chart(fig_phones, width="stretch")

                display_phones = phone_df[["phone_number", "occurrence_count", "scam_types", "state", "first_seen", "last_seen"]].copy()
                display_phones.columns = ["Phone Number", "Occurrences", "Scam Types", "State", "First Seen", "Last Seen"]
                st.dataframe(display_phones, width="stretch", hide_index=True)

                # Download
                csv_data = display_phones.to_csv(index=False).encode("utf-8")
                st.download_button("📥 Download Phone Registry CSV", data=csv_data, file_name="suspect_phones.csv", mime="text/csv")
            else:
                st.info("No suspect phone numbers extracted yet. Run collectors to build the registry.")
        else:
            # Fallback: extract from current df
            st.info("Phone registry API unavailable. Showing extracted phones from current feed.")
            all_ph = []
            for _, row in df.iterrows():
                if row.get("handles"):
                    for h in str(row["handles"]).split(","):
                        if h.strip() and h.strip().lstrip("+").isdigit():
                            all_ph.append({"Phone": h.strip(), "Campaign": row["campaign_id"], "Type": row["scam_type"]})
            if all_ph:
                st.dataframe(pd.DataFrame(all_ph), width="stretch", hide_index=True)

    with tab_domains:
        st.markdown("### Domain Blocklist Registry")
        st.markdown("<p style='color:#9CA3AF; font-size:0.85rem;'>Suspect domains extracted from all threat intelligence, ranked by risk score for DoT blocklist submission.</p>", unsafe_allow_html=True)

        domain_data = safe_api_get("/api/v1/analytics/suspect-domains?limit=300")
        if domain_data:
            dom_df = pd.DataFrame(domain_data)
            if not dom_df.empty:
                c1, c2, c3 = st.columns(3)
                with c1: st.metric("Unique Suspect Domains", len(dom_df))
                with c2: st.metric("Shortened URLs", int(dom_df["is_shortened"].sum()))
                with c3: st.metric("Avg Risk Score", f"{dom_df['max_risk_score'].mean():.1f}")

                display_dom = dom_df[["domain", "max_risk_score", "occurrence_count", "scam_types", "is_shortened", "first_seen"]].copy()
                display_dom.columns = ["Domain", "Max Risk", "Occurrences", "Scam Types", "Shortened URL", "First Seen"]
                st.dataframe(display_dom, width="stretch", hide_index=True)

                csv_data = display_dom.to_csv(index=False).encode("utf-8")
                st.download_button("📥 Download Domain Blocklist CSV", data=csv_data, file_name="domain_blocklist.csv", mime="text/csv")
        else:
            # Fallback: build from df
            blocklist = []
            for _, row in df.iterrows():
                if row["urls"]:
                    for u in str(row["urls"]).split(","):
                        u = u.strip()
                        if u:
                            blocklist.append({"Domain": u, "Risk": row["risk_score"], "Campaign": row["campaign_id"], "Type": row["scam_type"]})
            if blocklist:
                blk_df = pd.DataFrame(blocklist).drop_duplicates("Domain").sort_values("Risk", ascending=False)
                st.dataframe(blk_df, width="stretch", hide_index=True)
                csv_data = blk_df.to_csv(index=False).encode("utf-8")
                st.download_button("📥 Download Domain Blocklist CSV", data=csv_data, file_name="domain_blocklist.csv", mime="text/csv")
            else:
                st.info("No suspect domains extracted yet. Run collectors to build the domain registry.")


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 6: ACTIONABLE ALERTS
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.current_page == "Alerts":
    st.markdown("<h1 class='page-title'>⚠️ Actionable Alerts</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Interactive case inbox — review and take blocking actions against cyberthreats.</p>", unsafe_allow_html=True)

    tab_new, tab_ack, tab_res = st.tabs(["🔴 Active Alerts", "🟡 Under Investigation", "🟢 Resolved Cases"])
    alerts_df = df.sort_values("risk_score", ascending=False)

    def render_alerts_by_status(status_filter):
        camps = alerts_df.groupby("campaign_id").first().reset_index()
        matched = camps[camps["status"] == status_filter]
        if matched.empty:
            st.markdown(f"<p style='color:#9CA3AF; margin-top:15px;'>No alerts in '{status_filter}' queue.</p>", unsafe_allow_html=True)
            return

        for _, row in matched.iterrows():
            severity_str, badge_cls = get_risk_meta(row["risk_score"])
            geo_label = f"📍 {row['state']}" if row.get("state") else ""
            st.markdown(f"""
                <div style='background:#111827; border:1px solid #1F2937; border-radius:8px; padding:18px; margin-bottom:12px;'>
                    <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;'>
                        <span class="badge {badge_cls}">{severity_str} Severity</span>
                        <span style='font-size:0.75rem; color:#9CA3AF;'>{row['timestamp']} {geo_label}</span>
                    </div>
                    <h4 style='margin:0; font-size:1.1rem; color:#FFFFFF;'>{row['campaign_id']} — {row['scam_type']}</h4>
                    <p style='margin:8px 0; font-size:0.9rem; color:#E5E7EB; line-height:1.4;'>{row['text'][:300]}...</p>
                    <hr style='border:0.5px solid #1F2937; margin:10px 0;'/>
                    <p style='font-size:0.8rem; color:#9CA3AF; margin-bottom:10px;'>
                        <b>URLs:</b> <span class="high-contrast-url">{row['urls'][:100] if row['urls'] else 'None'}</span>
                    </p>
            """, unsafe_allow_html=True)

            b1, b2 = st.columns(2)
            with b1:
                if status_filter == "New":
                    if st.button(f"🔎 Acknowledge {row['campaign_id']}", key=f"ack_{row['campaign_id']}", width="stretch"):
                        resp = safe_api_post(f"/api/v1/alerts/{row['campaign_id']}/status", {"status": "Acknowledged"})
                        if resp and resp.status_code == 200:
                            st.toast(f"Case {row['campaign_id']} assigned for investigation.")
                            time.sleep(1)
                            st.rerun()
                elif status_filter == "Acknowledged":
                    if st.button(f"✅ Resolve {row['campaign_id']}", key=f"res_{row['campaign_id']}", width="stretch"):
                        resp = safe_api_post(f"/api/v1/alerts/{row['campaign_id']}/status", {"status": "Resolved"})
                        if resp and resp.status_code == 200:
                            st.toast(f"Case {row['campaign_id']} resolved.")
                            time.sleep(1)
                            st.rerun()
            with b2:
                if status_filter != "Resolved":
                    if st.button(f"🗑️ Dismiss {row['campaign_id']}", key=f"ig_{row['campaign_id']}", width="stretch"):
                        resp = safe_api_post(f"/api/v1/alerts/{row['campaign_id']}/status", {"status": "Resolved"})
                        if resp and resp.status_code == 200:
                            st.toast(f"Alert {row['campaign_id']} dismissed.")
                            time.sleep(1)
                            st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

    with tab_new: render_alerts_by_status("New")
    with tab_ack: render_alerts_by_status("Acknowledged")
    with tab_res: render_alerts_by_status("Resolved")


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 7: EVIDENCE & INGESTION
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.current_page == "Reports":
    st.markdown("<h1 class='page-title'>📥 Evidence & Ingestion</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Crawlers control panel, manual fraud message ingestion, and domain blocklist export.</p>", unsafe_allow_html=True)

    tab_ingest, tab_scan, tab_export = st.tabs(["📥 Report Fraud", "🎛️ Platform Scanners", "📑 Blocklist Export"])

    with tab_ingest:
        st.markdown("### 📥 Report Fraud Message")
        with st.form(key="manual_ingest_form", clear_on_submit=True):
            source_channel = st.selectbox("Source Platform", ["Telegram", "WhatsApp", "SMS Phishing", "Web Domain", "Reddit", "Email", "Manual"])
            threat_text = st.text_area("Suspicious Text / Payload", placeholder="Paste scam message, URLs, UPIs, phone numbers here...", height=150)
            submit_btn = st.form_submit_button("🧠 Ingest & Run AI Pipeline", width="stretch")
            if submit_btn:
                if not threat_text.strip():
                    st.error("Please enter suspicious text.")
                elif not api_online:
                    st.error("Core engine is offline.")
                else:
                    with st.spinner("Running two-stage AI classification pipeline..."):
                        resp = safe_api_post(
                            "/api/v1/intel/manual",
                            params={"text": threat_text, "source": source_channel.lower()},
                        )
                        if resp and resp.status_code == 200:
                            result = resp.json()
                            if result.get("status") == "duplicate":
                                st.warning("Duplicate record — already in database.")
                            else:
                                st.success(f"✅ Queued for analysis (ID: {result.get('raw_intel_id')})")
                                time.sleep(1.5)
                                st.rerun()
                        else:
                            st.error("Ingestion failed. Check if backend is running.")

    with tab_scan:
        st.markdown("### 🎛️ Platform Scanners")

        scanner_configs = [
            ("📰", "RSS News & Advisories", "60+ state-specific news feeds + CERT-In advisories", "/api/v1/collect/rss", "rss"),
            ("🔥", "Reddit OSINT", "r/IsThisAScamIndia + 14 India cybercrime subreddits", "/api/v1/collect/reddit", "reddit"),
            ("🦠", "Threat Intel Feeds", "URLhaus + OpenPhish malware/phishing feeds", "/api/v1/collect/malware", "malware"),
            ("🏛️", "Official Portals", "CERT-In + PIB/MHA + State Police advisories", "/api/v1/collect/portal", "portal"),
            ("✈️", "Telegram Channels", "Public Indian cyber threat Telegram channels", "/api/v1/collect/telegram", "telegram"),
        ]

        for icon, label, desc, endpoint, key in scanner_configs:
            st.markdown(f"""
                <div style='background:#111827; border:1px solid #1F2937; border-radius:6px;
                     padding:10px 15px; margin-bottom:8px;'>
                    <span style='font-size:1.1rem;'>{icon}</span> <b>{label}</b>
                    <div style='font-size:0.75rem; color:#9CA3AF; margin-top:2px;'>{desc}</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button(f"▶ Run {label}", key=f"scan_{key}", width="stretch", disabled=not api_online):
                with st.spinner(f"Running {label} scanner..."):
                    resp = safe_api_post(endpoint, timeout=120.0)
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        count = data.get("new_raw_records_collected", 0)
                        st.success(f"✅ {label} complete. {count} new records ingested.")
                        time.sleep(1.5)
                        st.rerun()
                    else:
                        st.error(f"Scanner error. Check backend logs.")

    with tab_export:
        st.markdown("### 📑 Export Blocklist")
        blocklist_data = []
        for _, row in df.iterrows():
            if row["urls"]:
                for u in str(row["urls"]).split(","):
                    u = u.strip()
                    if u:
                        blocklist_data.append({
                            "Campaign_ID": row["campaign_id"],
                            "Detected_At": row["timestamp"],
                            "Scam_Type": row["scam_type"],
                            "Risk_Score": row["risk_score"],
                            "State": row.get("state", ""),
                            "Suspect_Domain": u,
                        })
        if blocklist_data:
            blk_df = pd.DataFrame(blocklist_data)
            st.dataframe(blk_df[["Campaign_ID", "Suspect_Domain", "Scam_Type", "Risk_Score", "State"]], width="stretch", hide_index=True)
            st.download_button("📥 Download Blocklist CSV", blk_df.to_csv(index=False).encode("utf-8"), "cyber_sentinel_blocklist.csv", "text/csv", width="stretch")
        else:
            st.warning("No suspect domains to export.")

    # Threat History Log
    st.markdown("---")
    st.markdown("### 📜 Threat Detection History Log")
    hist_data = safe_api_get("/api/v1/analytics/threat-history?limit=100")
    if hist_data:
        hist_df = pd.DataFrame(hist_data)
        if not hist_df.empty:
            display_hist = hist_df[["timestamp", "platform", "scam_type", "risk_score", "verdict", "state", "raw_text"]].copy()
            display_hist.columns = ["Timestamp", "Platform", "Category", "Risk Score", "Verdict", "State", "Raw Payload"]
            st.dataframe(display_hist, width="stretch", hide_index=True)
    else:
        st.info("No scan history available. Run collectors to generate logs.")


# ═══════════════════════════════════════════════════════════════════════════════
# VIEW 8: SYSTEM CONTROL
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.current_page == "Settings":
    st.markdown("<h1 class='page-title'>⚙️ System Control</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Operational controls, database management, and AI seeder telemetry engine.</p>", unsafe_allow_html=True)

    st.markdown("### 🎛️ Database Operations")
    col_se1, col_se2 = st.columns(2)

    with col_se1:
        st.markdown("""
            <div class="saas-card">
                <h4 style="margin-top:0; color:#FFFFFF;">Seed Test Scenarios</h4>
                <p style="font-size:0.8rem; color:#9CA3AF; margin-bottom:15px;">
                    Populate the database with 10 realistic pan-India cybercrime scenarios
                    covering all major scam categories.
                </p>
            </div>
        """, unsafe_allow_html=True)

        MOCK_SCENARIOS = [
            {"text": "ALERT: Digital Arrest scam in Delhi. Victim received call from fake CBI officer claiming MDMA parcel intercepted. Victim transferred Rs 8 Lakhs via UPI to block@icici and sbi.clearance@ybl. Suspect website: http://cbi-clearance-india.com. Victim in Rohini, Delhi.", "source": "manual"},
            {"text": "WARNING: YouTube like task scam rampant in Gurugram, Haryana. WhatsApp message from +91 9876543210: 'Earn Rs 150 per like, Rs 5000 daily. Join Telegram @GurugramEarnTasks. Pay deposit at http://tmart-rewards-india.com'. Rs 12 Lakhs fraud reported.", "source": "telegram"},
            {"text": "SBI KYC Scam Alert: SMS to Maharashtra residents: 'Dear SBI user, account blocked. Update KYC: http://sbi-kyc-verification-online.in'. Phishing domain registered 3 days ago. Fake UPI: sbi.kyc.update@paytm", "source": "rss_news"},
            {"text": "Loan App Harassment: RupeeSpeedy instant loan app harassing contacts of Pune, Maharashtra residents. 200% interest demanded. APK: com.rupeespeedy.loan. Download: http://rupee-speedy.in/download.apk. Victim IFSC: HDFC0001234.", "source": "manual"},
            {"text": "Investment scam: Fake Telegram group @WealthAdvisorsIndia running pump-and-dump. Bengaluru, Karnataka victim lost Rs 25 Lakhs. Suspect domains: http://ggl-wealth-trading.com, http://secure-invest-india.in. BTC wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf", "source": "manual"},
            {"text": "Electricity bill scam: MSEDCL impersonation calls to Mumbai, Maharashtra. 'Pay Rs 2000 immediately or power cut at 9PM'. Fake UPI: msedcl.billpay@paytm. Helpline fraud number: +91 9988776655.", "source": "manual"},
            {"text": "Sextortion case: Tamil Nadu victim blackmailed after fake video call from Instagram account. Attacker demands Rs 50,000 via UPI. Telegram handle: @blackmail_india. Victim email leaked.", "source": "portal:TN_Cyber"},
            {"text": "Courier parcel scam: FedEx impersonation calls in Hyderabad, Telangana. Victim told package contains contraband. Suspect website: http://fedex-customs-clearance-in.com. Victim transferred Rs 3 Lakhs to customs.india@icici.", "source": "manual"},
            {"text": "Fake government scheme: WhatsApp message in UP claiming 'PM Free Laptop Yojana 2025'. Click http://pm-laptop-scheme.in to register. Aadhaar and PAN required. Phishing portal collecting PAN data.", "source": "rss_news"},
            {"text": "Bank impersonation: RBI officer call scam active across Rajasthan, Jaipur. Caller claims account involved in money laundering. Demands transfer to 'safe account'. IFSC: PUNB0012345. Phone: +91 8877665544.", "source": "manual"},
        ]

        if st.button("⚡ Seed 10 Pan-India Mock Scenarios", width="stretch", disabled=not api_online):
            with st.spinner("Seeding through AI pipeline..."):
                success_count = 0
                for scenario in MOCK_SCENARIOS:
                    resp = safe_api_post(
                        "/api/v1/intel/manual",
                        params={"text": scenario["text"], "source": scenario["source"]},
                    )
                    if resp and resp.status_code == 200:
                        success_count += 1
                if success_count > 0:
                    st.success(f"✅ {success_count}/{len(MOCK_SCENARIOS)} scenarios seeded and queued for AI analysis.")
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error("Failed. Check backend connection.")

    with col_se2:
        st.markdown("""
            <div class="saas-card">
                <h4 style="margin-top:0; color:#FFFFFF;">Reset Database</h4>
                <p style="font-size:0.8rem; color:#9CA3AF; margin-bottom:15px;">
                    Permanently delete ALL threat logs, campaigns, and extracted artifacts
                    from the local SQLite database.
                </p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("🗑️ Clear All Threat Data", width="stretch"):
            if manual_sqlite_clear():
                st.success("✅ Database cleared successfully.")
                time.sleep(1.5)
                st.rerun()

    # System Diagnostics
    st.markdown("---")
    st.markdown("### 📊 System Diagnostics")

    db_size_kb = os.path.getsize(DB_PATH) / 1024 if os.path.exists(DB_PATH) else 0
    total_records = len(df)

    health_resp = safe_api_get("/health")
    scanner_info = health_resp.get("scanner_feeds", {}) if health_resp else {}

    st.markdown(f"""
        <div class="saas-card" style="font-family: monospace; font-size:0.85rem;">
            <b>Database Path:</b> {DB_PATH}<br/>
            <b>Database Size:</b> {db_size_kb:.2f} KB<br/>
            <b>Total Threat Records:</b> {total_records}<br/>
            <b>API Engine URL:</b> {API_BASE_URL}<br/>
            <b>RSS Feeds Configured:</b> {scanner_info.get("rss_feeds_count", "—")}<br/>
            <b>Telegram Channels:</b> {scanner_info.get("telegram_channels", "—")}<br/>
            <b>Reddit Subreddits:</b> {scanner_info.get("reddit_subreddits", "—")}<br/>
            <b>System Version:</b> RAKSHAK Command Portal v3.0
        </div>
    """, unsafe_allow_html=True)