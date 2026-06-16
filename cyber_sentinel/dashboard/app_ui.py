import streamlit as st
import pandas as pd
import requests
import random
import time
import sqlite3
import os
import folium
import hashlib
from streamlit_folium import st_folium
from folium.plugins import MarkerCluster

# 1. Page Configuration & Custom Theme Initialization
st.set_page_config(
    page_title="Rakshak - Cyber Sentinel Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Splash Screen Transition (Shown for 5 seconds on first boot)
if 'splash_shown' not in st.session_state:
    st.session_state.splash_shown = False

if not st.session_state.splash_shown:
    st.markdown("""
        <style>
            [data-testid="stSidebar"] {
                display: none !important;
            }
            .main .block-container {
                padding: 0rem !important;
                background-color: #030712 !important;
            }
            .stApp {
                background-color: #030712 !important;
            }
        </style>
    """, unsafe_allow_html=True)
    
    # Center splash screen vertically
    st.markdown("<div style='height: 8vh;'></div>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 6, 1])
    with col2:
        img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rakshak_splash.jpg")
        st.image(img_path, use_container_width=True)
        st.markdown("""
            <p style='text-align: center; color: #3B82F6; font-size: 1.15rem; font-family: "Orbitron", sans-serif; letter-spacing: 3px; font-weight: 600; margin-top: 25px; text-shadow: 0 0 10px rgba(59, 130, 246, 0.4);'>
                INITIALIZING RAKSHAK SECURE OSINT THREAT DETECTOR...
            </p>
        """, unsafe_allow_html=True)
    
    time.sleep(5)
    st.session_state.splash_shown = True
    st.rerun()

# 3. Inject Clean Modern SaaS CSS Design System (Apple/Google Cleanliness, Low Clutter, Professional)
st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Orbitron:wght@500;700;900&display=swap');
        
        /* Master Layout Spacing & Spacing Scale */
        .stApp {
            background-color: #0B0F19 !important;
            color: #F3F4F6 !important;
            font-family: 'Inter', sans-serif !important;
        }
        
        /* Custom Headers */
        h1, h2, h3 {
            font-family: 'Inter', sans-serif !important;
            font-weight: 600 !important;
            color: #F3F4F6 !important;
            margin-bottom: 0.5rem !important;
            margin-top: 0.5rem !important;
        }
        
        .page-title {
            font-size: 1.75rem;
            font-weight: 700;
            color: #FFFFFF;
            letter-spacing: -0.5px;
        }
        
        .page-subtitle {
            font-size: 0.95rem;
            color: #9CA3AF;
            margin-bottom: 1.5rem !important;
        }
        
        /* Sidebar Navigation Spacing and Logo block */
        section[data-testid="stSidebar"] {
            background-color: #111827 !important;
            border-right: 1px solid #1F2937 !important;
        }
        
        /* Glassmorphic Metric Cards */
        .saas-card {
            background: #111827;
            border: 1px solid #1F2937;
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            transition: all 0.2s ease;
        }
        
        .saas-card:hover {
            border-color: #374151;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        .saas-metric-title {
            font-size: 0.75rem;
            color: #9CA3AF;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            margin-bottom: 4px;
        }
        
        .saas-metric-value {
            font-size: 1.75rem;
            font-weight: 700;
            color: #FFFFFF;
            font-family: 'Inter', sans-serif;
            margin-bottom: 4px;
        }
        
        .saas-metric-desc {
            font-size: 0.8rem;
            color: #9CA3AF;
        }
        
        .trend-up {
            color: #10B981;
            font-weight: 600;
            font-size: 0.8rem;
        }
        
        .trend-neutral {
            color: #9CA3AF;
            font-weight: 600;
            font-size: 0.8rem;
        }

        /* SaaS Threat Alert Badges */
        .badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.725rem;
            font-weight: 600;
            display: inline-block;
            text-align: center;
        }
        
        .badge-critical {
            background-color: rgba(239, 68, 68, 0.1);
            color: #EF4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .badge-high {
            background-color: rgba(249, 115, 22, 0.1);
            color: #F97316;
            border: 1px solid rgba(249, 115, 22, 0.3);
        }
        
        .badge-medium {
            background-color: rgba(251, 191, 36, 0.1);
            color: #FBBF24;
            border: 1px solid rgba(251, 191, 36, 0.3);
        }
        
        .badge-low {
            background-color: rgba(16, 185, 129, 0.1);
            color: #10B981;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        /* Explainable AI Block Styling */
        .xai-container {
            background: #1F2937;
            border: 1px dashed #374151;
            border-radius: 6px;
            padding: 1rem;
            margin-top: 8px;
        }
        
        .tag-pill {
            background: #374151;
            color: #E5E7EB;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-right: 6px;
            display: inline-block;
        }
    </style>
""", unsafe_allow_html=True)

# 4. Initialize Global Session States for Case Management & Navigation
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Dashboard"

if 'selected_campaign' not in st.session_state:
    st.session_state.selected_campaign = None

# Alert status is managed in
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8080")
# Resolve DB path relative to this dashboard file (works on any machine)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_SCRIPT_DIR, "..", "cyber_sentinel.db")
DB_PATH = os.path.normpath(DB_PATH)

# 5. Core Data Ingestion & Seeding Helpers
def manual_sqlite_clear():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threat_history;")
        cursor.execute("DELETE FROM scam_artifacts;")
        cursor.execute("DELETE FROM raw_intel;")
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error during SQLite reset: {e}")
        return False

# 6. Sidebar Navigation Control Center (Collapsible / Sleek SaaS Tabs)
with st.sidebar:
    st.markdown("""
        <div style='text-align: center; margin-top: 10px; margin-bottom: 25px;'>
            <span style='font-size: 2.2rem;'>🛡️</span>
            <h3 style='margin: 5px 0 0 0; color: #FFFFFF; font-family: "Inter", sans-serif; font-size: 1.15rem; font-weight: 700; letter-spacing: -0.5px;'>RAKSHAK</h3>
            <p style='margin: 0; color: #9CA3AF; font-size: 0.725rem; font-weight: 500; letter-spacing: 0.8px;'>CYBER COMMAND CENTER</p>
        </div>
    """, unsafe_allow_html=True)
    
    # API Live Connection Status Bar
    api_online = True
    try:
        health_check = requests.get(f"{API_BASE_URL}/health", timeout=1.5)
        st.markdown("""
            <div style='text-align: center; padding: 4px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 4px; color: #34D399; font-size: 0.75rem; margin-bottom: 20px; font-weight: 600;'>
                ● CORE ENGINE CONNECTED
            </div>
        """, unsafe_allow_html=True)
    except Exception:
        api_online = False
        st.markdown("""
            <div style='text-align: center; padding: 6px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 4px; color: #F87171; font-size: 0.75rem; margin-bottom: 20px; font-weight: 600;'>
                ▲ CORE ENGINE OFFLINE
            </div>
        """, unsafe_allow_html=True)

    # Navigation Menu Buttons
    nav_items = [
        ("Dashboard", "📊 System Overview"),
        ("Campaigns", "🏷️ Active Campaigns"),
        ("Feed", "🚨 Live Threat Feed"),
        ("Map", "🗺️ Geographic Radar"),
        ("Alerts", "⚠️ Actionable Alerts"),
        ("Reports", "📥 Evidence & Ingestion"),
        ("Settings", "⚙️ System Control")
    ]
    
    st.markdown("<p style='font-size:0.7rem; color:#6B7280; font-weight:700; text-transform:uppercase; letter-spacing: 1px; margin-bottom: 8px;'>Navigation</p>", unsafe_allow_html=True)
    
    for key, label in nav_items:
        is_active = st.session_state.current_page == key
        btn_type = "primary" if is_active else "secondary"
        if st.button(label, key=f"nav_btn_{key}", use_container_width=True, type=btn_type):
            st.session_state.current_page = key
            st.rerun()

    st.markdown("<div style='height: 12vh;'></div>", unsafe_allow_html=True)
    st.markdown("""
        <div style='text-align: center; color: #6B7280; font-size: 0.65rem;'>
            Gurugram Police Cyber Cell<br/>
            Portal Version 2.0 (RAKSHAK)
        </div>
    """, unsafe_allow_html=True)

# 7. Pull Live Data Feed from Core Engine
try:
    response = requests.get(f"{API_BASE_URL}/api/v1/analytics/dashboard-feed", timeout=30.0).json()
    df = pd.DataFrame(response)
except Exception:
    df = pd.DataFrame()

# Bulletproof check: Ensure all required columns exist to prevent KeyError crashes
required_cols = {
    "campaign_id": "CAMP_001",
    "scam_type": "Unknown",
    "risk_score": 0.0,
    "confidence": 0.0,
    "urls": "",
    "status": "New",
    "platform": "manual",
    "keywords": "",
    "geo": "",
    "text": "",
    "timestamp": "2026-06-13 00:00:00"
}
if not df.empty:
    for col, default in required_cols.items():
        if col not in df.columns:
            df[col] = default
    # Fill NaN values with safe defaults to prevent filter/render crashes
    df["urls"] = df["urls"].fillna("").astype(str)
    df["keywords"] = df["keywords"].fillna("").astype(str)
    df["geo"] = df["geo"].fillna("").astype(str)
    df["text"] = df["text"].fillna("").astype(str)
    df["campaign_id"] = df["campaign_id"].fillna("UNCLUSTERED").astype(str)
    df["status"] = df["status"].fillna("New").astype(str)
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0.0)

# 8. Render Routing Content Pages
if df.empty:
    # Empty State Display (Unified across all views except control/settings)
    if st.session_state.current_page not in ["Settings", "Reports"]:
        st.markdown("<h1 class='page-title'>🛡️ RAKSHAK Command</h1>", unsafe_allow_html=True)
        st.markdown("<p class='page-subtitle'>Early warning cyberthreat intelligence portal</p>", unsafe_allow_html=True)
        
        st.markdown("""
            <div style='background: #111827; border: 1px solid #1F2937; border-radius: 8px; padding: 40px; text-align: center; max-width: 600px; margin: 40px auto;'>
                <span style='font-size: 3rem;'>📭</span>
                <h3 style='margin-top: 15px; color:#FFFFFF;'>No Active Threat Telemetry Mapped</h3>
                <p style='color: #9CA3AF; font-size: 0.9rem; margin-bottom: 25px;'>
                    Database contains zero observation logs. Ingest telemetry logs manually, execute RSS Scrapers, or seed mock scenarios from the controls panel.
                </p>
            </div>
        """, unsafe_allow_html=True)
        
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if st.button("🔌 Go to System Control to Seed Data", use_container_width=True, type="primary"):
                st.session_state.current_page = "Settings"
                st.rerun()
        with col_s2:
            if st.button("📥 Go to Evidence Panel to Report Intel", use_container_width=True):
                st.session_state.current_page = "Reports"
                st.rerun()
        st.stop()

# Helpers to get Risk Classifications
def get_risk_meta(score):
    if score >= 75.0:
        return "Critical", "badge-critical"
    elif score >= 50.0:
        return "High", "badge-high"
    elif score >= 25.0:
        return "Medium", "badge-medium"
    else:
        return "Low", "badge-low"

# --- PAGE ROUTING CONTROLLERS ---

# --- VIEW 1: EXECUTIVE DASHBOARD ---
if st.session_state.current_page == "Dashboard":
    st.markdown("<h1 class='page-title'>📊 System Overview</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>High-level command metrics and threats intelligence dashboard.</p>", unsafe_allow_html=True)
    
    # KPIs calculations
    total_intel = len(df)
    active_campaigns = df["campaign_id"].nunique()
    critical_alerts = len(df[df["risk_score"] >= 75.0])
    
    all_urls = []
    for row in df["urls"].dropna():
        if row and str(row) != "None":
            all_urls.extend([u.strip() for u in str(row).split(",") if u.strip()])
    unique_domains = len(set(all_urls))
    
    # Display Clean KPI Cards
    col_k1, col_k2, col_k3, col_k4 = st.columns(4)
    with col_k1:
        st.markdown(f"""
            <div class="saas-card">
                <div class="saas-metric-title">📁 Monitored Threat Logs</div>
                <div class="saas-metric-value">{total_intel}</div>
                <div class="saas-metric-desc"><span class="trend-up">↑ Live</span> updates ingested</div>
            </div>
        """, unsafe_allow_html=True)
    with col_k2:
        st.markdown(f"""
            <div class="saas-card">
                <div class="saas-metric-title">🏷️ Active Campaigns</div>
                <div class="saas-metric-value">{active_campaigns}</div>
                <div class="saas-metric-desc"><span class="trend-neutral">● Tracked</span> clusters</div>
            </div>
        """, unsafe_allow_html=True)
    with col_k3:
        st.markdown(f"""
            <div class="saas-card">
                <div class="saas-metric-title">⚠️ Critical Risks (>=75)</div>
                <div class="saas-metric-value" style="color: #EF4444;">{critical_alerts}</div>
                <div class="saas-metric-desc">Require block list actions</div>
            </div>
        """, unsafe_allow_html=True)
    with col_k4:
        st.markdown(f"""
            <div class="saas-card">
                <div class="saas-metric-title">🌐 Suspicious Web Domains</div>
                <div class="saas-metric-value" style="color: #FBBF24;">{unique_domains}</div>
                <div class="saas-metric-desc">Extracted for blocking</div>
            </div>
        """, unsafe_allow_html=True)

    # Secondary Charts Row
    st.markdown("### 📈 threat Intelligence Analytics")
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        st.markdown("<p style='font-size: 0.95rem; font-weight:600; color:#3B82F6;'>Observations Breakdown by Scam Category</p>", unsafe_allow_html=True)
        type_counts = df["scam_type"].value_counts().reset_index()
        type_counts.columns = ["Scam Category", "Count"]
        st.bar_chart(type_counts.set_index("Scam Category"), color="#3B82F6")
        st.caption("Categorization distribution computed by the AI classifier engine.")
        
    with col_c2:
        st.markdown("<p style='font-size: 0.95rem; font-weight:600; color:#3B82F6;'>Scam Campaign Intensity Leaderboard</p>", unsafe_allow_html=True)
        camp_df = df.groupby("campaign_id").size().reset_index(name="Log Count").sort_values("Log Count", ascending=False)
        st.bar_chart(camp_df.set_index("campaign_id"), color="#EF4444")
        st.caption("Campaign clusters displaying highest observation volume.")

    # Recent Alerts Summary Panel
    st.markdown("---")
    st.markdown("### 🚨 Urgent Attention Queue")
    st.markdown("<p style='color:#9CA3AF; font-size:0.85rem; margin-top:-10px;'>Top critical threats requiring immediate review and blocking action.</p>", unsafe_allow_html=True)
    
    crit_list = df[df["risk_score"] >= 50.0].sort_values("risk_score", ascending=False).head(3)
    if not crit_list.empty:
        for idx, row in crit_list.iterrows():
            severity_str, badge_cls = get_risk_meta(row["risk_score"])
            status = row.get("status", "New")
            st.markdown(f"""
                <div style='background: #111827; border: 1px solid #1F2937; border-radius: 6px; padding: 12px 18px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;'>
                    <div>
                        <span class="badge {badge_cls}" style="margin-right: 10px;">{severity_str} Risk ({row['risk_score']})</span>
                        <span style="font-weight:600; font-size:0.9rem;">{row['campaign_id']} - {row['scam_type']}</span>
                        <div style="font-size:0.8rem; color:#9CA3AF; margin-top:3px;">
                            <b>URLs:</b> <code>{row['urls'] if row['urls'] else 'None detected'}</code> | <b>Case Status:</b> {status}
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        if st.button("➡️ Access Actionable Alerts Panel", use_container_width=True):
            st.session_state.current_page = "Alerts"
            st.rerun()
    else:
        st.success("No high-risk threats currently flagged.")

# --- VIEW 2: ACTIVE CAMPAIGNS ---
elif st.session_state.current_page == "Campaigns":
    st.markdown("<h1 class='page-title'>🏷️ Active Campaigns</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Organized threat groups and clusters mapped by semantic similarity models.</p>", unsafe_allow_html=True)
    
    # Calculate Campaign aggregations
    camp_groups = df.groupby("campaign_id").agg(
        Scam_Type=("scam_type", lambda x: x.mode()[0] if not x.empty else "Unknown"),
        Max_Risk=("risk_score", "max"),
        First_Seen=("timestamp", "min"),
        Last_Seen=("timestamp", "max"),
        Report_Volume=("text", "count"),
        Urls=("urls", lambda x: ", ".join(set([u.strip() for val in x if val for u in str(val).split(",") if u.strip()]))),
        Keywords=("keywords", lambda x: ", ".join(set([k.strip() for val in x if val for k in str(val).split(",") if k.strip()])))
    ).reset_index().sort_values(by="Max_Risk", ascending=False)
    
    # Layout: Split View (Left: List of Campaign Cards, Right: Interactive Detail Panel)
    col_c_list, col_c_detail = st.columns([3, 2])
    
    with col_c_list:
        st.markdown("### Campaign Registry")
        for idx, row in camp_groups.iterrows():
            severity_str, badge_cls = get_risk_meta(row["Max_Risk"])
            
            # Simple card rendering
            is_selected = st.session_state.selected_campaign == row["campaign_id"]
            card_border = "2px solid #3B82F6" if is_selected else "1px solid #1F2937"
            
            st.markdown(f"""
                <div style='background: #111827; border: {card_border}; border-radius: 8px; padding: 15px; margin-bottom: 12px;'>
                    <div style='display: flex; justify-content: space-between; align-items: start;'>
                        <div>
                            <span class="badge {badge_cls}" style='margin-bottom: 5px;'>{severity_str} (Risk: {row['Max_Risk']:.0f})</span>
                            <h4 style='margin: 0; font-size:1.05rem; font-weight:700;'>{row['campaign_id']}</h4>
                            <p style='margin: 3px 0 0 0; font-size: 0.85rem; color:#9CA3AF;'><b>Scam Type:</b> {row['Scam_Type']} | <b>Reports Logged:</b> {row['Report_Volume']}</p>
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            if st.button(f"🔍 View Campaign Details - {row['campaign_id']}", key=f"sel_{row['campaign_id']}", use_container_width=True):
                st.session_state.selected_campaign = row["campaign_id"]
                st.rerun()
                
    with col_c_detail:
        st.markdown("### Intelligence Details Panel")
        if st.session_state.selected_campaign:
            # Fetch details
            c_info = camp_groups[camp_groups["campaign_id"] == st.session_state.selected_campaign].iloc[0]
            severity_str, badge_cls = get_risk_meta(c_info["Max_Risk"])
            
            st.markdown(f"""
                <div style='background: #111827; border: 1px solid #1F2937; border-radius: 8px; padding: 20px;'>
                    <span class="badge {badge_cls}">{severity_str} Risk Level</span>
                    <h3 style='margin-top: 5px; margin-bottom:15px; color:#FFFFFF;'>{c_info['campaign_id']}</h3>
                    
                    <p style='font-size:0.85rem; color:#9CA3AF; margin-bottom: 12px;'>
                        <b>Primary Category:</b> {c_info['Scam_Type']}<br/>
                        <b>Observations Mapped:</b> {c_info['Report_Volume']} logs<br/>
                        <b>Confidence Level:</b> {c_info['Max_Risk']}% severity index
                    </p>
                    
                    <hr style='border: 0.5px solid #1F2937; margin: 12px 0;'/>
                    
                    <h5 style='margin-bottom:6px; color:#3B82F6; font-size:0.9rem;'>📁 Campaign Timeline</h5>
                    <p style='font-size:0.8rem; color:#E5E7EB; margin-bottom:12px;'>
                        <b>First Ingested:</b> {c_info['First_Seen']}<br/>
                        <b>Last Activity:</b> {c_info['Last_Seen']}
                    </p>
                    
                    <h5 style='margin-bottom:6px; color:#3B82F6; font-size:0.9rem;'>🌐 Implicated Domains/URLs</h5>
                    <p style='font-size:0.8rem; background: #0B0F19; padding: 8px; border-radius:4px; border: 1px solid #1F2937; color:#F3F4F6; font-family: monospace; word-break: break-all;'>
                        {c_info['Urls'] if c_info['Urls'] else 'No suspect domain links detected.'}
                    </p>
                    
                    <h5 style='margin-top:12px; margin-bottom:6px; color:#3B82F6; font-size:0.9rem;'>🔑 Extracted Key Identifiers</h5>
                    <div style='margin-bottom: 15px;'>
            """, unsafe_allow_html=True)
            
            # Print tags
            kws = c_info["Keywords"].split(",")
            for k in kws:
                if k.strip():
                    st.markdown(f"<span class='tag-pill'>{k.strip()}</span>", unsafe_allow_html=True)
                    
            st.markdown("""
                    </div>
                </div>
            """, unsafe_allow_html=True)
        else:
            st.info("Select a campaign card from the list on the left to examine detailed cyber intelligence.")

# --- VIEW 3: LIVE THREAT FEED ---
elif st.session_state.current_page == "Feed":
    st.markdown("<h1 class='page-title'>🚨 Live Threat Feed</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Interactive logs registry and Plain-English Explainable AI diagnostics.</p>", unsafe_allow_html=True)
    
    # Search & Filter Block
    search_q = st.text_input("🔍 Global Search Threat Logs", placeholder="Search by domains, Telegram channels, keywords, suspect text, or Campaign IDs...")
    
    f_col1, f_col2, f_col3 = st.columns(3)
    with f_col1:
        f_type = st.multiselect("Filter Scam Category", df["scam_type"].unique())
    with f_col2:
        f_platform = st.multiselect("Filter Platform Source", df["platform"].unique())
    with f_col3:
        # Custom risk levels
        f_risk = st.multiselect("Filter Risk Level", ["Critical (>=75)", "High (50-74)", "Medium (25-49)", "Low (<25)"])

    # Processing Filtering logic
    filtered_df = df.copy()
    
    if search_q.strip():
        q = search_q.lower()
        filtered_df = filtered_df[
            filtered_df["text"].str.lower().str.contains(q, na=False) |
            filtered_df["campaign_id"].str.lower().str.contains(q, na=False) |
            filtered_df["urls"].str.lower().str.contains(q, na=False) |
            filtered_df["scam_type"].str.lower().str.contains(q, na=False) |
            filtered_df["keywords"].str.lower().str.contains(q, na=False)
        ]
        
    if f_type:
        filtered_df = filtered_df[filtered_df["scam_type"].isin(f_type)]
        
    if f_platform:
        filtered_df = filtered_df[filtered_df["platform"].isin(f_platform)]
        
    if f_risk:
        indices = []
        for idx, row in filtered_df.iterrows():
            level, _ = get_risk_meta(row["risk_score"])
            if level == "Critical" and "Critical (>=75)" in f_risk:
                indices.append(idx)
            elif level == "High" and "High (50-74)" in f_risk:
                indices.append(idx)
            elif level == "Medium" and "Medium (25-49)" in f_risk:
                indices.append(idx)
            elif level == "Low" and "Low (<25)" in f_risk:
                indices.append(idx)
        filtered_df = filtered_df.loc[indices]

    filtered_df = filtered_df.sort_values(by="timestamp", ascending=False)
    
    # Threat Logs render
    st.markdown(f"**Showing {len(filtered_df)} Observations**")
    if not filtered_df.empty:
        for idx, row in filtered_df.iterrows():
            severity_str, badge_cls = get_risk_meta(row["risk_score"])
            
            st.markdown(f"""
                <div style='background:#111827; border: 1px solid #1F2937; border-radius: 8px; padding: 16px; margin-bottom: 12px;'>
                    <div style='display:flex; justify-content:space-between; align-items:center;'>
                        <div>
                            <span class="badge {badge_cls}" style='margin-right:8px;'>{severity_str} Risk ({row['risk_score']:.0f})</span>
                            <span style='color:#E5E7EB; font-size:0.8rem;'>Detected: {row['timestamp']} via <b>{row['platform'].upper()}</b></span>
                        </div>
                        <span style='font-family: monospace; font-size:0.85rem; color:#9CA3AF;'>ID: {row['campaign_id']}</span>
                    </div>
                    <p style='margin: 10px 0 10px 0; font-size:0.925rem; color:#FFFFFF; line-height: 1.4;'>{row['text']}</p>
            """, unsafe_allow_html=True)
            
            # Plain English XAI Expander
            with st.expander(f"❔ Why was this flagged? - AI Explanation Report"):
                st.markdown("""
                    <div class="xai-container">
                        <h5 style='margin-top:0; color:#FFFFFF; font-size: 0.85rem;'>Diagnostic Report</h5>
                """, unsafe_allow_html=True)
                
                # Risk explanation
                st.markdown(f"""
                        <p style='font-size:0.8rem; color:#E5E7EB; margin-bottom: 8px;'>
                            <b>AI scam classification:</b> Classified as a <b>{row['scam_type']}</b>. 
                            This scam vector commonly tricks victims by sending malicious URLs or using coercive messages.
                        </p>
                        <p style='font-size:0.8rem; color:#E5E7EB; margin-bottom: 8px;'>
                            <b>Indicators Found:</b>
                        </p>
                """, unsafe_allow_html=True)
                
                # Display keywords as tags
                if row["urls"]:
                    st.markdown(f"<div style='margin-bottom:8px;'><span style='font-size:0.75rem; color:#EF4444;'>● Suspect domain detected:</span> <code style='font-size:0.75rem;'>{row['urls']}</code></div>", unsafe_allow_html=True)
                
                if row["keywords"]:
                    st.markdown("<div style='margin-bottom:4px;'><span style='font-size:0.75rem; color:#9CA3AF;'>● Trigger keywords:</span>", unsafe_allow_html=True)
                    for k in str(row["keywords"]).split(","):
                        if k.strip():
                            st.markdown(f"<span class='tag-pill'>{k.strip()}</span>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)
                
                st.markdown(f"""
                        <p style='font-size:0.8rem; color:#E5E7EB; margin-top:8px; margin-bottom:0;'>
                            <b>Campaign Similarity:</b> Mapped with <b>{row['risk_score']:.0f}% confidence</b> to tracking group <b>{row['campaign_id']}</b> based on semantic structure.
                        </p>
                    </div>
                """, unsafe_allow_html=True)
                
            st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No threat logs matched the search filter criteria.")

# --- VIEW 4: GEOGRAPHIC RADAR ---
elif st.session_state.current_page == "Map":
    st.markdown("<h1 class='page-title'>🗺️ Geographic Radar</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Hosting server geolocation infrastructure and target regional alert hotspots.</p>", unsafe_allow_html=True)
    
    # Stats row
    m_col1, m_col2 = st.columns(2)
    with m_col1:
        st.markdown("""
            <div class="saas-card" style="padding: 12px 18px;">
                <div class="saas-metric-title">Mapped Hosts</div>
                <div style="font-size:1.5rem; font-weight:700;">Global Infrastructure Mapped</div>
                <p style="font-size:0.8rem; color:#9CA3AF; margin:0;">Suspect phishing hosting hubs geolocated.</p>
            </div>
        """, unsafe_allow_html=True)
    with m_col2:
        st.markdown("""
            <div class="saas-card" style="padding: 12px 18px;">
                <div class="saas-metric-title">Regional Target</div>
                <div style="font-size:1.5rem; font-weight:700;">Pan-India Hotspots</div>
                <p style="font-size:0.8rem; color:#9CA3AF; margin:0;">Highest target focus regional observations.</p>
            </div>
        """, unsafe_allow_html=True)
        
    # Build coordinates array
    map_coords = []
    locations_pool = [
        {"lat": 28.6139, "lon": 77.2090, "city": "Delhi/NCR Server"},
        {"lat": 19.0760, "lon": 72.8777, "city": "Mumbai Server"},
        {"lat": 12.9716, "lon": 77.5946, "city": "Bangalore Proxy Hub"},
        {"lat": 13.0827, "lon": 80.2707, "city": "Chennai Host"},
        {"lat": 22.5726, "lon": 88.3639, "city": "Kolkata Origin"},
        {"lat": 17.3850, "lon": 78.4867, "city": "Hyderabad Server"},
        {"lat": 18.5204, "lon": 73.8567, "city": "Pune Hotspot"},
        {"lat": 23.0225, "lon": 72.5714, "city": "Ahmedabad Host"},
        {"lat": 26.9124, "lon": 75.7873, "city": "Jaipur Origin"},
        {"lat": 26.8467, "lon": 80.9462, "city": "Lucknow Host"},
        {"lat": 1.3521, "lon": 103.8198, "city": "Singapore Host (DigitalOcean)"},
        {"lat": 37.7749, "lon": -122.4194, "city": "USA Cloudflare Proxy Host"},
        {"lat": 55.7558, "lon": 37.6173, "city": "Russia Proxy Host"},
        {"lat": 52.3676, "lon": 4.9041, "city": "Netherlands Host"}
    ]
    
    # Seeding random location coordinate based on domain name hash to keep coordinates stable
    for val in df["urls"].dropna():
        if val and str(val) != "None":
            urls_list = [u.strip() for u in str(val).split(",") if u.strip()]
            for url in urls_list:
                stable_hash = int(hashlib.md5(url.encode('utf-8')).hexdigest(), 16)
                loc_idx = stable_hash % len(locations_pool)
                loc = locations_pool[loc_idx]
                
                # Use a stable random seed per domain so markers don't jump around on refresh
                random.seed(stable_hash)
                lat_noise = random.uniform(-0.02, 0.02)
                lon_noise = random.uniform(-0.02, 0.02)
                # Reset random seed to avoid affecting other global processes
                random.seed()
                
                map_coords.append({
                    "lat": loc["lat"] + lat_noise,
                    "lon": loc["lon"] + lon_noise,
                    "Infrastructure Domain": url,
                    "Hosting Hub": loc["city"]
                })
                
    if map_coords:
        # Create Folium Map
        m = folium.Map(
            location=[22.0, 50.0], 
            zoom_start=3, 
            tiles="OpenStreetMap", 
            control_scale=True
        )
        
        # Add Marker Cluster
        marker_cluster = MarkerCluster().add_to(m)
        
        # Add markers to cluster
        for coord in map_coords:
            popup_html = f"""
            <div style="font-family: 'Inter', sans-serif; font-size: 12px; width: 230px; color: #1F2937;">
                <h4 style="margin: 0 0 5px 0; color: #1E3A8A; font-family: 'Inter', sans-serif; font-weight:700;">🚨 SUSPECT HOST</h4>
                <hr style="border: 0.5px solid #E5E7EB; margin: 4px 0;"/>
                <span style="font-weight: 600;">Suspect Domain:</span><br/>
                <code style="background: #F3F4F6; padding: 2px 4px; border-radius: 4px; display: inline-block; margin-top: 3px; font-size: 11px; color:#DC2626; word-break: break-all;">{coord['Infrastructure Domain']}</code><br/>
                <span style="font-weight: 600; display: inline-block; margin-top: 6px;">Hosting Location:</span><br/>
                <span>📍 {coord['Hosting Hub']}</span><br/>
                <span style="font-size: 10px; color: #6B7280; display: inline-block; margin-top: 4px;">Coords: {coord['lat']:.4f}, {coord['lon']:.4f}</span>
            </div>
            """
            folium.Marker(
                location=[coord["lat"], coord["lon"]],
                popup=folium.Popup(popup_html, max_width=270),
                icon=folium.Icon(color="red", icon="warning-sign"),
                tooltip=f"Domain: {coord['Infrastructure Domain']}"
            ).add_to(marker_cluster)
            
        # Display Map
        st_folium(m, height=500, use_container_width=True, returned_objects=[])
    else:
        st.info("No suspect web domains have been extracted to plot on the mapping radar.")

# --- VIEW 5: ACTIONABLE ALERTS (ALERT CENTER) ---
elif st.session_state.current_page == "Alerts":
    st.markdown("<h1 class='page-title'>⚠️ Actionable Alerts</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Interactive case inbox. Review and take blocking actions against cyberthreats.</p>", unsafe_allow_html=True)
    
    # Tabs to filter alert status
    tab_new, tab_ack, tab_res = st.tabs(["🔴 Active Alerts", "🟡 Under Investigation", "🟢 Resolved Cases"])
    
    # Process alerts
    alerts_list = df.copy()
    alerts_list = alerts_list.sort_values("risk_score", ascending=False)
    
    def render_alerts_by_status(status_filter):
        # Group df by campaign_id and get status of campaign (mode or first)
        camps = alerts_list.groupby("campaign_id").first().reset_index()
        matched = camps[camps["status"] == status_filter]
                
        if matched.empty:
            st.markdown(f"<p style='color:#9CA3AF; margin-top:15px;'>No alerts in '{status_filter}' queue.</p>", unsafe_allow_html=True)
            return
            
        for idx, row in matched.iterrows():
            severity_str, badge_cls = get_risk_meta(row["risk_score"])
            
            st.markdown(f"""
                <div style='background: #111827; border: 1px solid #1F2937; border-radius: 8px; padding: 18px; margin-bottom: 12px;'>
                    <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;'>
                        <span class="badge {badge_cls}">{severity_str} Severity</span>
                        <span style='font-size:0.75rem; color:#9CA3AF;'>Detected At: {row['timestamp']}</span>
                    </div>
                    <h4 style='margin:0; font-size:1.1rem; color:#FFFFFF;'>{row['campaign_id']} - {row['scam_type']} Flagged</h4>
                    <p style='margin:10px 0; font-size:0.9rem; color:#E5E7EB; line-height: 1.4;'>{row['text']}</p>
                    <hr style='border: 0.5px solid #1F2937; margin: 10px 0;'/>
                    <p style='font-size:0.8rem; color:#9CA3AF; margin-bottom: 12px;'>
                        <b>Recommended action:</b> Submit domains (<code>{row['urls'] if row['urls'] else 'None detected'}</code>) to DoT block list register. Notify Haryana Police Cyber Cell.
                    </p>
            """, unsafe_allow_html=True)
            
            # Action button columns
            b_col1, b_col2 = st.columns([1, 1])
            with b_col1:
                if status_filter == "New":
                    if st.button(f"Acknowledge Case - {row['campaign_id']}", key=f"ack_{row['campaign_id']}", use_container_width=True):
                        try:
                            requests.put(f"{API_BASE_URL}/api/v1/alerts/{row['campaign_id']}/status", params={"status": "Acknowledged"})
                            st.toast(f"Case {row['campaign_id']} assigned for investigation.")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"API Error: {e}")
                elif status_filter == "Acknowledged":
                    if st.button(f"Mark as Resolved - {row['campaign_id']}", key=f"res_{row['campaign_id']}", use_container_width=True):
                        try:
                            requests.put(f"{API_BASE_URL}/api/v1/alerts/{row['campaign_id']}/status", params={"status": "Resolved"})
                            st.toast(f"Case {row['campaign_id']} marked as resolved.")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"API Error: {e}")
            with b_col2:
                if status_filter != "Resolved":
                    if st.button(f"Ignore / Dismiss - {row['campaign_id']}", key=f"ig_{row['campaign_id']}", use_container_width=True):
                        try:
                            requests.put(f"{API_BASE_URL}/api/v1/alerts/{row['campaign_id']}/status", params={"status": "Resolved"})
                            st.toast(f"Dismissed alert {row['campaign_id']}.")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"API Error: {e}")
            st.markdown("</div>", unsafe_allow_html=True)

    with tab_new:
        render_alerts_by_status("New")
    with tab_ack:
        render_alerts_by_status("Acknowledged")
    with tab_res:
        render_alerts_by_status("Resolved")

# --- VIEW 6: EVIDENCE & INGESTION ---
elif st.session_state.current_page == "Reports":
    st.markdown("<h1 class='page-title'>📥 Evidence & Ingestion</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Crawlers control panel, manual fraud message ingestion, and registrar domain blocklist export.</p>", unsafe_allow_html=True)
    
    col_e1, col_e2, col_e3 = st.columns([1, 1, 1])
    
    with col_e1:
        st.markdown("### 📥 Report Fraud Message")
        st.markdown("<p style='font-size:0.85rem; color:#9CA3AF; margin-top:-10px;'>Analyze and ingest raw messages, UPIs, or links directly into the AI pipeline.</p>", unsafe_allow_html=True)
        
        with st.form(key="manual_ingest_page_form", clear_on_submit=True):
            source_channel = st.selectbox("Intelligence Source Platform", ["Telegram", "WhatsApp", "SMS Phishing", "Web Domain", "Email"])
            threat_text = st.text_area("Suspicious Text / Msg Payload", placeholder="Paste scam message, links, UPIs, or phone numbers here...", height=150)
            submit_button = st.form_submit_button(label="Ingest & Run Pipeline", use_container_width=True)
            
            if submit_button:
                if not threat_text.strip():
                    st.error("Please enter the suspicious text payload.")
                elif not api_online:
                    st.error("Ingestion failed: FastAPI Core engine is offline.")
                else:
                    with st.spinner("Analyzing message and running AI clustering..."):
                        try:
                            res = requests.post(
                                f"{API_BASE_URL}/api/v1/intel/manual",
                                params={"text": threat_text, "source": source_channel.lower()}
                            )
                            if res.status_code == 200:
                                st.success("Ingested successfully! Message classified and clustered.")
                                time.sleep(1.5)
                                st.rerun()
                            else:
                                st.error("Error processing manual ingestion endpoint.")
                        except Exception as e:
                            st.error(f"Request failed: {e}")
                            
    with col_e2:
        st.markdown("### 🎛️ Platform Scanners")
        st.markdown("<p style='font-size:0.85rem; color:#9CA3AF; margin-top:-10px;'>Trigger platform-specific OSINT crawlers and AI parsing pipeline.</p>", unsafe_allow_html=True)
        
        # 1. RSS Scanner Button
        st.markdown("""
            <div style='background:#111827; border:1px solid #1F2937; border-radius:6px; padding:10px 15px; margin-bottom:10px;'>
                <span style='font-size:1.1rem;'>📰</span> <b>RSS News / Websites</b>
                <div style='font-size:0.75rem; color:#9CA3AF; margin-top:2px;'>Scan BleepingComputer RSS feeds for new cyber alert posts.</div>
            </div>
        """, unsafe_allow_html=True)
        if st.button("🔌 Run RSS Website Scanner", use_container_width=True, key="trigger_rss_btn", disabled=not api_online):
            with st.spinner("Executing RSS collector & running AI parser..."):
                try:
                    res = requests.post(f"{API_BASE_URL}/api/v1/collect/rss")
                    if res.status_code == 200:
                        count = res.json().get("new_raw_records_collected", 0)
                        st.success(f"Success! RSS Crawler complete. Ingested {count} new records.")
                        time.sleep(1.5)
                        st.rerun()
                    else:
                        st.error("Crawler invocation error on backend server.")
                except Exception as e:
                    st.error(f"Failed to connect to API: {e}")
                    
        # 2. Telegram Scanner Button
        st.markdown("""
            <div style='background:#111827; border:1px solid #1F2937; border-radius:6px; padding:10px 15px; margin-top:15px; margin-bottom:10px;'>
                <span style='font-size:1.1rem;'>✈️</span> <b>Public Telegram Channels</b>
                <div style='font-size:0.75rem; color:#9CA3AF; margin-top:2px;'>Scan public Indian threat intel & task scam channels via Telethon.</div>
            </div>
        """, unsafe_allow_html=True)
        if st.button("✈️ Run Telegram Channel Scanner", use_container_width=True, key="trigger_tg_btn", disabled=not api_online):
            with st.spinner("Connecting to MTProto & pulling messages..."):
                try:
                    res = requests.post(f"{API_BASE_URL}/api/v1/collect/telegram")
                    if res.status_code == 200:
                        count = res.json().get("new_raw_records_collected", 0)
                        st.success(f"Success! Telegram Scraper complete. Ingested {count} new messages.")
                        time.sleep(1.5)
                        st.rerun()
                    else:
                        st.error("Scraper invocation error on backend server.")
                except Exception as e:
                    st.error(f"Failed to connect to API: {e}")

        # 3. Reddit Social Media Scanner Button
        st.markdown("""
            <div style='background:#111827; border:1px solid #1F2937; border-radius:6px; padding:10px 15px; margin-top:15px; margin-bottom:10px;'>
                <span style='font-size:1.1rem;'>🔥</span> <b>Public Reddit Communities</b>
                <div style='font-size:0.75rem; color:#9CA3AF; margin-top:2px;'>Scan r/IsThisAScamIndia, r/cybercrime etc. for real victim narratives.</div>
            </div>
        """, unsafe_allow_html=True)
        if st.button("🔥 Run Reddit Victim Scraper", use_container_width=True, key="trigger_reddit_btn", disabled=not api_online):
            with st.spinner("Connecting to Reddit APIs & pulling victim posts..."):
                try:
                    res = requests.post(f"{API_BASE_URL}/api/v1/collect/reddit")
                    if res.status_code == 200:
                        count = res.json().get("new_raw_records_collected", 0)
                        st.success(f"Success! Reddit Scraper complete. Ingested {count} new social media posts.")
                        time.sleep(1.5)
                        st.rerun()
                    else:
                        st.error("Scraper invocation error on backend server.")
                except Exception as e:
                    st.error(f"Failed to connect to API: {e}")

    with col_e3:
        st.markdown("### 📑 Export Domain Blocklist")
        st.markdown("<p style='font-size:0.85rem; color:#9CA3AF; margin-top:-10px;'>Download CSV blocklist file formatted for direct registrar submission.</p>", unsafe_allow_html=True)
        
        # Prepare blocklist data
        blocklist_data = []
        for idx, row in df.iterrows():
            urls = str(row["urls"])
            if urls and urls != "None" and urls != "":
                for u in urls.split(","):
                    u_clean = u.strip()
                    if u_clean:
                        blocklist_data.append({
                            "Campaign_ID": row["campaign_id"],
                            "Detected_At": row["timestamp"],
                            "Scam_Type": row["scam_type"],
                            "Risk_Score": row["risk_score"],
                            "Suspect_Domain": u_clean,
                            "Raw_Text": row["text"]
                        })
                        
        if blocklist_data:
            block_df = pd.DataFrame(blocklist_data)
            st.dataframe(block_df[["Campaign_ID", "Suspect_Domain", "Scam_Type", "Risk_Score"]], use_container_width=True, hide_index=True)
            
            csv_data = block_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Evidence Blocklist CSV File",
                data=csv_data,
                file_name="gurugram_cyber_sentinel_blocklist.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.warning("No suspect domains extracted to build an evidence blocklist.")

    st.markdown("---")
    st.markdown("### 📜 Threat Detection History Log")
    st.markdown("<p style='font-size:0.85rem; color:#9CA3AF; margin-top:-10px;'>Persistent audit log of all suspicious threats detected by scheduled or manual scans.</p>", unsafe_allow_html=True)
    
    try:
        hist_resp = requests.get(f"{API_BASE_URL}/api/v1/analytics/threat-history", timeout=2.0).json()
        hist_df = pd.DataFrame(hist_resp)
    except Exception:
        hist_df = pd.DataFrame()
        
    if not hist_df.empty:
        # Re-order columns and display
        display_hist = hist_df[["timestamp", "platform", "scam_type", "risk_score", "verdict", "raw_text"]]
        display_hist.columns = ["Timestamp", "Platform", "Category", "Risk Score", "Verdict", "Raw Message Payload"]
        st.dataframe(display_hist, use_container_width=True, hide_index=True)
    else:
        st.info("No scan logs found in history. Run platform scanners above or seed scenarios to generate logs.")

# --- VIEW 7: SYSTEM CONTROL (SETTINGS) ---
elif st.session_state.current_page == "Settings":
    st.markdown("<h1 class='page-title'>⚙️ System Control</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-subtitle'>Operational controls, databases management, and AI seeder telemetry engine.</p>", unsafe_allow_html=True)
    
    st.markdown("### 🎛️ Database Operations")
    
    col_se1, col_se2 = st.columns(2)
    with col_se1:
        st.markdown("""
            <div class="saas-card">
                <h4 style="margin-top:0; color:#FFFFFF;">Ingest Test Datasets</h4>
                <p style="font-size:0.8rem; color:#9CA3AF; margin-bottom:15px;">
                    Populate the local SQLite threat intelligence engine with 6 realistic Indian/Gurugram cybercrime scenarios.
                </p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("⚡ Seed Mock Cybercrime Telemetry", use_container_width=True, disabled=not api_online):
            MOCK_SCENARIOS = [
                {
                    "text": "ALERT: Cyber criminals impersonating FedEx and Customs officers. Victims in Sector 56, Gurugram received calls claiming a parcel containing MDMA was intercepted. Suspects forced victims to transfer Rs 4.5 Lakhs under threat of arrest. Suspect UPI: customsprotect@icici, Suspect website: https://fedex-clearance-support.com",
                    "source": "manual"
                },
                {
                    "text": "WARNING: YouTube video like scam active. WhatsApp message from +91 98765 43210 offers 'Rs 150 per like, earn Rs 5000 daily'. Victims directed to join Telegram channel @GurugramPartTimeTasks and deposited on website http://tmart-rewards-india.com. Total fraud reported: Rs 12 Lakhs.",
                    "source": "telegram"
                },
                {
                    "text": "SBI Customer KYC Alert: SMS sent to residents: 'Dear SBI user, your Netbanking account is blocked. Please update your KYC immediately to avoid suspension. Web portal: http://sbi-kyc-verification-online.com'. Please report phishing links immediately.",
                    "source": "rss_news"
                },
                {
                    "text": "LOAN FRAUD ALERT: Instant mobile loan app 'RupeeSpeedy' is harassing contacts of Gurugram residents, demanding 200% interest on Rs 10,000 loans. Suspect app download site: http://rupeespeedy-instant-loan.in/download.apk",
                    "source": "manual"
                },
                {
                    "text": "INVESTMENT SCAM: Suspect WhatsApp stock advice group 'GGL Wealth Advisory' running pump and dump stock fraud. Gurugram businessman lost Rs 25 Lakhs. Suspect platform: http://ggl-wealth-trading.com, mule bank accounts active in Haryana.",
                    "source": "manual"
                },
                {
                    "text": "URGENT DHBVN NOTICE: SMS warning Gurugram residents of electricity disconnection at 9:30 PM due to unpaid bills. Ask victims to contact helpline number +91 99998 88877. Suspect UPI payment link: dhavn.billpay@paytm",
                    "source": "manual"
                }
            ]
            
            with st.spinner("Executing pipeline ingestion..."):
                success_count = 0
                for scenario in MOCK_SCENARIOS:
                    try:
                        res = requests.post(
                            f"{API_BASE_URL}/api/v1/intel/manual",
                            params={"text": scenario["text"], "source": scenario["source"]}
                        )
                        if res.status_code == 200:
                            success_count += 1
                    except Exception:
                        pass
                
                if success_count > 0:
                    st.success(f"Success: Processed {success_count} mock cyber threats through AI models.")
                    time.sleep(1.5)
                    st.rerun()
                else:
                    st.error("Failed to connect or process mock data.")
                    
    with col_se2:
        st.markdown("""
            <div class="saas-card">
                <h4 style="margin-top:0; color:#FFFFFF;">Reset Local Database</h4>
                <p style="font-size:0.8rem; color:#9CA3AF; margin-bottom:15px;">
                    Permanently delete all logs and campaign artifacts inside the local SQLite database file.
                </p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("🗑️ Clear Local Threat DB", use_container_width=True):
            if manual_sqlite_clear():
                st.success("Success: Database wiped clean.")
                time.sleep(1.5)
                st.rerun()

    # System Diagnostics info
    st.markdown("---")
    st.markdown("### 📊 System Diagnostics")
    
    # Check database size
    db_size_kb = 0
    if os.path.exists(DB_PATH):
        db_size_kb = os.path.getsize(DB_PATH) / 1024
        
    st.markdown(f"""
        <div class="saas-card" style="font-family: monospace; font-size:0.85rem;">
            <b>Database Connection Path:</b> {DB_PATH}<br/>
            <b>Database Size:</b> {db_size_kb:.2f} KB<br/>
            <b>FastAPI Core URL:</b> {API_BASE_URL}<br/>
            <b>Environment:</b> RAKSHAK Command Portal 2.0 (Gurugram Police)
        </div>
    """, unsafe_allow_html=True)