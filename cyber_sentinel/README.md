# RAKSHAK Command Portal — Cyber Sentinel
**Advanced Threat Intelligence & OSINT Aggregation System**

The RAKSHAK Command Portal is a production-ready, pan-India threat intelligence platform designed to scrape, aggregate, classify, and visualize cyber threats in real time. It uses a robust FastAPI backend combined with an AI-driven text classification pipeline to extract actionable intelligence from unstructured data sources like Telegram, Reddit, RSS news feeds, and URLhaus.

---

## System Architecture

The application is strictly decoupled into two primary components to ensure clean architecture and scalability:

1. **The Core Engine (`backend/`)**
   Built with FastAPI and SQLAlchemy. It runs background scrapers, processes incoming unstructured text through an AI pipeline, stores results in a SQLite database, and serves the structured data via REST endpoints.
2. **The Command Portal (`frontend/`)**
   Built with Streamlit. It consumes the FastAPI endpoints to render real-time dashboards, an interactive pan-India geographic radar, and actionable alert queues for cyber analysts.

### The AI Pipeline Breakdown
When a new piece of text is ingested (either manually or via a crawler), it passes through a multi-stage NLP pipeline:
- **DNA Extractor (`backend/ai/dna_extractor.py`)**: Uses regex heuristics to extract structured entities (URLs, emails, crypto wallets, phone numbers, UPI IDs, IP addresses, and Geographic references—mapped across all 36 Indian States and UTs).
- **Zero-Shot Classifier (`backend/ai/classifier.py`)**: Uses a Hugging Face `transformers` model (`typeform/distilbert-base-uncased-mnli`) to classify the text into one of several scam categories (Phishing, Malware, Digital Arrest, Financial Scam, etc.) and calculate a risk score based on the category and extracted artifacts.
- **Semantic Clusterer (`backend/ai/clusterer.py`)**: Uses SentenceTransformers (`all-MiniLM-L6-v2`) to generate embeddings for the text. It then compares the new embedding against recent database entries using Cosine Similarity to group similar threats into "Campaigns".

### Database Schema
The SQLite database (`cyber_sentinel.db`) is the central repository. Key tables include:
- `raw_intel`: Stores the original ingested text and source platform.
- `threat_history`: Stores the finalized analysis (verdict, risk score, scam type).
- `scam_artifacts`: Relational table linking threats to specific extracted indicators (URLs, phone numbers).

---

## What We Built & Why (Recent Overhaul)

To make the platform truly production-ready and developer-friendly, we completely overhauled the architecture:

### 1. Architectural Restructuring (Frontend / Backend)
**What:** The project was completely refactored. The `app/` folder was renamed to `backend/`, and `dashboard/` was renamed to `frontend/`. All Python relative imports and Docker configurations were automatically rewired to support this strict separation of concerns.
**Why:** A flat or confusing folder structure makes onboarding new developers difficult. Separating the React-like dashboard code from the API code ensures better maintainability.

### 2. Real-Time Data Autorefresh
**What:** The Live Threat Feed and Dashboard now automatically refresh every 30 seconds using `streamlit-autorefresh`.
**Why:** A cyber threat command center cannot rely on manual page reloads. The real-time capability ensures analysts see the absolute latest ingested telemetry instantly, turning the app into a true "live" monitor.

### 3. Complete Pan-India Geographic Radar
**What:** The mapping engine was upgraded from a partial 24-state map to include the precise coordinates for **all 36 States and Union Territories** in India (including Andaman & Nicobar, Lakshadweep, Ladakh, and all North-Eastern states).
**Why:** Threats can originate or target anywhere in the country. Without a complete coordinate map, valid geo-tagged threats from smaller UTs or states would simply fail to render on the geographic radar.

### 4. High-Contrast UI & Evidence Tab Overhaul
**What:** URLs and critical indicators in the dashboard were upgraded to use a high-contrast cyan color (`#22D3EE`). The Evidence & Ingestion page was reorganized from a cramped 3-column layout into a clean Tabbed interface. Streamlit deprecation warnings (`use_container_width`) were universally patched.
**Why:** Dark mode UIs often suffer from readability issues with deep blue links. The high-contrast upgrade ensures analysts can read suspect URLs instantly. Tabbed interfaces prevent cognitive overload when running scrapers or exporting blocklists.

### 5. Critical Backend Bug Fixes
A comprehensive audit resolved severe backend instability:
- **Import Crash:** Wrapped the `telethon` import in a `try/except` block. Previously, if `telethon` was missing, the entire FastAPI backend would crash on startup.
- **Regex Tuple Bug:** Fixed a bug in the geographic regex extractor that caused it to return tuples instead of strings, breaking the state-matching logic.
- **SQLite Path Resolution:** Fixed the database URL parsing logic in `main.py` which prevented migrations from running.
- **URLhaus API:** Fixed the API URL path to properly pass limits, preventing 404 errors during malware collection.
- **Launcher Timeout:** Increased the FastAPI boot timeout from 15s to 60s in `run_project.py` because loading local PyTorch/Transformer AI models into memory takes ~40 seconds on cold boot.

---

## User Guide

### Starting the System
You do not need to start the frontend and backend manually. We built a unified launcher for convenience!

1. **Launch Both Servers:**
   Run `python run_project.py`. This script starts the FastAPI server on port `8080`, waits for the AI models to load into memory (up to 60 seconds), and then automatically launches the Streamlit dashboard in your browser on port `8501`.

### Navigating the Portal
- **Dashboard:** Executive overview of threat volume, top targeted states, and an Urgent Alerts queue.
- **Live Threat Feed:** Searchable database of all analyzed intel. Expand any row to see the "AI Explainability" diagnostic.
- **Geographic Radar:** Interactive map showing where threats are concentrated across India.
- **Actionable Alerts:** A case management view. Analysts can "Acknowledge", "Resolve", or "Dismiss" threats.
- **Suspect Registry:** Cross-campaign aggregations of repeat phone numbers and a domain blocklist ready for DoT submission.
- **Evidence & Ingestion:** The control panel to manually run scrapers (Reddit, RSS, Telegram) or submit manual intelligence reports.
- **System Control:** Seed the database with 10 realistic pan-India mock scenarios for testing, or completely clear the SQLite database.
