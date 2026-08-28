# VulnGraph AI

Demo video link : https://www.youtube.com/watch?v=Ga550O0RQOk

Intelligent dependency risk scoring, graph-based reachability analysis, and vulnerability prioritization platform.

VulnGraph AI ingests Software Bill of Materials (SBOMs), models dependencies as a directed graph, applies context-aware risk scoring, ranks vulnerabilities using a pre-trained Random Forest classifier, and outputs actionable remediation recommendations with config file patches.

---

## Features

- **Multi-Format Ingestion**: Supports CycloneDX and SPDX JSON formats.
- **Reachability Mapping**: Calculates dependency depth and topological statistics (in-degree, out-degree, dependents count) using Breadth-First Search (BFS).
- **Context-Aware Risk Engine**: Evaluates CVSS base score, exploit availability, EPSS probability, patch lag (version distance), and path depth decay.
- **Machine Learning Prioritization**: Uses a Random Forest Classifier to categorize risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with local feature contribution explanations.
- **Configurable Scoring Weights**: Offers runtime configuration of engine parameters via API to dynamically adjust organization-specific gates.
- **Actionable Remediation suggestions**: Generates package-manager commands (`npm`/`pip`) and configuration patches (`package.json`/`requirements.txt` diffs) with click-to-remediate simulation.
- **Interactive Dark-themed Dashboard**: Built with Cytoscape.js for force-directed node-link visualizations and Chart.js for stats analysis.

---

## Tech Stack

- **Backend**: FastAPI (Python 3.9+), SQLAlchemy, SQLite, scikit-learn, pandas, numpy, joblib.
- **Frontend**: HTML5, Vanilla CSS (Glassmorphism design system), Vanilla JS, Cytoscape.js, Chart.js.
- **Testing**: Pytest, FastAPI TestClient.

---

## Installation & Setup

Follow these steps to run the application locally on Windows:

### 1. Set Up Virtual Environment & Install Dependencies
Navigate to the `backend` directory, create a virtual environment, and install the required binary packages:
```powershell
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install requirements using precompiled binaries
python -m pip install --only-binary :all: -r requirements.txt
python -m pip install httpx
```

### 2. Seed Database & Pre-train ML Model
The system seeds SQLite with vulnerability threat intelligence and trains the classifier on startup. Alternatively, you can seed manually:
```powershell
# Run the database seed script
python -m backend.data.seed_data
```

### 3. Run Unit and Integration Tests
Validate the application services and static endpoint routing by running pytest from the project root:
```powershell
# Run from workspace root directory
cd ..
.\backend\venv\Scripts\python -m pytest backend/tests/
```

### 4. Start the Application
Start the FastAPI development server:
```powershell
.\backend\venv\Scripts\uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
- **Web App UI**: Navigate to [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser.
- **Interactive API Docs (Swagger UI)**: Access [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) to verify API routes.

---

## API Endpoints Reference

### 1. Configuration & Calibration
- `GET /api/risk/config` - Retrieve current risk scoring weights.
- `POST /api/risk/config` - Update scoring weights and re-evaluate the database.
  - **Request Body**:
    ```json
    {
      "cvss_weight": 10.0,
      "epss_weight": 1.0,
      "patch_lag_weight": 1.0,
      "depth_weight": 1.0
    }
    ```

### 2. Remediation Recommendations
- `GET /api/remediation/{finding_id}` - Fetch upgrade commands and config patch diffs for a specific vulnerability.
- `POST /api/remediate/{finding_id}` - Apply/simulate vulnerability remediation (updates package version in DB).

### 3. Ingestion & Graph Analytics
- `POST /api/sbom/upload` - Upload CycloneDX/SPDX JSON files to analyze software risk.
- `GET /api/repositories` - Fetch tracked repository status records.
- `GET /api/graph/{repository_id}` - Fetch Graph node-link schema for Cytoscape renderer.
- `GET /api/dashboard` - Get high-level KPI and chart metrics.
