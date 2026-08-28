import os
import json
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models.database import SessionLocal, init_db, Repository, Package, DependencyEdge, VulnerabilityDb, Finding
from backend.services.sbom_parser import SbomParser
from backend.services.graph_service import GraphService
from backend.services.vuln_intelligence import VulnIntelligenceService
from backend.services.risk_engine import RiskEngine
from backend.services.ml_service import MLService

VULNERABILITIES_SEED = [
    {
        "cve_id": "CVE-2021-23337",
        "package_name": "lodash",
        "affected_range": "<4.17.21",
        "fixed_version": "4.17.21",
        "cvss": 7.2,
        "epss": 0.85,
        "exploit_available": True,
        "title": "Prototype Pollution in Lodash Template Engine",
        "description": "lodash version < 4.17.21 is vulnerable to prototype pollution. An attacker can craft inputs to inject attributes into Object.prototype, leading to remote code execution or denial of service when processing user-controlled templates."
    },
    {
        "cve_id": "CVE-2023-45857",
        "package_name": "axios",
        "affected_range": "<1.6.0",
        "fixed_version": "1.6.0",
        "cvss": 7.5,
        "epss": 0.42,
        "exploit_available": False,
        "title": "Server-Side Request Forgery in Axios Redirects",
        "description": "axios before version 1.6.0 contains a server-side request forgery (SSRF) vulnerability. When handling redirect requests, axios fails to validate the hostname, letting attackers redirect internal requests to arbitrary endpoints."
    },
    {
        "cve_id": "CVE-2024-29025",
        "package_name": "express",
        "affected_range": "<4.19.2",
        "fixed_version": "4.19.2",
        "cvss": 5.3,
        "epss": 0.15,
        "exploit_available": False,
        "title": "Denial of Service via Unchecked Route Redirections",
        "description": "express < 4.19.2 is susceptible to request crashes when unvalidated routing headers are passed, enabling resource exhaustion and denial of service attacks."
    },
    {
        "cve_id": "CVE-2022-23529",
        "package_name": "jsonwebtoken",
        "affected_range": "<9.0.0",
        "fixed_version": "9.0.0",
        "cvss": 9.8,
        "epss": 0.96,
        "exploit_available": True,
        "title": "Signature Verification Bypass in jwt.verify",
        "description": "jsonwebtoken library version < 9.0.0 fails to validate algorithm properties properly. Attackers can supply specially crafted public keys to trigger signature bypass, forging valid authentication tokens."
    },
    {
        "cve_id": "CVE-2023-43804",
        "package_name": "urllib3",
        "affected_range": "<1.26.18",
        "fixed_version": "1.26.18",
        "cvss": 6.1,
        "epss": 0.28,
        "exploit_available": False,
        "title": "Cookie and Auth Header Leakage on Cross-Domain Redirect",
        "description": "urllib3 before 1.26.18 fails to strip critical Authorization or Cookie headers when redirecting HTTP requests to a different host, potentially leaking API keys and sessions."
    },
    {
        "cve_id": "CVE-2023-32681",
        "package_name": "requests",
        "affected_range": "<2.31.0",
        "fixed_version": "2.31.0",
        "cvss": 6.1,
        "epss": 0.32,
        "exploit_available": True,
        "title": "Proxy-Authorization Header Leakage during HTTPS redirect",
        "description": "requests library before version 2.31.0 leaks Proxy-Authorization headers to destination hostnames when following HTTP redirects, allowing session sniffing."
    },
    {
        "cve_id": "CVE-2024-27351",
        "package_name": "django",
        "affected_range": "<4.2.10",
        "fixed_version": "4.2.10",
        "cvss": 7.5,
        "epss": 0.12,
        "exploit_available": False,
        "title": "Regular Expression Denial of Service in Django Validators",
        "description": "django < 4.2.10 is vulnerable to ReDoS attacks in URLValidator due to a poorly optimized regular expression matching rule."
    }
]

def run_scan_for_repo(db: Session, repo: Repository, sbom_path: str):
    """Parses and scans a repository SBOM, populating packages and findings."""
    if not os.path.exists(sbom_path):
        print(f"SBOM path {sbom_path} not found. Skipping scan.")
        return

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom_content = json.load(f)

    # 1. Parse SBOM
    sbom_type, parsed_pkgs, parsed_edges = SbomParser.parse(sbom_content)
    repo.sbom_type = sbom_type

    # 2. Build and analyze dependency graph (calculates depths, dependents)
    analyzed_pkgs, analyzed_edges = GraphService.analyze_dependency_graph(parsed_pkgs, parsed_edges, repo.name)

    # 3. Store Packages in DB
    pkg_models = []
    pkg_by_name = {}
    for p in analyzed_pkgs:
        pkg = Package(
            repository_id=repo.id,
            name=p["name"],
            version=p["version"],
            type=p["type"],
            is_direct=p["is_direct"],
            depth=p["depth"],
            dependents_count=p["dependents_count"]
        )
        db.add(pkg)
        pkg_models.append(pkg)
        pkg_by_name[p["name"]] = p
        
    db.commit() # Commit to get IDs

    # 4. Store Dependency Edges
    for parent, child in analyzed_edges:
        edge = DependencyEdge(
            repository_id=repo.id,
            parent_name=parent,
            child_name=child
        )
        db.add(edge)
    db.commit()

    # 5. Scan vulnerabilities (Vulnerability Intelligence match)
    findings_data = VulnIntelligenceService.scan_packages(db, analyzed_pkgs)

    # 6. Apply Context-Aware Risk Scoring and ML Prioritization
    max_risk = 0.0
    for f in findings_data:
        # Context-Aware Risk Score
        risk_details = RiskEngine.calculate_risk_score(
            cvss=f["cvss"],
            epss=f["epss"],
            depth=f["depth"],
            installed_version=f["package_version"],
            fixed_version=f["fixed_version"]
        )
        
        # ML Prioritization Features
        ml_features = {
            "cvss": f["cvss"],
            "epss": f["epss"],
            "depth": f["depth"],
            "patch_lag": risk_details["patch_lag"],
            "exploit_available": f["exploit_available"],
            "in_degree": f["in_degree"],
            "out_degree": f["out_degree"],
            "dependents_count": f["dependents_count"]
        }
        
        ml_prediction = MLService.predict(ml_features)
        
        # Safe Remediation Info
        # NPM vs PIP
        pkg_type = "npm"
        for p in analyzed_pkgs:
            if p["name"] == f["package_name"]:
                pkg_type = p["type"]
                break

        # Generate Git Patch and upgrade command
        remediation_info = {
            "finding_id": 0, # Placeholder
            "package_name": f["package_name"],
            "current_version": f["package_version"],
            "recommended_version": f["fixed_version"],
            "pkg_type": pkg_type,
            "cve_id": f["cve_id"],
            "dependents_count": f["dependents_count"]
        }
        
        # Generate upgrade commands
        if pkg_type == "pip":
            remediation_cmd = f"pip install {f['package_name']}=={f['fixed_version']}"
            git_patch = (
                f"diff --git a/requirements.txt b/requirements.txt\n"
                f"--- a/requirements.txt\n"
                f"+++ b/requirements.txt\n"
                f"-{f['package_name']}=={f['package_version']}\n"
                f"+{f['package_name']}=={f['fixed_version']}\n"
            )
        else:
            remediation_cmd = f"npm install {f['package_name']}@{f['fixed_version']} --save-exact"
            git_patch = (
                f"diff --git a/package.json b/package.json\n"
                f"--- a/package.json\n"
                f"+++ b/package.json\n"
                f"-    \"{f['package_name']}\": \"^{f['package_version']}\",\n"
                f"+    \"{f['package_name']}\": \"^{f['fixed_version']}\",\n"
            )

        finding_model = Finding(
            repository_id=repo.id,
            package_name=f["package_name"],
            package_version=f["package_version"],
            cve_id=f["cve_id"],
            cvss=f["cvss"],
            epss=f["epss"],
            exploit_available=f["exploit_available"],
            depth=f["depth"],
            patch_lag=risk_details["patch_lag"],
            calculated_risk=risk_details["score"],
            ml_probability=ml_prediction["risk_probability"],
            ml_priority=ml_prediction["category"],
            status="active",
            remediation_cmd=remediation_cmd,
            patch_diff=git_patch,
            fixed_version=f["fixed_version"],
            dependency_path=json.dumps(f["dependency_path"])
        )
        
        db.add(finding_model)
        
        if risk_details["score"] > max_risk:
            max_risk = risk_details["score"]

    # 7. Update repository security status
    repo.status = "scanned"
    repo.risk_score = max_risk
    repo.last_scan = datetime.utcnow()
    
    # Calculate build status
    # BLOCKED if there are Critical vulnerabilities (risk score >= 90)
    has_critical = any(f["cvss"] >= 9.0 or (f["cvss"] * f["epss"] * 2.0 >= 10.0) for f in findings_data) # Check if any is critical
    # Better yet: check if max_risk >= 90.0
    if max_risk >= 90.0:
        repo.build_status = "BLOCKED"
    elif max_risk >= 70.0:
        repo.build_status = "WARNING"
    else:
        repo.build_status = "PASS"

    db.commit()

def seed_database():
    """Wipes and seeds the database with initial vulnerability Intel and scanned repos."""
    print("Initializing Database tables...")
    init_db()
    db = SessionLocal()
    
    try:
        # Check if database is already seeded
        if db.query(VulnerabilityDb).count() > 0:
            print("Database already seeded with vulnerabilities. Skipping seeding.")
            return

        print("Seeding Vulnerability Intelligence Database...")
        for vuln in VULNERABILITIES_SEED:
            v_model = VulnerabilityDb(
                cve_id=vuln["cve_id"],
                package_name=vuln["package_name"],
                affected_range=vuln["affected_range"],
                fixed_version=vuln["fixed_version"],
                cvss=vuln["cvss"],
                epss=vuln["epss"],
                exploit_available=vuln["exploit_available"],
                title=vuln["title"],
                description=vuln["description"]
            )
            db.add(v_model)
        db.commit()

        # Seed Sample Repositories
        print("Seeding Sample Repositories...")
        
        # Repo 1: NPM
        repo_npm = Repository(
            name="ecommerce-api",
            sbom_type="cyclonedx",
            status="unscanned",
            risk_score=0.0,
            build_status="PASS"
        )
        db.add(repo_npm)
        
        # Repo 2: PIP
        repo_pip = Repository(
            name="ml-analytics-pipeline",
            sbom_type="spdx",
            status="unscanned",
            risk_score=0.0,
            build_status="PASS"
        )
        db.add(repo_pip)
        db.commit()

        # Train ML Model first so it is ready
        print("Pre-training ML Priority Classifier...")
        MLService.load_model()

        # Run scans to populate packages and findings
        print("Running initial scans on seed repositories...")
        data_dir = os.path.dirname(os.path.abspath(__file__))
        
        run_scan_for_repo(db, repo_npm, os.path.join(data_dir, "sample_sbom_npm.json"))
        run_scan_for_repo(db, repo_pip, os.path.join(data_dir, "sample_sbom_pip.json"))
        
        print("Database successfully seeded.")
        
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
