import os
import json
from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from backend.models.database import engine, Base, get_db, Repository, Package, DependencyEdge, Finding, VulnerabilityDb
from backend.models import schemas
from backend.services.sbom_parser import SbomParser
from backend.services.graph_service import GraphService
from backend.services.vuln_intelligence import VulnIntelligenceService
from backend.services.risk_engine import RiskEngine
from backend.services.ml_service import MLService
from backend.services.remediation_service import RemediationService
from backend.services.cicd_service import CicdService
from backend.data.seed_data import seed_database, run_scan_for_repo

app = FastAPI(
    title="VulnGraph AI API",
    description="Intelligent dependency risk scoring and vulnerability prioritization backend.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    """Wipes/Initializes database and pre-trains the ML model on server startup."""
    seed_database()

# --- Health Check ---
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "vulngraph-ai-backend"}

# --- Repository Endpoints ---
@app.get("/api/repositories", response_model=List[schemas.RepositoryResponse])
def get_repositories(db: Session = Depends(get_db)):
    return db.query(Repository).all()

@app.get("/api/repositories/{repo_id}", response_model=schemas.RepositoryResponse)
def get_repository(repo_id: int, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo

@app.delete("/api/repositories/{repo_id}")
def delete_repository(repo_id: int, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    db.delete(repo)
    db.commit()
    return {"message": f"Repository {repo_id} deleted successfully"}

# --- SBOM Upload Endpoints ---
@app.post("/api/sbom/upload")
async def upload_sbom(
    file: UploadFile = File(...),
    repo_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    # Validate file extension
    filename = file.filename
    if not filename.endswith('.json'):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file format. Only JSON CycloneDX or SPDX files are supported."
        )
        
    try:
        content = await file.read()
        sbom_data = json.loads(content.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse JSON file: {str(e)}")

    # Auto-resolve repository name if not provided
    if not repo_name:
        # Extract from filename or use fallback
        repo_name = os.path.splitext(filename)[0]
        # Clean name
        repo_name = repo_name.replace("-sbom", "").replace("_sbom", "")

    # Parse and validate format
    try:
        sbom_type, parsed_pkgs, parsed_edges = SbomParser.parse(sbom_data)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"SBOM structural validation failed: {str(e)}")

    # Check if repository already exists, if so delete previous parsed components to overwrite
    repo = db.query(Repository).filter(Repository.name == repo_name).first()
    if repo:
        db.query(Package).filter(Package.repository_id == repo.id).delete()
        db.query(DependencyEdge).filter(DependencyEdge.repository_id == repo.id).delete()
        db.query(Finding).filter(Finding.repository_id == repo.id).delete()
        repo.status = "scanning"
        repo.sbom_type = sbom_type
    else:
        repo = Repository(
            name=repo_name,
            sbom_type=sbom_type,
            status="scanning",
            risk_score=0.0,
            build_status="PASS"
        )
        db.add(repo)
        db.commit() # Commit to get ID

    # Calculate graph structure
    analyzed_pkgs, analyzed_edges = GraphService.analyze_dependency_graph(parsed_pkgs, parsed_edges, repo.name)

    # Insert Packages
    for p in analyzed_pkgs:
        pkg_model = Package(
            repository_id=repo.id,
            name=p["name"],
            version=p["version"],
            type=p["type"],
            is_direct=p["is_direct"],
            depth=p["depth"],
            dependents_count=p["dependents_count"]
        )
        db.add(pkg_model)

    # Insert Dependency Edges
    for parent, child in analyzed_edges:
        edge_model = DependencyEdge(
            repository_id=repo.id,
            parent_name=parent,
            child_name=child
        )
        db.add(edge_model)
    db.commit()

    # Match Vulnerability Intelligence
    findings_data = VulnIntelligenceService.scan_packages(db, analyzed_pkgs)

    # Compute risk and ML prioritizations
    max_risk = 0.0
    for f in findings_data:
        risk_details = RiskEngine.calculate_risk_score(
            cvss=f["cvss"],
            epss=f["epss"],
            depth=f["depth"],
            installed_version=f["package_version"],
            fixed_version=f["fixed_version"]
        )
        
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

        # Generate commands
        pkg_type = f["package_name"]
        for p in analyzed_pkgs:
            if p["name"] == f["package_name"]:
                pkg_type = p["type"]
                break
                
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

    repo.status = "scanned"
    repo.risk_score = max_risk
    
    # Calculate build status
    if max_risk >= 90.0:
        repo.build_status = "BLOCKED"
    elif max_risk >= 70.0:
        repo.build_status = "WARNING"
    else:
        repo.build_status = "PASS"

    db.commit()

    return {
        "repository_id": repo.id,
        "repository_name": repo.name,
        "package_count": len(analyzed_pkgs),
        "direct_dependencies_count": sum(1 for p in analyzed_pkgs if p["is_direct"]),
        "transitive_dependencies_count": sum(1 for p in analyzed_pkgs if not p["is_direct"]),
        "findings_count": len(findings_data),
        "overall_risk_score": max_risk,
        "build_status": repo.build_status
    }

# --- Graph Endpoints ---
@app.get("/api/graph/{repository_id}", response_model=schemas.GraphResponse)
def get_dependency_graph(repository_id: int, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter(Repository.id == repository_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    packages = db.query(Package).filter(Package.repository_id == repository_id).all()
    edges = db.query(DependencyEdge).filter(DependencyEdge.repository_id == repository_id).all()
    findings = db.query(Finding).filter(Finding.repository_id == repository_id, Finding.status == "active").all()

    # Map findings by package name
    vuln_map = {}
    for f in findings:
        if f.package_name not in vuln_map:
            vuln_map[f.package_name] = []
        vuln_map[f.package_name].append({
            "cve_id": f.cve_id,
            "cvss": f.cvss,
            "risk_score": f.calculated_risk,
            "priority": f.ml_priority
        })

    nodes = []
    # Build list of nodes
    for p in packages:
        # Check if package has findings
        pkg_vulns = vuln_map.get(p.name, [])
        is_vuln = len(pkg_vulns) > 0
        
        max_priority = "SAFE"
        max_score = 0.0
        if is_vuln:
            max_score = max(v["risk_score"] for v in pkg_vulns)
            # Find matching priority
            priorities = [v["priority"] for v in pkg_vulns]
            if "CRITICAL" in priorities:
                max_priority = "CRITICAL"
            elif "HIGH" in priorities:
                max_priority = "HIGH"
            elif "MEDIUM" in priorities:
                max_priority = "MEDIUM"
            else:
                max_priority = "LOW"

        nodes.append({
            "id": p.name,
            "label": p.name,
            "version": p.version,
            "type": p.type,
            "is_direct": p.is_direct,
            "depth": p.depth,
            "dependents_count": p.dependents_count,
            "is_vulnerable": is_vuln,
            "max_risk_score": max_score,
            "risk_category": max_priority,
            "vulnerabilities": pkg_vulns
        })

    serialized_edges = [
        {"source": e.parent_name, "target": e.child_name} 
        for e in edges
    ]

    return {"nodes": nodes, "edges": serialized_edges}

# --- Dependencies list ---
@app.get("/api/dependencies/{repository_id}", response_model=List[schemas.PackageResponse])
def get_repository_dependencies(repository_id: int, db: Session = Depends(get_db)):
    return db.query(Package).filter(Package.repository_id == repository_id).all()

# --- Vulnerability / Findings Endpoints ---
@app.get("/api/vulnerabilities", response_model=List[schemas.FindingResponse])
def get_vulnerabilities(
    repository_id: Optional[int] = None,
    priority: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Finding)
    if repository_id is not None:
        query = query.filter(Finding.repository_id == repository_id)
    if priority is not None:
        query = query.filter(Finding.ml_priority == priority.upper())
    # Return sorted by risk score descending
    return query.order_by(Finding.calculated_risk.desc()).all()

@app.get("/api/vulnerabilities/{finding_id}", response_model=schemas.FindingResponse)
def get_vulnerability_detail(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

# --- Risk Engine Config Endpoints ---
@app.get("/api/risk/config", response_model=schemas.RiskConfigRequest)
def get_risk_config():
    """
    Retrieves the current configurable weights in the risk scoring engine.
    """
    weights = RiskEngine.get_weights()
    return schemas.RiskConfigRequest(
        cvss_weight=weights["cvss_weight"],
        epss_weight=weights["epss_weight"],
        patch_lag_weight=weights["patch_lag_weight"],
        depth_weight=weights["depth_weight"]
    )


@app.post("/api/risk/config")
def update_risk_config(config: schemas.RiskConfigRequest, db: Session = Depends(get_db)):
    """
    Updates the weights in the risk scoring engine and recalculates findings and repo build statuses.
    """
    RiskEngine.set_weights(
        cvss=config.cvss_weight,
        epss=config.epss_weight,
        patch_lag=config.patch_lag_weight,
        depth=config.depth_weight
    )
    
    # Recalculate risk scores for all active findings
    findings = db.query(Finding).all()
    for f in findings:
        risk_details = RiskEngine.calculate_risk_score(
            cvss=f.cvss,
            epss=f.epss,
            depth=f.depth,
            installed_version=f.package_version,
            fixed_version=f.fixed_version
        )
        f.calculated_risk = risk_details["score"]
        
    db.commit()
    
    # Recalculate repository overall risk score and build status
    repos = db.query(Repository).all()
    for repo in repos:
        active_findings = db.query(Finding).filter(
            Finding.repository_id == repo.id,
            Finding.status == "active"
        ).all()
        
        if active_findings:
            repo.risk_score = max(f.calculated_risk for f in active_findings)
        else:
            repo.risk_score = 0.0
            
        if repo.risk_score >= 90.0:
            repo.build_status = "BLOCKED"
        elif repo.risk_score >= 70.0:
            repo.build_status = "WARNING"
        else:
            repo.build_status = "PASS"
            
    db.commit()
    
    return {
        "message": "Risk engine configuration updated and database re-evaluated",
        "config": RiskEngine.get_weights()
    }


# --- Contextual Risk details endpoint ---
@app.get("/api/risk/{finding_id}")
def get_finding_risk_breakdown(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    risk_breakdown = RiskEngine.calculate_risk_score(
        cvss=finding.cvss,
        epss=finding.epss,
        depth=finding.depth,
        installed_version=finding.package_version,
        fixed_version=finding.fixed_version
    )
    
    # ML explanation
    pkg = db.query(Package).filter(
        Package.repository_id == finding.repository_id, 
        Package.name == finding.package_name
    ).first()
    
    ml_features = {
        "cvss": finding.cvss,
        "epss": finding.epss,
        "depth": finding.depth,
        "patch_lag": finding.patch_lag,
        "exploit_available": finding.exploit_available,
        "in_degree": pkg.in_degree if pkg else 0,
        "out_degree": pkg.out_degree if pkg else 0,
        "dependents_count": pkg.dependents_count if pkg else 0
    }
    
    ml_analysis = MLService.predict(ml_features)
    
    return {
        "finding_id": finding.id,
        "package_name": finding.package_name,
        "cve_id": finding.cve_id,
        "formula": "CVSS_Score * 10 * (0.15 + 0.85 * EPSS) * (1 + Patch_Lag) * (1 / sqrt(Depth))",
        "calculations": {
            "cvss_component": finding.cvss * 10,
            "epss_component": risk_breakdown["epss_factor"],
            "patch_lag_component": 1.0 + risk_breakdown["patch_lag"],
            "depth_component": risk_breakdown["depth_factor"]
        },
        "explanations": risk_breakdown["explanations"],
        "ml_analysis": ml_analysis
    }

# --- Actionable Remediation Endpoint ---
@app.post("/api/remediate/{finding_id}", response_model=schemas.FindingResponse)
def remediate_finding(finding_id: int, db: Session = Depends(get_db)):
    """
    Simulates remediation for a vulnerability.
    Updates finding status to 'remediated', updates package version to fixed,
    re-evaluates risk score for repository.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    if finding.status == "remediated":
        return finding
        
    finding.status = "remediated"
    
    # Update Package version to the fixed version
    pkg = db.query(Package).filter(
        Package.repository_id == finding.repository_id,
        Package.name == finding.package_name
    ).first()
    if pkg:
        pkg.version = finding.fixed_version

    db.commit()

    # Re-calculate overall repository risk score (max score of active findings)
    repo = db.query(Repository).filter(Repository.id == finding.repository_id).first()
    if repo:
        active_findings = db.query(Finding).filter(
            Finding.repository_id == repo.id,
            Finding.status == "active"
        ).all()
        
        if active_findings:
            repo.risk_score = max(f.calculated_risk for f in active_findings)
        else:
            repo.risk_score = 0.0
            
        # Update build status
        if repo.risk_score >= 90.0:
            repo.build_status = "BLOCKED"
        elif repo.risk_score >= 70.0:
            repo.build_status = "WARNING"
        else:
            repo.build_status = "PASS"

    db.commit()
    db.refresh(finding)
    return finding

# --- Dashboard Summary ---
@app.get("/api/dashboard", response_model=schemas.DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    repos = db.query(Repository).all()
    packages = db.query(Package).all()
    findings = db.query(Finding).filter(Finding.status == "active").all()
    
    total_repos = len(repos)
    total_deps = len(packages) - total_repos # Subtracting root projects
    total_findings = len(findings)
    
    # Calculate Severity stats
    critical = sum(1 for f in findings if f.ml_priority == "CRITICAL" or f.calculated_risk >= 90.0)
    high = sum(1 for f in findings if (f.ml_priority == "HIGH" or f.calculated_risk >= 70.0) and f.calculated_risk < 90.0)
    medium = sum(1 for f in findings if (f.ml_priority == "MEDIUM" or f.calculated_risk >= 40.0) and f.calculated_risk < 70.0)
    low = sum(1 for f in findings if f.ml_priority == "LOW" and f.calculated_risk < 40.0)
    
    transitive = sum(1 for f in findings if f.depth > 1)
    fixable = sum(1 for f in findings if f.fixed_version is not None)
    
    blocked = sum(1 for r in repos if r.build_status == "BLOCKED")
    
    # Sort and slice recent findings
    recent_findings = db.query(Finding).filter(Finding.status == "active").order_by(Finding.calculated_risk.desc()).limit(5).all()
    
    # Distribution charts
    severity_distribution = {
        "Critical": critical,
        "High": high,
        "Medium": medium,
        "Low": low
    }
    
    direct_vs_transitive = {
        "Direct": total_findings - transitive,
        "Transitive": transitive
    }
    
    risk_by_repository = {
        r.name: r.risk_score for r in repos
    }

    return {
        "total_repositories": total_repos,
        "total_dependencies": max(0, total_deps),
        "total_vulnerabilities": total_findings,
        "critical_vulnerabilities": critical,
        "high_vulnerabilities": high,
        "medium_vulnerabilities": medium,
        "low_vulnerabilities": low,
        "transitive_vulnerabilities": transitive,
        "fixable_vulnerabilities": fixable,
        "blocked_builds": blocked,
        "recent_findings": recent_findings,
        "severity_distribution": severity_distribution,
        "direct_vs_transitive": direct_vs_transitive,
        "risk_by_repository": risk_by_repository
    }

# --- CI/CD Security Check Endpoints ---
@app.post("/api/ci/check", response_model=schemas.CICDCheckResponse)
def check_ci_gate(request: schemas.CICDCheckRequest, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter(Repository.id == request.repository_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
        
    findings = db.query(Finding).filter(Finding.repository_id == request.repository_id).all()
    
    gate_results = CicdService.evaluate_build(
        findings=findings,
        risk_threshold=request.risk_threshold,
        fail_on_critical=request.fail_on_critical
    )
    
    # Sync status to repository model in database
    repo.build_status = gate_results["status"]
    db.commit()
    
    return gate_results

@app.post("/api/scan/{repository_id}")
def scan_repository(repository_id: int, db: Session = Depends(get_db)):
    """Triggers a re-scan of the repository from scratch."""
    repo = db.query(Repository).filter(Repository.id == repository_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
        
    # Find dependencies / packages
    packages = db.query(Package).filter(Package.repository_id == repository_id).all()
    
    # Translate DB packages back to dictionaries for VulnIntelligence scan
    pkg_dicts = []
    for p in packages:
        # Fetch connections in dependency graph
        pkg_dicts.append({
            "name": p.name,
            "version": p.version,
            "type": p.type,
            "depth": p.depth,
            "is_direct": p.is_direct,
            "dependents_count": p.dependents_count,
            "in_degree": p.id % 3, # Estimations
            "out_degree": p.id % 4,
            "path_from_root": [repo.name, p.name] if p.is_direct else [repo.name, "express", p.name] # Mock pathing
        })

    # Clear previous findings
    db.query(Finding).filter(Finding.repository_id == repository_id).delete()
    db.commit()

    findings_data = VulnIntelligenceService.scan_packages(db, pkg_dicts)

    max_risk = 0.0
    for f in findings_data:
        risk_details = RiskEngine.calculate_risk_score(
            cvss=f["cvss"],
            epss=f["epss"],
            depth=f["depth"],
            installed_version=f["package_version"],
            fixed_version=f["fixed_version"]
        )
        
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

        if f["exploit_available"]:
            remediation_cmd = f"npm install {f['package_name']}@{f['fixed_version']} --save-exact"
            git_patch = f"+ {f['package_name']}@{f['fixed_version']}"
        else:
            remediation_cmd = f"npm install {f['package_name']}@{f['fixed_version']}"
            git_patch = f"+ {f['package_name']}@{f['fixed_version']}"

        finding_model = Finding(
            repository_id=repository_id,
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

    repo.risk_score = max_risk
    if max_risk >= 90.0:
        repo.build_status = "BLOCKED"
    elif max_risk >= 70.0:
        repo.build_status = "WARNING"
    else:
        repo.build_status = "PASS"
        
    db.commit()
    return {"message": f"Scan completed. Over overall risk score: {max_risk}"}


# --- Actionable Remediation GET Endpoint ---
@app.get("/api/remediation/{finding_id}", response_model=schemas.RemediationResponse)
def get_remediation_details(finding_id: int, db: Session = Depends(get_db)):
    """
    Retrieves the specific remediation instructions and diff patch for a finding.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    # Retrieve dependency details to determine ecosystem (pip/npm) and dependents count
    pkg = db.query(Package).filter(
        Package.repository_id == finding.repository_id,
        Package.name == finding.package_name
    ).first()
    
    pkg_type = pkg.type if pkg else "npm"
    dependents_count = pkg.dependents_count if pkg else 0
    
    remediation_data = RemediationService.generate_remediation(
        finding_id=finding.id,
        package_name=finding.package_name,
        current_version=finding.package_version,
        fixed_version=finding.fixed_version or finding.package_version,
        pkg_type=pkg_type,
        cve_id=finding.cve_id,
        dependents_count=dependents_count
    )
    return remediation_data


from fastapi.staticfiles import StaticFiles

app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
