from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class RepositoryBase(BaseModel):
    name: str

class RepositoryCreate(RepositoryBase):
    pass

class RepositoryResponse(RepositoryBase):
    id: int
    last_scan: datetime
    sbom_type: Optional[str] = None
    status: str
    risk_score: float
    build_status: str

    class Config:
        from_attributes = True

class PackageResponse(BaseModel):
    id: int
    repository_id: int
    name: str
    version: str
    type: str
    is_direct: bool
    depth: int
    dependents_count: int

    class Config:
        from_attributes = True

class DependencyEdgeResponse(BaseModel):
    parent_name: str
    child_name: str

    class Config:
        from_attributes = True

class GraphResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]

class FindingResponse(BaseModel):
    id: int
    repository_id: int
    package_name: str
    package_version: str
    cve_id: str
    cvss: float
    epss: float
    exploit_available: bool
    depth: int
    patch_lag: float
    calculated_risk: float
    ml_probability: float
    ml_priority: str
    status: str
    remediation_cmd: Optional[str] = None
    patch_diff: Optional[str] = None
    fixed_version: Optional[str] = None
    dependency_path: Optional[str] = None

    class Config:
        from_attributes = True

class DashboardSummary(BaseModel):
    total_repositories: int
    total_dependencies: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    transitive_vulnerabilities: int
    fixable_vulnerabilities: int
    blocked_builds: int
    recent_findings: List[FindingResponse]
    severity_distribution: Dict[str, int]
    direct_vs_transitive: Dict[str, int]
    risk_by_repository: Dict[str, float]

class CICDCheckRequest(BaseModel):
    repository_id: int
    risk_threshold: float = Field(default=80.0, description="Risk score above which a build fails")
    fail_on_critical: bool = Field(default=True, description="Fail the build if any Critical vulnerability (Risk >= 90) is found")

class CICDCheckResponse(BaseModel):
    status: str  # 'PASS', 'WARNING', 'BLOCKED'
    reason: str
    violated_rules: List[str]
    critical_count: int
    high_count: int
    max_risk_score: float
    report: str

class RemediationResponse(BaseModel):
    finding_id: int
    package_name: str
    current_version: str
    recommended_version: str
    remediation_cmd: str
    patch_diff: str
    explanation: str

class RiskConfigRequest(BaseModel):
    cvss_weight: float = 10.0
    epss_weight: float = 1.0
    patch_lag_weight: float = 1.0
    depth_weight: float = 1.0
