import re
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models.database import VulnerabilityDb

class VulnIntelligenceService:
    @staticmethod
    def parse_version(version_str: str) -> List[int]:
        """Parses semantic version string into list of integers for comparison."""
        # Extract digits, ignore prefixes like ^ or ~ or v
        cleaned = re.sub(r'^[^\d]+', '', version_str)
        # Split on dot and clean any trailing non-numeric parts (e.g. -beta.1 -> just numeric)
        parts = []
        for part in cleaned.split('.'):
            # Extract only leading digits of the part
            match = re.match(r'^\d+', part)
            if match:
                parts.append(int(match.group()))
            else:
                parts.append(0)
        # Ensure we return at least 3 parts
        while len(parts) < 3:
            parts.append(0)
        return parts[:3]

    @classmethod
    def version_satisfies(cls, version: str, affected_range: str) -> bool:
        """
        Check if package version satisfies the affected range.
        Handles ranges like:
          "<4.17.21"
          ">=3.0.0,<3.2.1"
          "<=1.2.3"
        """
        if not affected_range:
            return False
            
        version_parts = cls.parse_version(version)
        
        # Split on comma if we have compound ranges (e.g. >=3.0.0,<3.2.1)
        sub_conditions = affected_range.split(",")
        
        for condition in sub_conditions:
            condition = condition.strip()
            # Parse operator and version
            match = re.match(r'^([<>=]+)\s*(.*)$', condition)
            if not match:
                continue
            
            operator, ref_version = match.groups()
            ref_parts = cls.parse_version(ref_version)
            
            if operator == "<":
                if not (version_parts < ref_parts):
                    return False
            elif operator == "<=":
                if not (version_parts <= ref_parts):
                    return False
            elif operator == ">":
                if not (version_parts > ref_parts):
                    return False
            elif operator == ">=":
                if not (version_parts >= ref_parts):
                    return False
            elif operator == "==":
                if not (version_parts == ref_parts):
                    return False
                    
        return True

    @classmethod
    def scan_packages(cls, db: Session, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Matches a list of packages against known vulnerabilities in VulnerabilityDb.
        Returns:
            List of matched findings as dictionaries
        """
        findings = []
        
        for pkg in packages:
            name = pkg["name"]
            version = pkg["version"]
            
            # Query db for vulnerabilities affecting this package name
            vulns = db.query(VulnerabilityDb).filter(VulnerabilityDb.package_name == name).all()
            
            for vuln in vulns:
                if cls.version_satisfies(version, vuln.affected_range):
                    # Found a vulnerability match!
                    findings.append({
                        "package_name": name,
                        "package_version": version,
                        "cve_id": vuln.cve_id,
                        "cvss": vuln.cvss,
                        "epss": vuln.epss,
                        "exploit_available": vuln.exploit_available,
                        "depth": pkg.get("depth", 1),
                        "fixed_version": vuln.fixed_version,
                        "title": vuln.title,
                        "description": vuln.description,
                        "dependency_path": pkg.get("path_from_root", [name]),
                        "in_degree": pkg.get("in_degree", 0),
                        "out_degree": pkg.get("out_degree", 0),
                        "dependents_count": pkg.get("dependents_count", 0)
                    })
                    
        return findings
