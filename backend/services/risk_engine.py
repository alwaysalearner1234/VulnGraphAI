import math
from typing import Dict, Any, List
from backend.services.vuln_intelligence import VulnIntelligenceService

class RiskEngine:
    # Configurable weights in risk scoring formula
    CVSS_SCALE = 10.0
    MIN_EPSS_FACTOR = 0.15 # Prevents risk from bottoming out to 0 for low EPSS
    MAX_PATCH_LAG_FACTOR = 1.5
    
    cvss_weight = 10.0
    epss_weight = 1.0
    patch_lag_weight = 1.0
    depth_weight = 1.0

    @classmethod
    def set_weights(cls, cvss: float, epss: float, patch_lag: float, depth: float):
        cls.cvss_weight = cvss
        cls.epss_weight = epss
        cls.patch_lag_weight = patch_lag
        cls.depth_weight = depth

    @classmethod
    def get_weights(cls) -> Dict[str, float]:
        return {
            "cvss_weight": cls.cvss_weight,
            "epss_weight": cls.epss_weight,
            "patch_lag_weight": cls.patch_lag_weight,
            "depth_weight": cls.depth_weight
        }

    @classmethod
    def calculate_version_distance(cls, installed: str, fixed: str) -> float:
        """
        Calculates a distance factor between the installed and fixed versions.
        For example:
        - Major version difference: high distance (1.0)
        - Minor version difference: medium distance (0.3)
        - Patch version difference: low distance (0.05 per patch)
        """
        if not installed or not fixed:
            return 0.0
            
        try:
            inst_parts = VulnIntelligenceService.parse_version(installed)
            fix_parts = VulnIntelligenceService.parse_version(fixed)
            
            # If installed is greater or equal to fixed, distance is 0
            if inst_parts >= fix_parts:
                return 0.0
                
            major_diff = max(0, fix_parts[0] - inst_parts[0])
            minor_diff = max(0, fix_parts[1] - inst_parts[1]) if major_diff == 0 else fix_parts[1]
            patch_diff = max(0, fix_parts[2] - inst_parts[2]) if (major_diff == 0 and minor_diff == 0) else fix_parts[2]
            
            distance = (major_diff * 1.0) + (minor_diff * 0.25) + (patch_diff * 0.05)
            return min(cls.MAX_PATCH_LAG_FACTOR, distance)
        except Exception:
            return 0.5  # default fallback distance

    @classmethod
    def calculate_risk_score(
        cls, 
        cvss: float, 
        epss: float, 
        depth: int, 
        installed_version: str, 
        fixed_version: str
    ) -> Dict[str, Any]:
        """
        Computes the context-aware risk score:
        Risk Score = CVSS * 10 * (MIN_EPSS_FACTOR + (1 - MIN_EPSS_FACTOR) * EPSS) * (1 + Patch Lag) * (1 / sqrt(Depth))
        Normalizes to 0-100.
        """
        # Ensure values are within bounds
        cvss = max(0.0, min(10.0, cvss))
        epss = max(0.0, min(1.0, epss))
        depth = max(1, depth)
        
        # Calculate Patch Lag
        patch_lag = cls.calculate_version_distance(installed_version, fixed_version)
        
        # EPSS scaling factor
        epss_factor = cls.MIN_EPSS_FACTOR + (1.0 - cls.MIN_EPSS_FACTOR) * epss
        
        # Depth scaling factor
        depth_factor = 1.0 / math.sqrt(depth)
        
        # Formula execution
        raw_score = (cvss * cls.cvss_weight) * (epss_factor * cls.epss_weight) * (1.0 + patch_lag * cls.patch_lag_weight) * (depth_factor ** cls.depth_weight)
        
        # Normalize and cap to 0-100 range
        risk_score = round(max(0.0, min(100.0, raw_score)), 1)
        
        # Categorize
        if risk_score >= 90.0:
            category = "CRITICAL"
        elif risk_score >= 70.0:
            category = "HIGH"
        elif risk_score >= 40.0:
            category = "MEDIUM"
        else:
            category = "LOW"
            
        # Explanatory factors
        explanations = []
        if depth == 1:
            explanations.append("Direct dependency: highest exploit reachability (+0% depth mitigation).")
        else:
            reduction = round((1.0 - depth_factor) * 100)
            explanations.append(f"Transitive dependency at depth {depth}: risk mitigated by {reduction}% due to traversal distance.")
            
        if epss > 0.5:
            explanations.append(f"High exploit probability (EPSS = {round(epss * 100)}%): active threat in the wild.")
        else:
            explanations.append(f"Low exploit probability (EPSS = {round(epss * 100)}%): fewer active wild threats reported.")
            
        if patch_lag > 0.5:
            explanations.append(f"Significant version lag: {installed_version} is far behind fixed version {fixed_version}.")
        elif patch_lag > 0:
            explanations.append(f"Minor version lag: update available to version {fixed_version}.")
        else:
            explanations.append("Up-to-date or no known fix version mapped.")
            
        return {
            "score": risk_score,
            "category": category,
            "patch_lag": round(patch_lag, 2),
            "depth_factor": round(depth_factor, 3),
            "epss_factor": round(epss_factor, 3),
            "explanations": explanations
        }
