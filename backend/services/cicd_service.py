from typing import List, Dict, Any
from backend.models.database import Finding

class CicdService:
    @classmethod
    def evaluate_build(
        cls, 
        findings: List[Finding], 
        risk_threshold: float, 
        fail_on_critical: bool
    ) -> Dict[str, Any]:
        """
        Evaluates scan findings against CI/CD rule thresholds.
        Returns:
            Dict containing: status (PASS/BLOCKED), reason, violated_rules, critical_count, high_count, max_risk_score, report
        """
        violated_rules = []
        blocked = False
        max_risk_score = 0.0
        critical_count = 0
        high_count = 0
        
        violating_findings = []
        
        for f in findings:
            if f.status != "active":
                continue
                
            risk = f.calculated_risk
            priority = f.ml_priority
            
            if risk > max_risk_score:
                max_risk_score = risk
                
            if priority == "CRITICAL" or risk >= 90.0:
                critical_count += 1
            elif priority == "HIGH" or risk >= 70.0:
                high_count += 1
                
            # Rule 1: Risk threshold
            if risk >= risk_threshold:
                blocked = True
                rule_str = f"Finding {f.cve_id} on {f.package_name}@{f.package_version} risk score ({risk}) exceeds configured threshold ({risk_threshold})"
                if rule_str not in violated_rules:
                    violated_rules.append(rule_str)
                violating_findings.append(f)
                    
            # Rule 2: Fail on Critical
            if fail_on_critical and (priority == "CRITICAL" or risk >= 90.0):
                blocked = True
                rule_str = f"Critical vulnerability gate triggered: {f.cve_id} on {f.package_name}@{f.package_version} is classified as CRITICAL"
                if rule_str not in violated_rules:
                    violated_rules.append(rule_str)
                violating_findings.append(f)

        status = "BLOCKED" if blocked else ("WARNING" if (critical_count + high_count) > 0 else "PASS")
        
        if blocked:
            reason = f"Build BLOCKED by VulnGraph AI. Found {len(violated_rules)} security gate violations."
        elif status == "WARNING":
            reason = f"Build PASSED with warnings. Found {critical_count} critical and {high_count} high vulnerabilities below threshold."
        else:
            reason = "Build PASSED. No security gate violations detected."

        # Compile console report string
        report_lines = []
        report_lines.append("=========================================================")
        report_lines.append("                VULNGRAPH AI SECURITY GATE               ")
        report_lines.append("=========================================================")
        report_lines.append(f"Status:          {status}")
        report_lines.append(f"Max Risk Score:  {max_risk_score} / 100")
        report_lines.append(f"Critical Findings: {critical_count}")
        report_lines.append(f"High Findings:     {high_count}")
        report_lines.append(f"Threshold Limit:   {risk_threshold}")
        report_lines.append(f"Fail On Critical:  {'Enabled' if fail_on_critical else 'Disabled'}")
        report_lines.append("---------------------------------------------------------")
        
        if violated_rules:
            report_lines.append("Violating Findings:")
            for idx, f in enumerate(violating_findings, 1):
                report_lines.append(f"  {idx}. {f.cve_id} - {f.package_name}@{f.package_version}")
                report_lines.append(f"     Risk Score: {f.calculated_risk} | ML Priority: {f.ml_priority}")
                report_lines.append(f"     Remediation: {f.remediation_cmd}")
            report_lines.append("---------------------------------------------------------")
            report_lines.append("Gate Verdict:")
            for rule in violated_rules:
                report_lines.append(f"  [FAIL] {rule}")
        else:
            report_lines.append("Gate Verdict:")
            report_lines.append("  [PASS] All dependency risks conform to configuration threshold rules.")
            
        report_lines.append("=========================================================")
        report = "\n".join(report_lines)

        return {
            "status": status,
            "reason": reason,
            "violated_rules": violated_rules,
            "critical_count": critical_count,
            "high_count": high_count,
            "max_risk_score": max_risk_score,
            "report": report
        }
