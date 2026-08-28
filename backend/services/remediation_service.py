from typing import Dict, Any

class RemediationService:
    @classmethod
    def generate_remediation(
        cls, 
        finding_id: int,
        package_name: str, 
        current_version: str, 
        fixed_version: str, 
        pkg_type: str,
        cve_id: str,
        dependents_count: int
    ) -> Dict[str, Any]:
        """
        Generates remediation recommendation package-manager updates,
        JSON changes, git diff files, and risk-mitigation explanations.
        """
        # Define command and config file name based on package type
        if pkg_type == "pip":
            config_file = "requirements.txt"
            remediation_cmd = f"pip install {package_name}=={fixed_version}"
            
            package_file_old = f"{package_name}=={current_version}"
            package_file_new = f"{package_name}=={fixed_version}"
            
            git_diff = (
                f"diff --git a/requirements.txt b/requirements.txt\n"
                f"index e69de29..d95f3b2 100\n"
                f"--- a/requirements.txt\n"
                f"+++ b/requirements.txt\n"
                f"@@ -1,1 +1,1 @@\n"
                f"-{package_file_old}\n"
                f"+{package_file_new}\n"
            )
        else:  # npm
            config_file = "package.json"
            remediation_cmd = f"npm install {package_name}@{fixed_version} --save-exact"
            
            package_file_old = f'"{package_name}": "^{current_version}"'
            package_file_new = f'"{package_name}": "^{fixed_version}"'
            
            git_diff = (
                f"diff --git a/package.json b/package.json\n"
                f"index a1b2c3d..e4f5g6h 100644\n"
                f"--- a/package.json\n"
                f"+++ b/package.json\n"
                f"@@ -12,3 +12,3 @@\n"
                f"   \"dependencies\": {{\n"
                f"-    \"{package_name}\": \"^{current_version}\",\n"
                f"+    \"{package_name}\": \"^{fixed_version}\",\n"
                f"   }}\n"
            )

        # Generate custom explanation
        if dependents_count > 0:
            explanation = (
                f"Upgrading {package_name} from {current_version} to {fixed_version} resolves "
                f"vulnerability {cve_id}. This is a critical shared component in your dependency graph; "
                f"updating it secures {dependents_count} dependents that transitively rely on this library."
            )
        else:
            explanation = (
                f"Upgrading {package_name} from {current_version} to {fixed_version} resolves "
                f"vulnerability {cve_id} in your direct codebase dependencies."
            )

        return {
            "finding_id": finding_id,
            "package_name": package_name,
            "current_version": current_version,
            "recommended_version": fixed_version,
            "remediation_cmd": remediation_cmd,
            "config_file": config_file,
            "package_file_old": package_file_old,
            "package_file_new": package_file_new,
            "patch_diff": git_diff,
            "explanation": explanation
        }
