import json
from typing import Dict, List, Tuple, Any, Optional

class SbomParser:
    @staticmethod
    def detect_format(content: Dict[str, Any]) -> str:
        """Detect if the SBOM is CycloneDX or SPDX."""
        if content.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        elif "spdxVersion" in content:
            return "spdx"
        else:
            # Fallback heuristic
            if "components" in content or "metadata" in content:
                return "cyclonedx"
            elif "packages" in content or "relationships" in content:
                return "spdx"
        raise ValueError("Unsupported or invalid SBOM format. Must be CycloneDX or SPDX JSON.")

    @classmethod
    def parse(cls, content: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]], List[Tuple[str, str]]]:
        """
        Parses SBOM JSON content.
        Returns:
            Tuple of (sbom_type, list of packages, list of dependency edges)
            where packages is a list of dicts: {"name": str, "version": str, "type": str}
            and edges is a list of tuples: (parent_package_name, child_package_name)
        """
        sbom_type = cls.detect_format(content)
        if sbom_type == "cyclonedx":
            return "cyclonedx", *cls._parse_cyclonedx(content)
        else:
            return "spdx", *cls._parse_spdx(content)

    @classmethod
    def _parse_cyclonedx(cls, content: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
        packages = []
        edges = []
        
        # Determine ecosystem from metadata tools or package purls
        ecosystem = "npm"  # Default
        metadata = content.get("metadata", {})
        root_component = metadata.get("component", {})
        root_name = root_component.get("name", "app")
        
        # Add root component to packages if exists
        root_pkg_info = None
        if root_component:
            purl = root_component.get("purl", "")
            if "pypi" in purl or "pip" in purl:
                ecosystem = "pip"
            root_pkg_info = {
                "name": root_name,
                "version": root_component.get("version", "1.0.0"),
                "type": ecosystem
            }
            packages.append(root_pkg_info)

        # Ingest components
        components = content.get("components", [])
        ref_to_name = {} # CycloneDX uses ref to link. Often it is the purl or a custom ID.
        if root_component:
            root_ref = root_component.get("bom-ref") or root_component.get("purl") or root_name
            ref_to_name[root_ref] = root_name

        for comp in components:
            name = comp.get("name")
            version = comp.get("version", "0.0.0")
            bom_ref = comp.get("bom-ref") or comp.get("purl") or name
            purl = comp.get("purl", "")
            
            comp_type = "npm"
            if "pypi" in purl or "pip" in purl:
                comp_type = "pip"
                ecosystem = "pip"  # upgrade default if we see pypi

            ref_to_name[bom_ref] = name
            packages.append({
                "name": name,
                "version": version,
                "type": comp_type
            })

        # Parse dependencies relationships
        dependencies = content.get("dependencies", [])
        for dep in dependencies:
            parent_ref = dep.get("ref")
            depends_on = dep.get("dependsOn", [])
            
            parent_name = ref_to_name.get(parent_ref, parent_ref)
            for child_ref in depends_on:
                child_name = ref_to_name.get(child_ref, child_ref)
                if parent_name and child_name:
                    edges.append((parent_name, child_name))
                    
        # Update ecosystem type for root if we detected pip elsewhere
        if root_pkg_info and ecosystem == "pip":
            root_pkg_info["type"] = "pip"
            for p in packages:
                if p["name"] != root_name:
                    p["type"] = "pip"

        return packages, edges

    @classmethod
    def _parse_spdx(cls, content: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
        packages = []
        edges = []
        
        spdx_id_to_name = {}
        document_name = content.get("name", "app")
        spdx_id_to_name["SPDXRef-DOCUMENT"] = document_name
        
        # Read packages
        spdx_packages = content.get("packages", [])
        ecosystem = "npm" # Default
        
        # Check if we can find project name from describes
        describes = content.get("documentDescribes", [])
        
        for pkg in spdx_packages:
            name = pkg.get("name")
            version = pkg.get("versionInfo", "0.0.0")
            spdx_id = pkg.get("SPDXID")
            
            # Infer package type
            pkg_type = "npm"
            for ext in pkg.get("externalRefs", []):
                loc = ext.get("referenceLocator", "")
                if "pypi" in loc or "pip" in loc:
                    pkg_type = "pip"
                    ecosystem = "pip"
            
            spdx_id_to_name[spdx_id] = name
            packages.append({
                "name": name,
                "version": version,
                "type": pkg_type
            })
            
        # Add root document describing package if not explicitly in package list
        if describes:
            for desc_id in describes:
                if desc_id not in spdx_id_to_name:
                    spdx_id_to_name[desc_id] = document_name
                    
        # Ensure root document package is present in packages
        if not any(pkg["name"] == document_name for pkg in packages):
            packages.append({
                "name": document_name,
                "version": "1.0.0",
                "type": ecosystem
            })

        # Read relationships
        relationships = content.get("relationships", [])
        for rel in relationships:
            parent_id = rel.get("spdxElementId")
            child_id = rel.get("relatedSpdxElement")
            rel_type = rel.get("relationshipType")
            
            # We look for DEPENDS_ON relationship
            if rel_type in ("DEPENDS_ON", "DEPENDENCY_OF"):
                parent_name = spdx_id_to_name.get(parent_id)
                child_name = spdx_id_to_name.get(child_id)
                
                if parent_name and child_name:
                    if rel_type == "DEPENDS_ON":
                        edges.append((parent_name, child_name))
                    else:  # DEPENDENCY_OF means child is a dependency of parent
                        edges.append((child_name, parent_name))

        return packages, edges
