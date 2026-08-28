import unittest
from backend.services.sbom_parser import SbomParser

class TestSbomParser(unittest.TestCase):
    def test_cyclonedx_parser(self):
        cyclonedx_mock = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {
                "component": {
                    "bom-ref": "app-root",
                    "name": "my-app",
                    "version": "1.0.0"
                }
            },
            "components": [
                {
                    "bom-ref": "lodash-purl",
                    "name": "lodash",
                    "version": "4.17.15",
                    "purl": "pkg:npm/lodash@4.17.15"
                }
            ],
            "dependencies": [
                {
                    "ref": "app-root",
                    "dependsOn": ["lodash-purl"]
                }
            ]
        }
        
        sbom_type, packages, edges = SbomParser.parse(cyclonedx_mock)
        self.assertEqual(sbom_type, "cyclonedx")
        
        package_names = [p["name"] for p in packages]
        self.assertIn("my-app", package_names)
        self.assertIn("lodash", package_names)
        
        self.assertIn(("my-app", "lodash"), edges)

    def test_spdx_parser(self):
        spdx_mock = {
            "spdxVersion": "SPDX-2.3",
            "name": "my-python-app",
            "packages": [
                {
                    "name": "requests",
                    "SPDXID": "SPDXRef-requests",
                    "versionInfo": "2.28.1"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": "SPDXRef-requests",
                    "relationshipType": "DEPENDS_ON"
                }
            ]
        }
        
        sbom_type, packages, edges = SbomParser.parse(spdx_mock)
        self.assertEqual(sbom_type, "spdx")
        
        package_names = [p["name"] for p in packages]
        self.assertIn("my-python-app", package_names)
        self.assertIn("requests", package_names)
        
        self.assertIn(("my-python-app", "requests"), edges)

if __name__ == "__main__":
    unittest.main()
