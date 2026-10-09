import unittest

from drost_ai.catalog import CATALOG, TOOL_GROUPS, category_counts
from drost_ai.coverage import REFERENCE_FUNCTIONS, reference_coverage, uncovered_reference_functions
from drost_ai.workflows import WORKFLOW_STEPS


class CatalogTests(unittest.TestCase):
    def test_catalog_is_large_and_unique(self):
        names = [spec.name for spec in CATALOG]
        self.assertGreaterEqual(len(names), 100)
        self.assertEqual(len(names), len(set(names)))

    def test_every_major_category_has_tools(self):
        counts = category_counts()
        self.assertEqual(set(counts), set(TOOL_GROUPS))
        self.assertTrue(all(count > 0 for count in counts.values()))

    def test_names_are_drost_owned(self):
        self.assertTrue(all(spec.name.startswith("drost_") for spec in CATALOG))
        self.assertIn("drost_jq", {spec.name for spec in CATALOG})

    def test_reference_functional_inventory_is_accounted_for(self):
        self.assertEqual(uncovered_reference_functions(), [])
        self.assertEqual(len(reference_coverage()), len(REFERENCE_FUNCTIONS))

    def test_workflow_steps_reference_real_catalog_tools(self):
        names = {spec.name for spec in CATALOG}
        names.update(
            {
                "drost_openapi_inspect",
                "drost_http_request",
                "drost_graphql_request",
                "drost_jwt_decode",
                "drost_scan_summary",
                "drost_finding_report",
            }
        )
        referenced = {step["tool"] for steps in WORKFLOW_STEPS.values() for step in steps}
        self.assertEqual(sorted(referenced - names), [])


if __name__ == "__main__":
    unittest.main()
