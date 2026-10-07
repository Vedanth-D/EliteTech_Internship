import unittest
from netaudit.core.scope import ScopeGuard
from netaudit.core.graph import AssetGraph
from netaudit.core.models import Finding, RiskLevel, ServiceNode


class TestAssetGraph(unittest.TestCase):

    def setUp(self):
        self.scope = ScopeGuard(["127.0.0.1"])
        self.graph = AssetGraph(self.scope)

    def test_add_host_and_service(self):
        host = self.graph.get_or_create_host("127.0.0.1", hostname="localhost")
        self.assertEqual(host.ip, "127.0.0.1")
        self.assertEqual(host.hostname, "localhost")

        srv = ServiceNode(port=80, service_name="http")
        host.add_service(srv)
        self.assertIn(80, host.services)

    def test_risk_calculation(self):
        finding1 = Finding(
            id="TEST-1",
            title="Critical Vuln",
            severity=RiskLevel.CRITICAL,
            description="Test",
            remediation="Patch"
        )
        self.graph.add_finding_to_host("127.0.0.1", finding1)
        score = self.graph.calculate_risk_score()
        self.assertEqual(score, 25.0)


if __name__ == "__main__":
    unittest.main()
