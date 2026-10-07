import unittest
import os
from netaudit.core.models import ServiceNode, Finding
from netaudit.core.scope import ScopeGuard
from netaudit.core.graph import AssetGraph
from netaudit.core.engine import AuditEngine
from netaudit.modules.auditors.banner_grabber import ServiceBannerAuditor
from netaudit.modules.reporting.markdown_reporter import MarkdownReportGenerator


class TestEnginePipeline(unittest.TestCase):

    def test_pipeline_execution(self):
        scope = ScopeGuard(["127.0.0.1"])
        graph = AssetGraph(scope)
        engine = AuditEngine(graph)

        host = graph.get_or_create_host("127.0.0.1")
        host.add_service(ServiceNode(port=80, service_name="http", banner="Ubuntu Apache/2.4.41"))

        md_path = "test_out.md"
        engine.register_module(ServiceBannerAuditor())
        engine.register_module(MarkdownReportGenerator(output_path=md_path))
        engine.run_all()

        self.assertTrue(os.path.exists(md_path))
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("Executive Security Audit", content)

        if os.path.exists(md_path):
            os.remove(md_path)


if __name__ == "__main__":
    unittest.main()
