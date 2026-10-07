import socket
from typing import Dict, Any
from ..base import BaseModule
from ...core.graph import AssetGraph
from ...core.models import Finding, RiskLevel


class ServiceBannerAuditor(BaseModule):
    """
    Inspects service banners on open TCP ports to infer software versions
    and identify verbose banner information disclosures.
    """

    name = "service_banner_auditor"
    description = "Audits service header disclosures and version information."
    category = "audit"

    KNOWN_SERVICES = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        5432: "postgresql",
        8080: "http-alt"
    }

    def __init__(self, timeout: float = 2.0, options: Dict[str, Any] = None):
        super().__init__(options)
        self.timeout = timeout

    def _grab_banner(self, ip: str, port: int) -> str:
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                # Trigger HTTP response for web ports
                if port in (80, 8080, 8443):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                
                response = s.recv(1024)
                banner = response.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
        return banner

    def run(self, graph: AssetGraph) -> None:
        for ip, host in graph.hosts.items():
            for port, service in host.services.items():
                if port in self.KNOWN_SERVICES and service.service_name == "unknown":
                    service.service_name = self.KNOWN_SERVICES[port]

                banner = self._grab_banner(ip, port)
                if banner:
                    service.banner = banner[:200]  # Truncate clean string
                    
                    # Audit for verbose banner disclosure
                    if any(ver in banner.lower() for ver in ["ubuntu", "debian", "openssh", "apache", "nginx"]):
                        finding = Finding(
                            id=f"INFO-BANNER-{port}",
                            title=f"Verbose Service Banner Disclosed on Port {port}",
                            severity=RiskLevel.LOW,
                            description=f"Service on port {port} disclosed internal version details: '{service.banner}'",
                            remediation="Configure server configuration files to suppress detailed software version banners.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Fingerprinting_Cheat_Sheet.html"]
                        )
                        service.findings.append(finding)
