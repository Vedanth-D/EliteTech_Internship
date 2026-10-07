from typing import Dict, List, Optional, Any
from .models import HostNode, ServiceNode, Finding, RiskLevel
from .scope import ScopeGuard


class AssetGraph:
    """
    Graph-based data engine for tracking network assets, open services,
    correlated security findings, and topology.
    """

    def __init__(self, scope_guard: ScopeGuard):
        self.scope_guard = scope_guard
        self.hosts: Dict[str, HostNode] = {}

    def get_or_create_host(self, ip: str, hostname: Optional[str] = None) -> HostNode:
        """Retrieve existing host or initialize a new HostNode after scope validation."""
        self.scope_guard.validate(ip)
        if ip not in self.hosts:
            self.hosts[ip] = HostNode(ip=ip, hostname=hostname)
        elif hostname and not self.hosts[ip].hostname:
            self.hosts[ip].hostname = hostname
        return self.hosts[ip]

    def add_finding_to_host(self, ip: str, finding: Finding) -> None:
        host = self.get_or_create_host(ip)
        host.findings.append(finding)

    def add_finding_to_service(self, ip: str, port: int, finding: Finding) -> None:
        host = self.get_or_create_host(ip)
        if port in host.services:
            host.services[port].findings.append(finding)
        else:
            host.findings.append(finding)

    def get_all_findings(self) -> List[Dict[str, Any]]:
        all_findings = []
        for host in self.hosts.values():
            for f in host.findings:
                all_findings.append({**f.to_dict(), "target_ip": host.ip, "port": None})
            for service in host.services.values():
                for f in service.findings:
                    all_findings.append({**f.to_dict(), "target_ip": host.ip, "port": service.port})
        return all_findings

    def calculate_risk_score(self) -> float:
        """
        Calculate aggregate security risk score (0.0 to 100.0)
        based on weighted findings.
        """
        weights = {
            RiskLevel.CRITICAL: 25.0,
            RiskLevel.HIGH: 10.0,
            RiskLevel.MEDIUM: 4.0,
            RiskLevel.LOW: 1.0,
            RiskLevel.INFO: 0.0,
        }
        score = 0.0
        for item in self.get_all_findings():
            sev = RiskLevel(item["severity"])
            score += weights.get(sev, 0.0)
        return min(100.0, round(score, 1))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.calculate_risk_score(),
            "hosts": {ip: host.to_dict() for ip, host in self.hosts.items()}
        }
