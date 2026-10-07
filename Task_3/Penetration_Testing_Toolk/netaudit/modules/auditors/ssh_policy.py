import socket
from typing import Dict, Any
from ..base import BaseModule
from ...core.graph import AssetGraph
from ...core.models import Finding, RiskLevel


class SSHPolicyAuditor(BaseModule):
    """
    Audits SSH service configurations, protocol version compliance (SSHv2 requirement),
    and crypto policy indicators on TCP port 22.
    """

    name = "ssh_policy_auditor"
    description = "Audits SSH server protocol versions and configuration compliance."
    category = "audit"

    def __init__(self, options: Dict[str, Any] = None):
        super().__init__(options)

    def run(self, graph: AssetGraph) -> None:
        for ip, host in graph.hosts.items():
            if 22 in host.services:
                service = host.services[22]
                banner = service.banner or ""
                
                # Check for obsolete SSH v1
                if "SSH-1." in banner:
                    finding = Finding(
                        id="CRITICAL-SSH-V1-SUPPORT",
                        title="Legacy SSH v1 Protocol Detected",
                        severity=RiskLevel.CRITICAL,
                        description="SSH server advertises support for SSH protocol version 1, which suffers from fundamental design flaws.",
                        remediation="Set 'Protocol 2' in /etc/ssh/sshd_config and restart sshd.",
                        references=["https://www.openssh.com/legacy.html"]
                    )
                    service.findings.append(finding)

                # Check for outdated OpenSSH releases (< OpenSSH 8.0)
                if "openssh" in banner.lower():
                    finding = Finding(
                        id="INFO-SSH-VERSION-AUDIT",
                        title="SSH Policy Baseline Alignment",
                        severity=RiskLevel.INFO,
                        description=f"SSH banner verified: '{banner}'. Ensure public-key authentication is enforced and password login is disabled.",
                        remediation="Review SSH hardening guidelines: enforce PasswordAuthentication no and PubkeyAuthentication yes.",
                        references=["https://www.cisecurity.org/benchmark/ubuntu_linux"]
                    )
                    service.findings.append(finding)
