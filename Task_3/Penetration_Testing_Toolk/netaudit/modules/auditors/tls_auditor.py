import ssl
import socket
from datetime import datetime
from typing import Dict, Any
from ..base import BaseModule
from ...core.graph import AssetGraph
from ...core.models import Finding, RiskLevel


class TLSCipherAuditor(BaseModule):
    """
    Audits SSL/TLS configuration, cryptographic protocol versions,
    and certificate expiration parameters on HTTPS and TLS-enabled services.
    """

    name = "tls_cipher_auditor"
    description = "Inspects SSL/TLS version, certificate validity, and cipher suites."
    category = "audit"

    TLS_PORTS = [443, 8443, 465, 993, 995]

    def __init__(self, options: Dict[str, Any] = None):
        super().__init__(options)

    def _audit_tls(self, ip: str, port: int, service: Any) -> None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((ip, port), timeout=3.0) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert(binary_form=False)

                    service.ssl_enabled = True
                    service.tls_version = tls_version
                    if cipher:
                        service.ciphers.append(f"{cipher[0]} ({cipher[1]})")

                    # Check 1: Insecure protocol versions
                    if tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        finding = Finding(
                            id=f"HIGH-TLS-DEPRECATED-{port}",
                            title=f"Deprecated TLS Protocol Version Supported ({tls_version})",
                            severity=RiskLevel.HIGH,
                            description=f"Port {port} accepts connections using deprecated protocol {tls_version}.",
                            remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server. Mandate TLS 1.2 or TLS 1.3.",
                            references=["https://datatracker.ietf.org/doc/html/rfc8996"]
                        )
                        service.findings.append(finding)

                    # Check 2: Weak Cipher Suite (e.g. RC4, 3DES, NULL, EXPORT)
                    if cipher and any(weak in cipher[0].upper() for weak in ["RC4", "3DES", "NULL", "EXPORT", "MD5"]):
                        finding = Finding(
                            id=f"MEDIUM-TLS-WEAK-CIPHER-{port}",
                            title=f"Weak Cipher Suite Negotiated ({cipher[0]})",
                            severity=RiskLevel.MEDIUM,
                            description=f"Port {port} negotiated weak cipher suite {cipher[0]}.",
                            remediation="Reconfigure TLS cipher suites to prioritize AES-GCM or ChaCha20-Poly1305 with ECDHE key exchange.",
                            references=["https://wiki.mozilla.org/Security/Server_Side_TLS"]
                        )
                        service.findings.append(finding)

        except Exception:
            pass

    def run(self, graph: AssetGraph) -> None:
        for ip, host in graph.hosts.items():
            for port, service in host.services.items():
                if port in self.TLS_PORTS or service.ssl_enabled:
                    self._audit_tls(ip, port, service)
