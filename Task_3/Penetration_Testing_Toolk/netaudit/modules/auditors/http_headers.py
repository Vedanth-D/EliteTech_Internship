import socket
import ssl
from typing import Dict, Any, Tuple
from ..base import BaseModule
from ...core.graph import AssetGraph
from ...core.models import Finding, RiskLevel


class HTTPHeaderAuditor(BaseModule):
    """
    Audits HTTP and HTTPS services for missing security response headers
    and tech-stack information disclosures.
    """

    name = "http_header_auditor"
    description = "Inspects HTTP/HTTPS response headers for OWASP security header compliance."
    category = "audit"

    HTTP_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 9090]

    def __init__(self, options: Dict[str, Any] = None):
        super().__init__(options)

    def _fetch_headers(self, ip: str, port: int, use_ssl: bool) -> Tuple[Dict[str, str], str]:
        headers = {}
        raw_response = ""
        try:
            raw_sock = socket.create_connection((ip, port), timeout=2.0)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
            else:
                sock = raw_sock

            with sock:
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetAudit-SecurityScanner/1.0\r\nConnection: close\r\n\r\n"
                sock.sendall(req.encode("utf-8"))
                resp_bytes = sock.recv(4096)
                raw_response = resp_bytes.decode("utf-8", errors="ignore")

                # Parse status line and headers
                lines = raw_response.split("\r\n")
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
        except Exception:
            pass
        return headers, raw_response

    def run(self, graph: AssetGraph) -> None:
        for ip, host in graph.hosts.items():
            for port, service in host.services.items():
                if port in self.HTTP_PORTS or service.service_name in ("http", "https", "http-alt"):
                    use_ssl = port in (443, 8443) or service.ssl_enabled
                    headers, raw_resp = self._fetch_headers(ip, port, use_ssl)
                    if not headers:
                        continue

                    service.service_name = "https" if use_ssl else "http"
                    if "server" in headers:
                        service.banner = f"Server: {headers['server']}"

                    # Audit 1: Missing Strict-Transport-Security (HSTS) on HTTPS
                    if use_ssl and "strict-transport-security" not in headers:
                        service.findings.append(Finding(
                            id=f"MEDIUM-HTTP-HSTS-MISSING-{port}",
                            title="Missing Strict-Transport-Security (HSTS) Header",
                            severity=RiskLevel.MEDIUM,
                            description=f"HTTPS service on {ip}:{port} does not enforce HTTP Strict Transport Security (HSTS).",
                            remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to all HTTPS responses.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                            raw_evidence=f"Response headers on {ip}:{port} missing Strict-Transport-Security."
                        ))

                    # Audit 2: Missing Content-Security-Policy (CSP)
                    if "content-security-policy" not in headers:
                        service.findings.append(Finding(
                            id=f"LOW-HTTP-CSP-MISSING-{port}",
                            title="Missing Content-Security-Policy (CSP) Header",
                            severity=RiskLevel.LOW,
                            description=f"Web application on {ip}:{port} lacks a Content-Security-Policy header to prevent XSS and data injection attacks.",
                            remediation="Define a restrictive Content-Security-Policy header (e.g. default-src 'self').",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"]
                        ))

                    # Audit 3: Missing Anti-Clickjacking Header (X-Frame-Options)
                    if "x-frame-options" not in headers and "content-security-policy" not in headers:
                        service.findings.append(Finding(
                            id=f"LOW-HTTP-CLICKJACKING-{port}",
                            title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                            severity=RiskLevel.LOW,
                            description=f"Port {port} does not restrict framing via X-Frame-Options or frame-ancestors CSP directive.",
                            remediation="Configure web server to include 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"]
                        ))

                    # Audit 4: Missing X-Content-Type-Options
                    if "x-content-type-options" not in headers:
                        service.findings.append(Finding(
                            id=f"INFO-HTTP-NOSNIFF-{port}",
                            title="Missing X-Content-Type-Options Header",
                            severity=RiskLevel.INFO,
                            description=f"Web server on port {port} is missing 'X-Content-Type-Options: nosniff'.",
                            remediation="Add 'X-Content-Type-Options: nosniff' header to prevent MIME-sniffing vulnerabilities.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
                        ))

                    # Audit 5: Tech Disclosure Headers (X-Powered-By, Server)
                    disclosures = []
                    if "x-powered-by" in headers:
                        disclosures.append(f"X-Powered-By: {headers['x-powered-by']}")
                    if "server" in headers and any(char.isdigit() for char in headers['server']):
                        disclosures.append(f"Server: {headers['server']}")

                    if disclosures:
                        service.findings.append(Finding(
                            id=f"INFO-HTTP-HEADER-DISCLOSURE-{port}",
                            title="HTTP Technology Stack Information Disclosure",
                            severity=RiskLevel.INFO,
                            description=f"Web server discloses detailed technical stack information: {', '.join(disclosures)}",
                            remediation="Suppress or obfuscate Server and X-Powered-By headers in web server configurations.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Fingerprinting_Cheat_Sheet.html"],
                            raw_evidence="\n".join(disclosures)
                        ))
