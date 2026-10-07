import socket
from typing import Dict, Any
from ..base import BaseModule
from ...core.graph import AssetGraph
from ...core.models import Finding, RiskLevel


class SMBPolicyAuditor(BaseModule):
    """
    Audits Server Message Block (SMB) service exposure on TCP ports 445 and 139.
    Evaluates risk of unencrypted SMB traffic, SMBv1 exposure, and missing message signing.
    """

    name = "smb_policy_auditor"
    description = "Audits SMB exposure, dialect requirements, and signing policies."
    category = "audit"

    SMB_PORTS = [139, 445]

    def __init__(self, options: Dict[str, Any] = None):
        super().__init__(options)

    def _probe_smb(self, ip: str, port: int) -> Dict[str, Any]:
        result = {"is_open": False, "banner": None, "smbv1_indicated": False}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                if s.connect_ex((ip, port)) == 0:
                    result["is_open"] = True
                    
                    # Send NetBIOS / SMB Protocol Negotiation Header (SMBv1/v2 probe)
                    # SMB Negotiate Protocol Request (probes SMBv1 / NT LM 0.12)
                    smb_negotiate_pkt = (
                        b"\x00\x00\x00\x54"  # NetBIOS Session Header
                        b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
                        b"\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"
                        b"\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"
                    )
                    s.sendall(smb_negotiate_pkt)
                    resp = s.recv(1024)
                    if resp and len(resp) > 4:
                        if b"\xffSMB" in resp:
                            result["smbv1_indicated"] = True
                            result["banner"] = "SMBv1 Dialect Accepted"
                        elif b"\xfeSMB" in resp:
                            result["banner"] = "SMBv2/v3 Dialect Negotiated"
        except Exception:
            pass
        return result

    def run(self, graph: AssetGraph) -> None:
        for ip, host in graph.hosts.items():
            for port in self.SMB_PORTS:
                if port in host.services:
                    service = host.services[port]
                    service.service_name = "microsoft-ds" if port == 445 else "netbios-ssn"
                    
                    smb_info = self._probe_smb(ip, port)
                    if smb_info["banner"]:
                        service.banner = smb_info["banner"]

                    # Audit Finding 1: Unrestricted SMB Service Exposure
                    f_exposure = Finding(
                        id=f"MEDIUM-SMB-EXPOSURE-{port}",
                        title=f"Direct SMB Network Service Exposure on Port {port}",
                        severity=RiskLevel.MEDIUM,
                        description=(
                            f"Server Message Block (SMB) service is accessible on {ip}:{port}. "
                            "Exposing SMB to untrusted network segments increases attack surface for lateral movement and credential theft."
                        ),
                        remediation=(
                            "Restrict SMB access via firewall rules (block TCP ports 139 and 445 from external networks). "
                            "Enforce network segmentation for management and file sharing interfaces."
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Network_Security_Cheat_Sheet.html"
                        ],
                        raw_evidence=f"Service active on {ip}:{port}. Protocol response: {smb_info.get('banner') or 'Connected'}"
                    )
                    service.findings.append(f_exposure)

                    # Audit Finding 2: Legacy SMBv1 Dialect Risk
                    if smb_info["smbv1_indicated"]:
                        f_smbv1 = Finding(
                            id="CRITICAL-SMBV1-ENABLED",
                            title="Legacy SMBv1 Protocol Enabled",
                            severity=RiskLevel.CRITICAL,
                            description=(
                                "The SMB service indicates support for the legacy SMBv1 protocol. "
                                "SMBv1 contains severe architectural vulnerabilities (e.g., EternalBlue / CVE-2017-0144) "
                                "and lacks modern cryptographic protections."
                            ),
                            remediation=(
                                "Disable SMBv1 immediately. On Windows PowerShell, execute:\n"
                                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                            ),
                            references=[
                                "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
                            ],
                            raw_evidence="Server negotiated SMBv1 dialect response packet."
                        )
                        service.findings.append(f_smbv1)

                    # Audit Finding 3: SMB Message Signing Audit Recommendation
                    f_signing = Finding(
                        id="LOW-SMB-SIGNING-CHECK",
                        title="SMB Security Policy & Message Signing Hardening Requirement",
                        severity=RiskLevel.LOW,
                        description=(
                            "SMB communication should enforce required SMB Message Signing to prevent "
                            "man-in-the-middle (MitM) packet manipulation and relay attacks."
                        ),
                        remediation=(
                            "Enforce SMB Signing in Group Policy or registry:\n"
                            "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
                        ),
                        references=[
                            "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-of-smb-signing"
                        ]
                    )
                    service.findings.append(f_signing)
