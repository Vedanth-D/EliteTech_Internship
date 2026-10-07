from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str
    title: str
    severity: RiskLevel
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    raw_evidence: Optional[Any] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "raw_evidence": str(self.raw_evidence) if self.raw_evidence else None,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ServiceNode:
    port: int
    protocol: str = "tcp"
    service_name: str = "unknown"
    banner: Optional[str] = None
    ssl_enabled: bool = False
    tls_version: Optional[str] = None
    ciphers: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "banner": self.banner,
            "ssl_enabled": self.ssl_enabled,
            "tls_version": self.tls_version,
            "ciphers": self.ciphers,
            "findings": [f.to_dict() for f in self.findings]
        }


@dataclass
class HostNode:
    ip: str
    hostname: Optional[str] = None
    is_up: bool = True
    services: Dict[int, ServiceNode] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def add_service(self, service: ServiceNode) -> ServiceNode:
        self.services[service.port] = service
        return service

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_up": self.is_up,
            "services": {port: s.to_dict() for port, s in self.services.items()},
            "findings": [f.to_dict() for f in self.findings]
        }
