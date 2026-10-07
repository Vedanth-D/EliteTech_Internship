import socket
import concurrent.futures
from typing import List, Dict, Any
from ..base import BaseModule
from ...core.graph import AssetGraph
from ...core.models import HostNode, ServiceNode


class HostSweepCollector(BaseModule):
    """
    Discovers active hosts and common service ports within authorized target networks.
    """

    name = "host_sweep"
    description = "Scans authorized subnets for active hosts and open infrastructure ports."
    category = "discovery"

    DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

    def __init__(self, target_ips: List[str], ports: List[int] = None, timeout: float = 1.0, max_threads: int = 20, options: Dict[str, Any] = None):
        super().__init__(options)
        self.target_ips = target_ips
        self.ports = ports or self.DEFAULT_PORTS
        self.timeout = timeout
        self.max_threads = max_threads

    def _check_port(self, ip: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                res = s.connect_ex((ip, port))
                return res == 0
        except Exception:
            return False

    def _audit_host(self, ip: str, graph: AssetGraph) -> None:
        # Scope validation is automatically triggered via graph.get_or_create_host
        try:
            host = graph.get_or_create_host(ip)
        except Exception as e:
            return  # Out of scope IP skipped

        open_found = False
        for port in self.ports:
            if self._check_port(ip, port):
                open_found = True
                service = ServiceNode(port=port, protocol="tcp")
                host.add_service(service)

        if open_found:
            host.is_up = True
            # Attempt reverse DNS lookup safely
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                host.hostname = hostname
            except Exception:
                pass

    def run(self, graph: AssetGraph) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._audit_host, ip, graph) for ip in self.target_ips]
            concurrent.futures.wait(futures)
