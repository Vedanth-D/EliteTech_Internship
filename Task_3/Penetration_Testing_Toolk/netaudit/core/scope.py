import ipaddress
from typing import List, Union


class ScopeViolationError(Exception):
    """Raised when an IP or target is outside the authorized scope."""
    pass


class ScopeGuard:
    """
    Enforces authorization safety by restricting audit activities
    strictly to explicitly authorized CIDR blocks or IP addresses.
    """

    def __init__(self, allowed_targets: List[str]):
        self.networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for target in allowed_targets:
            try:
                # Handle host IPs or CIDR notation
                net = ipaddress.ip_network(target, strict=False)
                self.networks.append(net)
            except ValueError as e:
                raise ValueError(f"Invalid target IP/CIDR specification '{target}': {e}")

    def is_in_scope(self, ip_str: str) -> bool:
        """Check if a given IP address string falls within any allowed network."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(ip_obj in net for net in self.networks)
        except ValueError:
            return False

    def validate(self, ip_str: str) -> None:
        """Raise ScopeViolationError if the target IP is out of authorized scope."""
        if not self.is_in_scope(ip_str):
            raise ScopeViolationError(
                f"Target IP '{ip_str}' is outside of authorized scope networks: "
                f"{[str(n) for n in self.networks]}"
            )
