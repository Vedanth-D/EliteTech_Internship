from abc import ABC, abstractmethod
from typing import Dict, Any, List
from ..core.graph import AssetGraph


class BaseModule(ABC):
    """
    Abstract Base Class for all NetAudit plugins (Collectors, Auditors, Reporters).
    """

    name: str = "base_module"
    description: str = "Base plugin interface"
    author: str = "NetAudit Team"
    category: str = "general"  # discovery, audit, reporting

    def __init__(self, options: Dict[str, Any] = None):
        self.options = options or {}

    @abstractmethod
    def run(self, graph: AssetGraph) -> None:
        """
        Execute module logic against the shared AssetGraph context.
        Must respect scope validation when querying or modifying targets.
        """
        pass
