import logging
from typing import List, Type, Dict, Any
from .graph import AssetGraph
from ..modules.base import BaseModule

logger = logging.getLogger("netaudit.engine")


class AuditEngine:
    """
    Orchestrates execution of audit and discovery plugins against the AssetGraph.
    """

    def __init__(self, graph: AssetGraph):
        self.graph = graph
        self.modules: List[BaseModule] = []

    def register_module(self, module_instance: BaseModule) -> None:
        """Register an instantiated module into the pipeline."""
        self.modules.append(module_instance)
        logger.info(f"Registered module: {module_instance.name} ({module_instance.category})")

    def run_all(self) -> None:
        """Run all registered modules in order of registration."""
        logger.info(f"Starting audit execution with {len(self.modules)} modules...")
        for mod in self.modules:
            logger.info(f"Executing module [{mod.category.upper()}] {mod.name}...")
            try:
                mod.run(self.graph)
            except Exception as e:
                logger.error(f"Error running module '{mod.name}': {e}", exc_info=True)
        logger.info("Audit execution complete.")
