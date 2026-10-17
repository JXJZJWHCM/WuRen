import json
import os
from datetime import datetime
from typing import Dict, Any, List
from loguru import logger

class ReconAggregator:
    """
    Aggregates reconnaissance results from active and passive modules.
    """

    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def aggregate(self, target: str, active_results: Dict[str, Any], passive_results: Dict[str, Any]) -> str:
        """
        Merge and save reconnaissance data.

        Args:
            target (str): The target identifier.
            active_results (Dict[str, Any]): Results from ActiveRecon.
            passive_results (Dict[str, Any]): Results from PassiveRecon.

        Returns:
            str: Path to the saved JSON file.
        """
        logger.info(f"Aggregating recon data for {target}...")

        aggregated_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "recon": {
                "active": active_results,
                "passive": passive_results
            }
        }

        # Deduplication logic (placeholder if needed)
        # For now, active and passive results are distinct enough.
        # If we had multiple sources for the same data (e.g., multiple port scanners), we'd deduplicate here.

        filename = f"recon_{target.replace('/', '_').replace(':', '_')}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(aggregated_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Recon results saved to {filepath}")
            return filepath
        except IOError as e:
            logger.error(f"Failed to save recon results: {e}")
            return ""
