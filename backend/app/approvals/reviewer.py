import os
import logging
from typing import Dict, Any, Optional

from backend.app.approvals.service import ApprovalService

logger = logging.getLogger(__name__)

class SimulatedReviewer:
    """
    Simulated Reviewer for automated testing and benchmark runs.
    NEVER active in normal/production mode.
    Controlled by SENTINEL_SIMULATED_REVIEWER: 'disabled' (default), 'deny', or 'scripted'.
    """
    @classmethod
    def get_mode(cls) -> str:
        return os.getenv("SENTINEL_SIMULATED_REVIEWER", "disabled").lower().strip()

    @classmethod
    def set_mode(cls, mode: str):
        os.environ["SENTINEL_SIMULATED_REVIEWER"] = mode.lower().strip()

    @classmethod
    def is_active(cls) -> bool:
        return cls.get_mode() in ["deny", "scripted"]

    @classmethod
    def evaluate_and_resolve(
        cls,
        approval_id: str,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        mode = cls.get_mode()
        if mode == "disabled":
            return None

        if mode == "deny":
            logger.info(f"Simulated Reviewer [DENY]: Auto-denying approval {approval_id}")
            return ApprovalService.resolve_approval(
                approval_id=approval_id,
                decision="deny",
                resolved_by="simulated_reviewer",
                resolution_reason="Simulated reviewer policy: Automatic denial for testing."
            )

        if mode == "scripted":
            # Scripted rule: approve if destination is approved vendor or within maintenance window
            args_str = str(arguments).lower()
            if "vendor-corp.com" in args_str or "approved" in args_str:
                logger.info(f"Simulated Reviewer [SCRIPTED APPROVE]: Auto-approving {approval_id}")
                return ApprovalService.resolve_approval(
                    approval_id=approval_id,
                    decision="approve",
                    resolved_by="simulated_reviewer",
                    resolution_reason="Scripted policy: Destination matches verified partner whitelist.",
                    raw_arguments=arguments
                )
            else:
                logger.info(f"Simulated Reviewer [SCRIPTED DENY]: Auto-denying {approval_id}")
                return ApprovalService.resolve_approval(
                    approval_id=approval_id,
                    decision="deny",
                    resolved_by="simulated_reviewer",
                    resolution_reason="Scripted policy: Destination does not match approved whitelist."
                )

        return None
