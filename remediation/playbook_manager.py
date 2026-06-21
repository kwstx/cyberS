import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class Playbook:
    def __init__(self, pb_id: str, name: str, pb_type: str, match_rules: Dict[str, Any], steps: List[Dict[str, Any]]):
        self.pb_id = pb_id
        self.name = name
        self.pb_type = pb_type  # 'automated' or 'guided'
        self.match_rules = match_rules
        self.steps = steps

    def matches(self, insight: Dict[str, Any]) -> bool:
        """
        Evaluate if this playbook matches the given risk insight based on rules.
        """
        for key, expected_value in self.match_rules.items():
            actual_value = insight.get(key)
            # Support simple exact match and list inclusion
            if isinstance(expected_value, list):
                if actual_value not in expected_value:
                    return False
            else:
                if actual_value != expected_value:
                    return False
        return True


class PlaybookManager:
    def __init__(self):
        self.playbooks: List[Playbook] = []
        self._load_default_playbooks()

    def _load_default_playbooks(self):
        # In a real system, these would be loaded from a database or YAML files
        self.playbooks = [
            Playbook(
                pb_id="pb_network_isolate_01",
                name="Network Isolation for Critical Vulnerabilities",
                pb_type="automated",
                match_rules={"severity": "critical", "type": "vulnerability"},
                steps=[
                    {"action": "network_segmentation", "params": {"isolation_level": "strict"}}
                ]
            ),
            Playbook(
                pb_id="pb_patch_guidance_01",
                name="Guided Patching Workflow",
                pb_type="guided",
                match_rules={"severity": ["high", "critical"], "type": "vulnerability"},
                steps=[
                    {"step_id": "step_1", "instruction": "Verify the asset is in the patch management system.", "requires_evidence": False},
                    {"step_id": "step_2", "instruction": "Apply patch and provide proof of successful deployment.", "requires_evidence": True}
                ]
            ),
             Playbook(
                pb_id="pb_generic_investigate",
                name="Generic Investigation",
                pb_type="guided",
                match_rules={}, # Matches anything
                steps=[
                    {"step_id": "step_1", "instruction": "Review the risk insight.", "requires_evidence": False}
                ]
            ),
            Playbook(
                pb_id="pb_soar_escalation",
                name="Complex Incident SOAR Escalation",
                pb_type="automated",
                match_rules={"severity": "critical", "type": "complex_incident"},
                steps=[
                    {"action": "soar_integration", "params": {"platform": "Cortex XSOAR", "escalation_level": "critical"}}
                ]
            ),
            Playbook(
                pb_id="pb_supply_chain_comm",
                name="Vendor Breach Notification",
                pb_type="automated",
                match_rules={"severity": ["high", "critical"], "type": "supply_chain_breach"},
                steps=[
                    {"action": "vendor_communication", "params": {"template_type": "breach_notification"}}
                ]
            ),
            Playbook(
                pb_id="pb_supply_chain_controls",
                name="Apply Compensating Controls for Vendor Portal",
                pb_type="automated",
                match_rules={"severity": "high", "type": "vendor_portal_vulnerability"},
                steps=[
                    {"action": "compensating_controls", "params": {"control_type": "waf_strict_filtering"}}
                ]
            )
        ]
        logger.info(f"Loaded {len(self.playbooks)} playbooks.")

    def get_eligible_playbooks(self, insight: Dict[str, Any]) -> List[Playbook]:
        eligible = [pb for pb in self.playbooks if pb.matches(insight)]
        logger.info(f"Found {len(eligible)} eligible playbooks for insight.")
        return eligible

    def get_playbook(self, pb_id: str) -> Optional[Playbook]:
        for pb in self.playbooks:
            if pb.pb_id == pb_id:
                return pb
        return None
