import random
import logging
from typing import List, Dict, Any
from remediation.playbook_manager import Playbook

logger = logging.getLogger(__name__)

class RLPolicyEngine:
    """
    Mock Reinforcement Learning Policy Engine.
    In a real-world scenario, this could be a contextual bandit or Q-learning model 
    (e.g., implemented using scikit-learn or stable-baselines3) that learns the probability 
    of remediation success given a risk insight context.
    """
    def __init__(self):
        # Maps (insight_type, severity) -> Dict[pb_id, expected_reward]
        self.q_table: Dict[str, Dict[str, float]] = {}
        # Hyperparameters for epsilon-greedy policy
        self.epsilon = 0.1

    def _get_state_key(self, insight: Dict[str, Any]) -> str:
        # A simplified state representation
        return f"{insight.get('type', 'unknown')}_{insight.get('severity', 'low')}"

    def select_best_playbook(self, insight: Dict[str, Any], eligible_playbooks: List[Playbook]) -> Playbook:
        if not eligible_playbooks:
            raise ValueError("No eligible playbooks provided to policy engine.")

        state_key = self._get_state_key(insight)
        
        # Initialize Q-values for unseen state-action pairs
        if state_key not in self.q_table:
            self.q_table[state_key] = {pb.pb_id: 0.5 for pb in eligible_playbooks}

        state_q = self.q_table[state_key]
        for pb in eligible_playbooks:
            if pb.pb_id not in state_q:
                 state_q[pb.pb_id] = 0.5 # Default initial reward expectation

        # Epsilon-greedy selection
        if random.random() < self.epsilon:
            # Explore
            selected_pb = random.choice(eligible_playbooks)
            logger.info(f"RL Policy (Explore): Selected {selected_pb.pb_id}")
        else:
            # Exploit
            # Find the pb_id with max Q-value among eligible
            best_pb_id = max(eligible_playbooks, key=lambda pb: state_q[pb.pb_id]).pb_id
            selected_pb = next(pb for pb in eligible_playbooks if pb.pb_id == best_pb_id)
            logger.info(f"RL Policy (Exploit): Selected {selected_pb.pb_id} with Q-value {state_q[best_pb_id]:.2f}")

        return selected_pb

    def update_policy(self, insight: Dict[str, Any], pb_id: str, success: bool):
        """
        Update the Q-table based on the reward (success=1.0, failure=0.0).
        """
        state_key = self._get_state_key(insight)
        if state_key not in self.q_table:
            return
        
        reward = 1.0 if success else 0.0
        current_q = self.q_table[state_key].get(pb_id, 0.5)
        
        # Simple exponential smoothing update rule (learning rate alpha = 0.2)
        alpha = 0.2
        new_q = current_q + alpha * (reward - current_q)
        self.q_table[state_key][pb_id] = new_q
        logger.info(f"RL Policy Updated: {state_key} -> {pb_id} new Q-value: {new_q:.2f}")
