from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseAutomatedAction(ABC):
    """
    Interface for all automated remediation actions.
    """
    
    @abstractmethod
    def execute(self, params: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Execute the automated action.
        
        Args:
            params: Parameters specified in the playbook step.
            context: The risk insight context triggering this action.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        pass

    @abstractmethod
    def simulate(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate the automated action to evaluate impact before execution.
        
        Args:
            params: Parameters specified in the playbook step.
            context: The risk insight context triggering this action.
            
        Returns:
            Dict[str, Any]: A report describing the simulated impact.
        """
        pass
