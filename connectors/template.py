from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseBidirectionalConnector(ABC):
    """
    Standardized template for 10x connectivity.
    Ensures that all new integrations conform to bidirectional requirements.
    """
    
    @abstractmethod
    async def pull_data(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Pull data from the external system (e.g., fetching a list of active vendors).
        """
        pass
        
    @abstractmethod
    async def push_action(self, action_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Push an action to the external system (e.g., block a vendor, create an incident).
        Must return a standardized response dict.
        """
        pass

    @abstractmethod
    async def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and normalize an incoming webhook from the external system.
        """
        pass
