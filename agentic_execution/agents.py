import logging
import httpx
from typing import Dict, Any, List
from langchain_core.tools import tool
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import SystemMessage
from agentic_execution.memory import audit_logger

logger = logging.getLogger("AgenticTools")

GOVERNANCE_URL = "http://localhost:8001"
INFERENCE_URL = "http://localhost:8003"

# --- Tools ---

@tool
def discover_vendor_dependencies(vendor_name: str) -> str:
    """Discovers software components and sub-tier supply relationships for a given vendor."""
    logger.info(f"Tool executed: discover_vendor_dependencies for {vendor_name}")
    # In a real implementation, this would trigger the DiscoveryEngine
    return f"Resolved 1 primary software dependency for {vendor_name}: OpenSSL 1.1.1t. Verified 4th-party suppliers."

@tool
def read_sbom(vendor_name: str) -> str:
    """Reads and parses the SBOM for the specified vendor to identify components."""
    logger.info(f"Tool executed: read_sbom for {vendor_name}")
    return f"SBOM for {vendor_name} indicates presence of legacy OpenSSL libraries."

@tool
def query_subgraph_risk(vendor_name: str) -> str:
    """Queries the predictive risk intelligence service to evaluate risk footprint."""
    logger.info(f"Tool executed: query_subgraph_risk for {vendor_name}")
    audit_logger.log_action(vendor_name, "AssessmentTool", "query_subgraph_risk")
    
    try:
        # Mocking the inference call. High uncertainty is flagged for specific patterns.
        is_high_risk = "highrisk" in vendor_name.lower()
        
        data = {
            "composite_risk_score": 95.0 if is_high_risk else 45.0,
            "risk_level": "CRITICAL" if is_high_risk else "LOW",
            "vulnerability_cascade_probability": 0.95 if is_high_risk else 0.10
        }
        
        approval_flag = ""
        if data['vulnerability_cascade_probability'] > 0.8:
            approval_flag = " [HIGH_UNCERTAINTY: REQUIRES_HUMAN_APPROVAL]"
            audit_logger.log_action(vendor_name, "PolicyEngine", "flagged_for_approval", {"reason": "High Cascade Probability"})
            
        return f"Risk Level: {data['risk_level']}, Score: {data['composite_risk_score']}, Cascade Prob: {data['vulnerability_cascade_probability']}{approval_flag}"
    except Exception as e:
        return f"Failed to query risk: {str(e)}"

@tool
def trigger_remediation(vendor_name: str, issue: str) -> str:
    """Executes automated risk mitigation or generates patching recommendations."""
    logger.info(f"Tool executed: trigger_remediation for {vendor_name} - {issue}")
    return f"Generated mitigation plan for {vendor_name}: Patch OpenSSL 1.1.1t to OpenSSL 3.0.x to mitigate {issue}. Alert sent to SecOps."

@tool
def verify_compliance(agent_type: str, action: str) -> str:
    """Verifies with the Governance service if a specific agent is authorized to perform an action."""
    logger.info(f"Tool executed: verify_compliance for {agent_type} attempting {action}")
    # Mocking Governance interaction
    return f"Compliance verified: Agent {agent_type} is AUTHORIZED for action {action}."

# --- Agent Creation Helpers ---

def get_llm():
    """Returns the Local LLM instance (e.g., Ollama)."""
    # Using llama3 as a placeholder for the local model
    return ChatOllama(model="llama3", temperature=0)

def create_agent(agent_name: str, system_prompt: str, tools: list):
    """
    Helper to bind tools to a local LLM. 
    Note: Some local models don't support native tool calling perfectly, 
    but LangChain handles prompt-based tool usage if needed.
    """
    llm = get_llm()
    # Bind tools to the LLM
    llm_with_tools = llm.bind_tools(tools)
    
    # We will return a simple callable that simulates an agent step
    def agent_node(state: dict):
        vendor_name = state.get("vendor_name", "unknown")
        audit_logger.log_action(vendor_name, agent_name, "activated")
        
        messages = state.get("messages", [])
        # Prepend system message if not present
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=system_prompt)] + messages
        
        response = llm_with_tools.invoke(messages)
        audit_logger.log_action(vendor_name, agent_name, "responded", {"content": response.content})
        
        # If the assessment agent identifies high uncertainty, flag state
        requires_approval = state.get("requires_approval", False)
        if "REQUIRES_HUMAN_APPROVAL" in response.content or "REQUIRES_HUMAN_APPROVAL" in str(state.get("messages", [])):
            requires_approval = True
            
        return {"messages": [response], "sender": agent_name, "requires_approval": requires_approval}
        
    return agent_node

# Specialized Agents
discovery_agent = create_agent(
    "discovery_agent",
    "You are a Discovery Agent. Your task is to map supply chain dependencies and read SBOMs. Use the provided tools.",
    [discover_vendor_dependencies, read_sbom]
)

assessment_agent = create_agent(
    "assessment_agent",
    "You are a Risk Assessment Agent. Your task is to evaluate risk scores and threat cascades. Use the provided tools.",
    [query_subgraph_risk]
)

remediation_agent = create_agent(
    "remediation_agent",
    "You are a Remediation Agent. Your task is to formulate mitigation actions and patches. Use the provided tools.",
    [trigger_remediation]
)

compliance_agent = create_agent(
    "compliance_agent",
    "You are a Compliance Agent. Your task is to ensure all actions comply with Governance OPA policies. Use the provided tools.",
    [verify_compliance]
)
