import logging
import httpx
from typing import Dict, Any, List
from langchain_core.tools import tool
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import SystemMessage

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
    try:
        # Mocking the inference call as this requires the predictive inference service
        # resp = httpx.post(f"{INFERENCE_URL}/predict", json={"vendor_name": vendor_name})
        # data = resp.json()
        data = {
            "composite_risk_score": 85.0,
            "risk_level": "HIGH",
            "vulnerability_cascade_probability": 0.75
        }
        return f"Risk Level: {data['risk_level']}, Score: {data['composite_risk_score']}, Cascade Prob: {data['vulnerability_cascade_probability']}"
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
        messages = state.get("messages", [])
        # Prepend system message if not present
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=system_prompt)] + messages
        
        response = llm_with_tools.invoke(messages)
        return {"messages": [response], "sender": agent_name}
        
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
