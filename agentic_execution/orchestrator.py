import operator
from typing import Annotated, Sequence, TypedDict, List
import logging

from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from agentic_execution.agents import (
    discovery_agent,
    assessment_agent,
    remediation_agent,
    compliance_agent,
    get_llm
)
from agentic_execution.memory import vector_store
from langchain_core.documents import Document

logger = logging.getLogger("AgenticOrchestrator")

# The agent state definition
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    next: str
    vendor_name: str

# Define the supervisor routing logic
members = ["discovery_agent", "assessment_agent", "remediation_agent", "compliance_agent"]
system_prompt = (
    "You are a supervisor managing a conversation between the following workers: {members}. "
    "Given the following user request, respond with the worker to act next. "
    "The typical flow is: compliance_agent (to check auth) -> discovery_agent -> assessment_agent -> remediation_agent (if needed). "
    "Each worker will perform a task and respond with their results and status. "
    "When finished, respond with FINISH."
)

options = members + ["FINISH"]

class Router(BaseModel):
    """Worker to route to next. If no workers needed, route to FINISH."""
    next: str = Field(description=f"The next worker to route to: {', '.join(options)}")

prompt = ChatPromptTemplate.from_messages(
    [
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="messages"),
        (
            "system",
            "Given the conversation above, who should act next? "
            "Or should we FINISH? Select one of: {options}",
        ),
    ]
).partial(options=str(options), members=", ".join(members))

llm = get_llm()

# Bind the router to the LLM
# Fallback to simple completion if structured output isn't fully supported by local model
def supervisor_node(state: AgentState):
    logger.info("Supervisor evaluating next step...")
    # Add to memory
    if state["messages"]:
        last_message = state["messages"][-1].content
        vector_store.add_documents([Document(page_content=f"State updated: {last_message}")])
        
    messages = prompt.format_messages(messages=state["messages"])
    # For a local LLM, we might need a simpler routing mechanism, but we'll use the bind_tools approach 
    # or direct string matching for robustness.
    # To keep it generic across LLMs:
    response = llm.invoke(messages)
    content = response.content.strip().upper()
    
    # Simple heuristic routing for local models
    next_worker = "FINISH"
    for opt in options:
        if opt.upper() in content:
            next_worker = opt
            break
            
    # Default workflow enforcement if LLM fails to output exact token
    if next_worker == "FINISH" and len(state["messages"]) < 3:
        # Force the flow if the LLM hallucinated FINISH too early
        if "compliance_agent" not in str(state["messages"]):
            next_worker = "compliance_agent"
        elif "discovery_agent" not in str(state["messages"]):
            next_worker = "discovery_agent"
        elif "assessment_agent" not in str(state["messages"]):
            next_worker = "assessment_agent"

    logger.info(f"Supervisor decided next worker: {next_worker}")
    return {"next": next_worker}

# Build the Graph
workflow = StateGraph(AgentState)

# Add nodes
workflow.add_node("supervisor", supervisor_node)
workflow.add_node("discovery_agent", discovery_agent)
workflow.add_node("assessment_agent", assessment_agent)
workflow.add_node("remediation_agent", remediation_agent)
workflow.add_node("compliance_agent", compliance_agent)

# Add edges
for member in members:
    workflow.add_edge(member, "supervisor")

# The supervisor determines the next step
workflow.add_conditional_edges(
    "supervisor",
    lambda x: x["next"],
    {
        "discovery_agent": "discovery_agent",
        "assessment_agent": "assessment_agent",
        "remediation_agent": "remediation_agent",
        "compliance_agent": "compliance_agent",
        "FINISH": END
    }
)

workflow.set_entry_point("supervisor")

# Compile the graph
orchestrator_app = workflow.compile()

def run_agentic_workflow(vendor_name: str) -> dict:
    """Executes the full agentic workflow using the LangGraph orchestrator."""
    logger.info(f"Starting LangGraph multi-agent workflow for {vendor_name}")
    
    initial_state = {
        "messages": [HumanMessage(content=f"Evaluate supply chain risk for vendor: {vendor_name}")],
        "vendor_name": vendor_name
    }
    
    final_state = None
    # We can stream the output or just run it
    for s in orchestrator_app.stream(initial_state, config={"recursion_limit": 15}):
        logger.info(f"Graph step completed: {list(s.keys())[0]}")
        final_state = s
        
    return final_state
