import operator
from typing import Annotated, Sequence, TypedDict, List
import logging

from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
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
    requires_approval: bool
    human_approved: bool

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
            
    # Check if approval is required
    if state.get("requires_approval", False) and not state.get("human_approved", False):
        next_worker = "human_approval"
        logger.info(f"Supervisor escalating to HITL due to high uncertainty policy.")
    else:
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

def human_approval_node(state: AgentState):
    """
    A dummy node that LangGraph stops before. 
    Once approved by the API, it simply passes through.
    """
    logger.info("Human approval gate passed.")
    return {"human_approved": True}

# Build the Graph
workflow = StateGraph(AgentState)

# Add nodes
workflow.add_node("supervisor", supervisor_node)
workflow.add_node("discovery_agent", discovery_agent)
workflow.add_node("assessment_agent", assessment_agent)
workflow.add_node("remediation_agent", remediation_agent)
workflow.add_node("compliance_agent", compliance_agent)
workflow.add_node("human_approval", human_approval_node)

# Add edges
for member in members:
    workflow.add_edge(member, "supervisor")

workflow.add_edge("human_approval", "supervisor")

# The supervisor determines the next step
workflow.add_conditional_edges(
    "supervisor",
    lambda x: x["next"],
    {
        "discovery_agent": "discovery_agent",
        "assessment_agent": "assessment_agent",
        "remediation_agent": "remediation_agent",
        "compliance_agent": "compliance_agent",
        "human_approval": "human_approval",
        "FINISH": END
    }
)

workflow.set_entry_point("supervisor")

# Initialize Checkpointer
memory_saver = MemorySaver()

# Compile the graph with interrupt before human_approval
orchestrator_app = workflow.compile(checkpointer=memory_saver, interrupt_before=["human_approval"])

def run_agentic_workflow(vendor_name: str) -> dict:
    """Executes the full agentic workflow using the LangGraph orchestrator."""
    logger.info(f"Starting LangGraph multi-agent workflow for {vendor_name}")
    
    config = {"configurable": {"thread_id": vendor_name}}
    
    # Check if thread already exists and is interrupted
    state = orchestrator_app.get_state(config)
    
    if state and state.next and state.next[0] == "human_approval":
        # It's waiting for approval, we shouldn't run it blindly from start.
        return {"status": "pending_approval"}
    
    initial_state = {
        "messages": [HumanMessage(content=f"Evaluate supply chain risk for vendor: {vendor_name}")],
        "vendor_name": vendor_name,
        "requires_approval": False,
        "human_approved": False
    }
    
    final_state = None
    for s in orchestrator_app.stream(initial_state, config=config, stream_mode="values"):
        logger.info(f"Graph step completed. Current nodes: {list(s.keys()) if isinstance(s, dict) else 'State update'}")
        
    # After stream finishes or interrupts, check state
    current_state = orchestrator_app.get_state(config)
    if current_state.next and current_state.next[0] == "human_approval":
        logger.warning(f"Workflow interrupted. Awaiting HITL approval for {vendor_name}.")
        return {"status": "pending_approval", "state": current_state.values}
        
    return current_state.values

def approve_workflow(vendor_name: str) -> dict:
    """Resumes the workflow after human approval."""
    config = {"configurable": {"thread_id": vendor_name}}
    logger.info(f"Received human approval for {vendor_name}. Resuming workflow...")
    
    # Resume the graph by passing None
    for s in orchestrator_app.stream(None, config=config, stream_mode="values"):
         logger.info(f"Graph step completed post-approval.")
         
    return orchestrator_app.get_state(config).values
