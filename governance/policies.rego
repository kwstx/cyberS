package darip.authz

# Default to deny all access
default allow = False

# Helper: Decode and verify token metadata
# In a full OPA installation, you'd use io.jwt.decode_verify.
# Here we represent the policy logic based on inputs received from the Governance service token evaluation.

# Rules for service-to-service communication
allow {
    input.action == "inter_service_call"
    input.token.claims.iss == "DARIP-Governance"
    valid_service_to_service_flow(input.src_service, input.dest_service)
}

# Rules for agent actions
allow {
    input.action == "agent_execution"
    input.token.claims.iss == "DARIP-Governance"
    input.token.claims.role == "agent"
    agent_action_allowed(input.token.claims.agent_type, input.agent_task)
    target_is_allowed(input.target_asset)
}

# Allow list check (mocked here, primarily handled in Python service layer)
target_is_allowed(target) {
    true
}
# Rules for stateful database mutations
allow {
    input.action == "graph_mutation"
    input.token.claims.iss == "DARIP-Governance"
    service_can_mutate_graph(input.token.claims.sub)
}

# Rules for reading sensitive risk intelligence
allow {
    input.action == "read_risk_intelligence"
    input.token.claims.iss == "DARIP-Governance"
    service_can_read_intelligence(input.token.claims.sub)
}

# Valid data flows in our layered architecture
# Data Ingestion -> Semantic Fusion is allowed
valid_service_to_service_flow("data_ingestion", "semantic_fusion") = true
# Semantic Fusion -> Stateful Graph is allowed
valid_service_to_service_flow("semantic_fusion", "stateful_graph") = true
# Predictive Inference -> Stateful Graph is allowed
valid_service_to_service_flow("predictive_inference", "stateful_graph") = true
# Agentic Execution -> Predictive Inference is allowed
valid_service_to_service_flow("agentic_execution", "predictive_inference") = true
# Agentic Execution -> Semantic Fusion is allowed (for updating discovered vendors)
valid_service_to_service_flow("agentic_execution", "semantic_fusion") = true
# Governance -> All layers is allowed
valid_service_to_service_flow("governance", _) = true

# Agent task permissions
# Discovery Agent can only discover and read telemetry
agent_action_allowed("discovery_agent", "discover_vendor") = true
agent_action_allowed("discovery_agent", "read_sbom") = true
# Risk Evaluator Agent can evaluate risks and query subgraphs
agent_action_allowed("risk_evaluator_agent", "query_subgraph") = true
agent_action_allowed("risk_evaluator_agent", "predict_risk") = true
# Remediation Agent can issue remediation, run mitigations, and notify governance
agent_action_allowed("remediation_agent", "trigger_remediation") = true
agent_action_allowed("remediation_agent", "verify_remediation") = true

# Graph mutator authorizations
service_can_mutate_graph("semantic_fusion") = true
service_can_mutate_graph("governance") = true

# Graph reader authorizations
service_can_read_intelligence("predictive_inference") = true
service_can_read_intelligence("agentic_execution") = true
service_can_read_intelligence("governance") = true
