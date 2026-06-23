# DARIP — Decentralized Agentic Risk Intelligence Fabric

DARIP is a supply chain cybersecurity and third-party risk management platform. It uses a graph-based knowledge model, multi-agent orchestration, predictive ML inference, and post-quantum cryptography to discover vendor dependencies, fuse multi-source signals, compute risk scores, and execute remediation actions across an organization's supply chain.

The system is structured as a five-layer microservices architecture, deployable via Docker Compose for local development or Kubernetes with Istio for production environments.

**Current version:** 0.1.0 (pre-production)

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [System Components](#system-components)
  - [Data Ingestion Service](#data-ingestion-service)
  - [Semantic Fusion Service](#semantic-fusion-service)
  - [Predictive Inference Service](#predictive-inference-service)
  - [Agentic Execution Service](#agentic-execution-service)
  - [Governance Service](#governance-service)
  - [API Gateway](#api-gateway)
  - [Connectors](#connectors)
  - [Stream Processing](#stream-processing)
  - [Remediation Engine](#remediation-engine)
  - [Orchestration and Scheduling](#orchestration-and-scheduling)
  - [MLOps Pipeline](#mlops-pipeline)
  - [Automation and Security Operations](#automation-and-security-operations)
- [Knowledge Graph Model](#knowledge-graph-model)
- [Security Model](#security-model)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
  - [Zero-Trust Enforcement](#zero-trust-enforcement)
  - [Policy-as-Code](#policy-as-code)
- [Data Flow](#data-flow)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Local Development Setup](#local-development-setup)
- [Kubernetes Deployment](#kubernetes-deployment)
- [CI/CD Pipeline](#cicd-pipeline)
- [Testing](#testing)
- [Configuration Reference](#configuration-reference)
- [Current Limitations](#current-limitations)

---

## Architecture Overview

DARIP is organized into five service layers, each running as an independent microservice:

| Layer | Service | Port | Responsibility |
|---|---|---|---|
| 1 | Data Ingestion | 8000 | Receives external signals (SBOMs, ratings, telemetry), encrypts payloads, and forwards them to Semantic Fusion |
| 2 | Governance | 8001 | Issues Zero-Trust tokens, enforces RBAC, evaluates OPA/Rego policies, manages audit ledger |
| 3 | Semantic Fusion | 8002 | Decrypts payloads, resolves entities via GNN, writes to Neo4j graph, serves subgraph queries |
| 4 | Predictive Inference | 8003 | Computes composite risk scores, cascade probabilities, and SHAP-based explanations from graph data |
| 5 | Agentic Execution | 8004 | Orchestrates autonomous agents (Discovery, Assessment, Remediation, Compliance) via LangGraph |

Supporting infrastructure includes Apache Kafka for event streaming, Neo4j as the graph database, Redis for distributed caching, and Apache Spark for stream processing.

All inter-service communication requires a Governance-issued JWT token wrapped with a PQC (Dilithium3) digital signature. Every API call is authorized against OPA Rego policies before execution.

---

## System Components

### Data Ingestion Service

**Location:** `data_ingestion/`
**Port:** 8000
**Entry point:** `data_ingestion/ingestion_service.py`

Accepts multi-source input payloads containing any combination of:
- **SBOMs** in CycloneDX format (vendor name, component name, version, Package URL)
- **Security ratings** (vendor name, security score 0-100, risk tier)
- **Device telemetry** (device ID, running components, associated CVEs)

Processing pipeline:
1. Validates and normalizes incoming signals into the internal schema
2. Establishes a Kyber768 KEM tunnel with the Semantic Fusion service
3. Encrypts the normalized payload using AES-GCM-256 with the KEM-derived shared secret
4. Forwards the encrypted payload to the Semantic Fusion `/fuse` endpoint
5. Optionally publishes events to Kafka for downstream consumers

Additional capabilities:
- `enrichment.py` — Adds contextual metadata (geo-IP, WHOIS, threat intelligence) to ingested signals
- `minimization.py` — GDPR-compliant PII removal and pseudonymization before storage

---

### Semantic Fusion Service

**Location:** `semantic_fusion/`
**Port:** 8002
**Entry point:** `semantic_fusion/fusion_service.py`

Acts as the graph custodian. Receives encrypted payloads from Data Ingestion, processes them, and writes structured data into the Neo4j knowledge graph.

Processing pipeline:
1. Decapsulates the Kyber KEM ciphertext to recover the shared secret
2. Decrypts the AES-GCM payload
3. Runs NLP extraction (`nlp_extractor.py`) to identify threat actors and CVEs from unstructured text fields
4. Resolves entities against existing graph nodes using a GNN-based deduplication engine (`gnn_resolver.py`) — currently implemented as TF-IDF character n-gram similarity with a 0.85 cosine threshold
5. Upserts Vendor, Component, and Device nodes and their relationships into Neo4j via `graph_service.py`

Endpoints:
- `POST /fuse` — Accepts encrypted payloads and processes them into the graph
- `GET /subgraph/{vendor}` — Returns the full subgraph for a given vendor (used by Predictive Inference)

The graph client (`graph_client.py`) supports both a live Neo4j async driver and a full in-memory fallback for development and testing without a running database.

---

### Predictive Inference Service

**Location:** `predictive_inference/`
**Port:** 8003
**Entry point:** `predictive_inference/inference_service.py`

Stateless risk computation engine. Fetches vendor subgraphs from Semantic Fusion and computes:
- **Composite Risk Score** (0-100)
- **Vulnerability Cascade Probability** (likelihood of transitive propagation)
- **Contributing Factors** with SHAP-based explanations

Risk computation methods:

| Module | Method | Description |
|---|---|---|
| `risk_algorithms.py` | Personalized PageRank | Models risk flow through the supply chain graph |
| `risk_algorithms.py` | Bayesian Belief Propagation | Propagates risk probabilities across DAG structures |
| `causal_inference.py` | Structural Causal Model | Supports observational risk (Bayesian propagation) and interventional risk (do-calculus graph mutilation) for what-if analysis |
| `explainer.py` | SHAP Surrogate Model | Generates feature attributions using a linear surrogate with weighted factors: rating risk (0.4), CVE risk (15.0), supply chain depth (4.0) |
| `models/multi_modal.py` | Multi-Modal Fusion | PyTorch ensemble fusing three modalities — see below |

**Multi-Modal ML Architecture** (`models/multi_modal.py`):
- **StructuralGNN**: Graph Convolutional Network processing supply chain topology
- **TextualThreatTransformer**: DistilBERT-based model processing threat advisory text
- **TemporalTrendForecaster**: LSTM processing historical risk time series
- **MultiModalFusionEngine**: Concatenates embeddings from all three modalities, outputs risk score and cascade probability with MC Dropout uncertainty estimation

Additional modules:
- `he_engine.py` — Homomorphic Encryption (CKKS via TenSEAL) for privacy-preserving risk inference across organizational boundaries
- `smpc.py` — Secure Multi-Party Computation using additive secret sharing for cross-organization risk aggregation
- `adversarial_tester.py` — FGSM adversarial attack simulation for model robustness testing
- `graph_builder.py` — Converts discovery topology to NetworkX directed graphs for algorithmic analysis
- `training/` — Training pipeline with synthetic data generation (`dataset.py`), contrastive pre-training via triplet margin loss (`contrastive.py`), and two-phase supervised training with MLflow logging (`train_ensemble.py`)

Endpoints:
- `POST /predict` — Returns risk score, cascade probability, and explanations for a vendor
- `POST /predict/intervention` — Runs interventional (do-calculus) what-if risk scenarios

---

### Agentic Execution Service

**Location:** `agentic_execution/`
**Port:** 8004
**Entry point:** `agentic_execution/agent_service.py`

Orchestrates four specialized autonomous agents using LangGraph with a supervisor routing pattern:

| Agent | Tools | Role |
|---|---|---|
| Discovery | `discover_vendor_dependencies`, `read_sbom` | Maps vendor relationships, parses SBOMs, performs recursive N-th party traversal |
| Assessment | `query_subgraph_risk` | Triggers Predictive Inference, evaluates cascading risk |
| Remediation | `trigger_remediation` | Recommends patches, issues alerts, triggers remediation workflows |
| Compliance | `verify_compliance` | Validates vendor posture against regulatory frameworks |

The supervisor node routes tasks to the appropriate agent based on task type. Human-in-the-loop (HITL) approval is supported via LangGraph's `interrupt_before` mechanism on the `human_approval` node.

LLM backend: Local Ollama instance running Llama 3.

Supporting modules:
- `orchestrator.py` — LangGraph `StateGraph` definition with supervisor, agent, and human approval nodes
- `agents.py` — LangChain agent definitions with bound tools
- `discovery_engine.py` — Recursive N-th party vendor traversal using DNS, port scanning, and SBOM dependency analysis
- `memory.py` — Simulated vector store (Pinecone interface) for agent memory and per-thread audit trails

Endpoints:
- `POST /orchestrate` — Triggers the full agent workflow for a given vendor
- `POST /approve` — Submits human approval/rejection for pending HITL checkpoints

---

### Governance Service

**Location:** `governance/`
**Port:** 8001
**Entry point:** `governance/governance_service.py`

Central authority for authentication, authorization, and compliance.

**Token issuance:**
- Issues JWT tokens signed with RSA-2048
- Wraps each token with a PQC Dilithium3 digital signature
- Tokens encode service identity, role, and expiration

**Authorization flow:**
1. Service presents token to Governance
2. Governance verifies RSA JWT signature
3. Governance verifies PQC Dilithium3 outer signature
4. Governance evaluates the requested action against OPA Rego policies
5. Returns allow/deny decision

Additional modules:
- `compliance_engine.py` — Maps organizational requirements to SOC 2, ISO 27001, and GDPR controls using TF-IDF similarity matching. Evaluates graph state against compliance frameworks.
- `rbac.py` — Fine-grained RBAC with four predefined roles (admin, auditor, analyst, scanner). Supports wildcard action/resource matching. Deny-takes-precedence evaluation.
- `audit_ledger.py` — Append-only JSON ledger with SHA-256 hash chaining for tamper-evident audit trails. Supports integrity verification of the full chain.
- `policies.rego` — OPA Rego rules defining allowed inter-service flows, agent task permissions, and graph mutation/read authorizations.

---

### API Gateway

**Location:** `api/`
**Entry point:** `api/main.py`

A FastAPI application providing the external-facing interface to the platform. Includes:

**Middleware:**
- Zero-Trust header validation
- Rate limiting (via slowapi)
- mTLS simulation

**Endpoints (routers):**
- `routers/assets.py` — CRUD operations for asset management
- `routers/scans.py` — Scan job creation and status
- `routers/insights.py` — Risk insight retrieval
- `routers/compliance.py` — Compliance checks and framework mapping
- `routers/exports.py` — Data export in PDF, CSV, and JSON formats
- `routers/developer_portal.py` — SDK download and API key management

**Additional capabilities:**
- `graphql.py` — Strawberry-based GraphQL endpoint for asset queries
- `grpc_server.py` — gRPC service for `GetAsset` and `ListAssets` RPCs (schema in `protos/darip.proto`)
- `auth.py` — JWT + PQC token validation against Governance
- `events.py` — Kafka event publishing with webhook fallback
- `pep.py` — Policy Enforcement Point for outbound actions and inbound webhooks

---

### Connectors

**Location:** `connectors/`

Data source connectors that push raw signals into Kafka.

**Built-in producers** (`main_connector.py`):
- GitHub repository metadata
- npm package data
- PyPI package data
- Threat intelligence feeds
- Mock vulnerability scanner output

All producers write to the `darip-raw-signals` Kafka topic.

**Enterprise bidirectional connectors** (`enterprise/`):

| Connector | System | Capabilities |
|---|---|---|
| `ariba.py` | SAP Ariba | Pull vendor data, push vendor block/unblock actions |
| `servicenow.py` | ServiceNow | Create incidents and tickets |
| `jira.py` | Jira | Create issues |
| `sentinel.py` | Microsoft Sentinel | Ingest security logs |
| `splunk.py` | Splunk | Forward events via HEC |

All enterprise connectors implement the `BaseBidirectionalConnector` abstract class (`template.py`), which defines `pull_data()`, `push_action()`, and `handle_webhook()` interfaces.

**Webhook receiver** (`webhooks/receiver.py`): Receives inbound webhooks from external systems.

---

### Stream Processing

**Location:** `transformations/` and `fusion/`

**Signal normalization** (`transformations/pipeline.py`):
- Faust streaming application consuming from `darip-raw-signals`
- Normalizes raw signals based on source type
- Produces normalized events to `darip-normalized` topic

**Correlation engine** (`fusion/correlation_engine.py`):
- Fuzzy entity matching using TF-IDF vectorization and cosine similarity
- Matches incoming signals against existing graph assets

**Telemetry fusion** (`fusion/telemetry_fusion.py`):
- Aggregates real-time telemetry streams
- Computes anomaly scores using rolling window statistics

**Graph updater** (`automation/graph_updater.py`):
- Faust consumer on normalized signals
- Forwards processed events to Semantic Fusion for graph updates

**Spark streaming** (Dockerfile.spark):
- Apache Spark 3.5 job for Complex Event Processing and ML anomaly detection
- Reads from Kafka, writes results to Semantic Fusion

---

### Remediation Engine

**Location:** `remediation/`

Handles automated and human-guided remediation based on risk insights.

**Core engine** (`engine.py`):
1. Receives a risk insight (severity, category, affected assets)
2. Selects a playbook using the RL policy engine
3. Executes the playbook via automated actions or guided human workflows
4. Manages multi-role approval chains for high-risk actions

**Playbooks** (`playbook_manager.py`): Six predefined playbooks:
- Network isolation
- Patch guidance
- Generic investigation
- SOAR escalation
- Vendor breach notification
- Compensating controls

**Automated actions** (`actions/`):

| Action | Module | Description |
|---|---|---|
| Network segmentation | `network_segmentation.py` | Strict or moderate network isolation |
| SOAR integration | `soar_integration.py` | Cortex XSOAR escalation |
| Vendor communication | `vendor_communication.py` | Automated breach notification emails |
| Compensating controls | `compensating_controls.py` | WAF rule deployment, IP restrictions |

All actions implement `BaseAutomatedAction` with `execute()` and `simulate()` methods. Simulation runs before execution for supply chain incidents.

**RL policy engine** (`policies/rl_policy.py`): Epsilon-greedy Q-learning agent that learns playbook selection preferences from outcome feedback. Uses exponential smoothing for Q-value updates.

**Guided workflows** (`workflows/guided_workflow.py`): Stateful multi-step workflows for human analysts, including evidence submission and approval/rejection tracking.

---

### Orchestration and Scheduling

**Location:** `orchestration/`

**Intelligent scheduler** (`scheduler.py`):
- Priority queue-based job scheduling
- Token bucket rate limiting per target
- ML-enhanced delay optimization using a RandomForestRegressor trained on scheduling history
- Exponential backoff with jitter on rate limit responses (HTTP 429)
- Time window constraints (e.g., business hours only)
- Full audit trail of scheduling decisions with timestamps and reasoning

**Models** (`models.py`): Pydantic models for `Job` (target, priority, type) and `ScheduleDecision` (action, delay, reason).

---

### MLOps Pipeline

**Location:** `mlops/`

Manages the lifecycle of ML models used by the Predictive Inference service.

| Module | Responsibility |
|---|---|
| `pipeline.py` | End-to-end training pipeline: data loading, training, evaluation, MLflow experiment logging, WandB sync, automatic model promotion when F1 exceeds 0.85 |
| `evaluation.py` | Offline evaluation metrics (precision, recall, F1, AUC-ROC, Brier score), shadow deployment comparison against production model, real outcome tracking |
| `feedback.py` | RLHF feedback loop: ingests analyst feedback, trains a reward model, applies online learning updates via policy gradient |

Data versioning is handled by DVC with a local remote (`dvc_remote/`).

---

### Automation and Security Operations

**Location:** `automation/`

| Module | Responsibility |
|---|---|
| `vulnerability_scanner.py` | Static code analysis detecting hardcoded secrets, unsafe patterns (`eval`, `exec`, `shell=True`), and vulnerable dependency versions |
| `red_team_pen_test.py` | Automated penetration test suite: broken authentication, token tampering, mTLS boundary violations, injection attacks, secret auditing, rate limiting |
| `trigger_engine.py` | Faust stream processor triggering external actions (e.g., Ariba vendor blocking) from risk insights, with policy enforcement |
| `graph_updater.py` | Faust consumer forwarding normalized signals to Semantic Fusion |

---

## Knowledge Graph Model

The supply chain is modeled as a directed property graph in Neo4j with three node types and three relationship types:

**Nodes:**

| Label | Properties | Description |
|---|---|---|
| `:Vendor` | `name`, `security_score` (0-100), `risk_tier` (LOW/MEDIUM/HIGH/CRITICAL) | An organization in the supply chain |
| `:Component` | `name`, `version`, `purl` (Package URL) | A software component or library |
| `:Device` | `id` | An endpoint or infrastructure device |

**Relationships:**

| Type | Direction | Properties | Meaning |
|---|---|---|---|
| `SUPPLIES` | Vendor → Vendor | — | Vendor-to-vendor supply relationship |
| `DEVELOPED` | Vendor → Component | — | Vendor authored or maintains a component |
| `RUNS` | Device → Component | `cves` (list) | Device runs a component with known CVEs |

This graph structure enables transitive dependency analysis across N-th party vendor relationships.

---

## Security Model

### Post-Quantum Cryptography

**Module:** `crypto_pqc.py`

| Algorithm | Standard | Use Case | Fallback |
|---|---|---|---|
| Dilithium3 | NIST PQC | Digital signatures on access tokens and audit entries | Ed25519 (when liboqs is unavailable) |
| Kyber768 | NIST PQC | Key Encapsulation Mechanism for establishing ephemeral symmetric keys between services | AES-GCM key wrapping simulation |
| AES-GCM-256 | — | Symmetric encryption of inter-service payloads using KEM-derived shared secrets | — |

The PQC implementations use liboqs when available and fall back to classical cryptographic equivalents otherwise. This means the system runs without liboqs installed, but without actual post-quantum resistance.

### Zero-Trust Enforcement

Every inter-service API call follows this flow:
1. Calling service requests a token from Governance (`POST /token`)
2. Governance issues a JWT signed with RSA-2048, wrapped in a Dilithium3 signature
3. Calling service includes the token in requests to the target service
4. Target service forwards the token to Governance for verification (`POST /authorize`)
5. Governance verifies the JWT signature, the PQC signature, and evaluates the Rego policy
6. Access is granted or denied

The API gateway adds a `ZeroTrustMiddleware` layer that validates required security headers on all inbound requests.

### Policy-as-Code

Authorization rules are defined in `governance/policies.rego` using Open Policy Agent's Rego language. Policies cover:
- Allowed inter-service communication flows
- Agent task permissions (which agent can perform which actions)
- Graph mutation permissions (which services can write to which node types)
- Graph read permissions

In Kubernetes, OPA Gatekeeper constraints enforce namespace annotation requirements and container registry restrictions.

---

## Data Flow

```
External Sources
  │
  ├─ [Kafka Connectors] ─── darip-raw-signals ─── [Transformations] ─── darip-normalized ─── [Graph Updater]
  │                                                                                                │
  └─ [Data Ingestion :8000] ─── (Kyber KEM + AES-GCM) ──────────────────────────────────────────┐  │
                                                                                                 │  │
                                                                                                 v  v
                                                                                       [Semantic Fusion :8002]
                                                                                          │            │
                                                                                     NLP + GNN     Neo4j Graph
                                                                                          │            │
                                                                                          v            │
                                                                                   [Predictive    <────┘
                                                                                    Inference :8003]
                                                                                          │
                                                                                          v
                                                                                   [Agentic Execution :8004]
                                                                                          │
                                                                                          v
                                                                                   [Remediation Engine]
                                                                                          │
                                                                                    ┌─────┴──────┐
                                                                                    v            v
                                                                              Automated    Guided Human
                                                                              Actions      Workflows

[Governance :8001] ◄──── Token/Authz requests from ALL services
```

---

## Technology Stack

| Category | Technologies |
|---|---|
| Language | Python 3.10+ |
| Web framework | FastAPI, Uvicorn |
| Graph database | Neo4j 5.x |
| Message broker | Apache Kafka (KRaft mode, no ZooKeeper) |
| Stream processing | Apache Spark 3.5, Faust |
| ML / Deep Learning | PyTorch, PyTorch Geometric, Transformers (HuggingFace), scikit-learn |
| LLM orchestration | LangGraph, LangChain, Ollama (Llama 3) |
| Privacy-preserving ML | TenSEAL (Homomorphic Encryption), custom SMPC |
| MLOps | MLflow, Weights & Biases, DVC |
| Cryptography | liboqs (Dilithium3, Kyber768), cryptography (AES-GCM, Ed25519, RSA) |
| API protocols | REST, GraphQL (Strawberry), gRPC |
| Policy engine | Open Policy Agent (Rego) |
| Secrets management | HashiCorp Vault (hvac client) |
| Observability | OpenTelemetry, Prometheus |
| Container runtime | Docker, Docker Compose |
| Orchestration | Kubernetes, Kustomize, Istio, KEDA |
| CI/CD | GitHub Actions |
| Data models | Pydantic v2, STIX-inspired schema |

---

## Project Structure

```
cyberS/
├── api/                          # API gateway (REST, GraphQL, gRPC)
│   ├── main.py                   # FastAPI app with Zero-Trust middleware
│   ├── auth.py                   # JWT + PQC token validation
│   ├── events.py                 # Kafka event publisher
│   ├── graphql.py                # Strawberry GraphQL schema
│   ├── grpc_server.py            # gRPC asset service
│   ├── pep.py                    # Policy Enforcement Point
│   └── routers/                  # REST endpoint modules
├── agentic_execution/            # LangGraph multi-agent orchestrator
│   ├── agent_service.py          # FastAPI wrapper
│   ├── orchestrator.py           # LangGraph StateGraph definition
│   ├── agents.py                 # Agent definitions and tools
│   ├── discovery_engine.py       # N-th party vendor traversal
│   └── memory.py                 # Agent memory and audit trails
├── automation/                   # Security operations automation
│   ├── vulnerability_scanner.py  # Static code analysis
│   ├── red_team_pen_test.py      # Automated pen test suite
│   ├── trigger_engine.py         # Risk-driven action triggers
│   └── graph_updater.py          # Signal-to-graph pipeline
├── connectors/                   # Data source connectors
│   ├── main_connector.py         # Kafka producers (GitHub, npm, PyPI, etc.)
│   ├── template.py               # BaseBidirectionalConnector ABC
│   ├── enterprise/               # SAP Ariba, ServiceNow, Jira, Sentinel, Splunk
│   └── webhooks/                 # Inbound webhook receiver
├── core/                         # Shared infrastructure
│   ├── models.py                 # STIX-inspired Pydantic data models
│   ├── config.py                 # Centralized settings (env vars)
│   ├── secrets.py                # Vault integration with fallback
│   ├── audit.py                  # Structured audit event logging
│   └── observability.py          # OpenTelemetry + Prometheus setup
├── data_ingestion/               # Data Ingestion Service
│   ├── ingestion_service.py      # FastAPI app, PQC-encrypted forwarding
│   ├── enrichment.py             # Signal enrichment (geo-IP, WHOIS)
│   └── minimization.py           # GDPR PII removal
├── fusion/                       # Correlation and telemetry fusion
│   ├── correlation_engine.py     # TF-IDF entity matching
│   └── telemetry_fusion.py       # Real-time telemetry aggregation
├── governance/                   # Governance and Zero-Trust Service
│   ├── governance_service.py     # Token issuance, authorization
│   ├── compliance_engine.py      # SOC2/ISO27001/GDPR mapping
│   ├── rbac.py                   # Fine-grained RBAC
│   ├── audit_ledger.py           # Hash-chained audit ledger
│   └── policies.rego             # OPA Rego authorization rules
├── k8s/                          # Kubernetes manifests
│   ├── base/                     # Base Kustomize resources
│   └── overlays/                 # Environment-specific overlays
│       ├── development/
│       ├── staging/
│       ├── production/
│       ├── region-us-east/
│       └── region-eu-west/
├── mlops/                        # ML operations pipeline
│   ├── pipeline.py               # Training, logging, promotion
│   ├── evaluation.py             # Offline metrics, shadow deployment
│   └── feedback.py               # RLHF feedback loop
├── orchestration/                # Intelligent job scheduler
│   ├── scheduler.py              # ML-enhanced scheduling, rate limiting
│   └── models.py                 # Job and decision models
├── predictive_inference/         # Predictive Inference Service
│   ├── inference_service.py      # FastAPI app, risk prediction
│   ├── causal_inference.py       # Structural Causal Model
│   ├── explainer.py              # SHAP explanations
│   ├── risk_algorithms.py        # PageRank, Bayesian propagation
│   ├── graph_builder.py          # NetworkX graph construction
│   ├── he_engine.py              # Homomorphic Encryption (CKKS)
│   ├── smpc.py                   # Secure Multi-Party Computation
│   ├── adversarial_tester.py     # FGSM robustness testing
│   ├── models/
│   │   └── multi_modal.py        # GCN + DistilBERT + LSTM ensemble
│   └── training/                 # Training pipeline
│       ├── dataset.py            # Synthetic data generation
│       ├── contrastive.py        # Triplet margin loss pre-training
│       └── train_ensemble.py     # Two-phase training
├── protos/
│   └── darip.proto               # gRPC service definitions
├── remediation/                  # Remediation engine
│   ├── engine.py                 # Central remediation orchestrator
│   ├── playbook_manager.py       # Playbook definitions and selection
│   ├── actions/                  # Automated action implementations
│   ├── policies/
│   │   └── rl_policy.py          # Q-learning playbook selection
│   └── workflows/
│       └── guided_workflow.py    # Human-guided workflows
├── semantic_fusion/              # Semantic Fusion Service
│   ├── fusion_service.py         # FastAPI app, payload processing
│   ├── graph_service.py          # Graph write operations
│   ├── graph_client.py           # Neo4j driver + in-memory fallback
│   ├── gnn_resolver.py           # GNN entity deduplication
│   └── nlp_extractor.py          # Threat actor and CVE extraction
├── storage/
│   └── graph.py                  # Neo4j async CRUD repository
├── transformations/
│   └── pipeline.py               # Faust signal normalization
├── crypto_pqc.py                 # PQC library (Dilithium3, Kyber768)
├── demo_run.py                   # Integration test runner
├── demo_scheduler.py             # Scheduler demonstration
├── demo_remediation.py           # Remediation engine demonstration
├── docker-compose.yml            # Local deployment (8 services)
├── Dockerfile.*                  # Per-service container definitions
├── pyproject.toml                # Python package metadata
├── requirements.txt              # Full dependency list
└── .github/workflows/ci-cd.yml  # CI/CD pipeline
```

---

## Prerequisites

- Python 3.10 or later
- Docker and Docker Compose (for containerized deployment)
- Neo4j 5.x (runs automatically via Docker Compose, or install separately)
- Apache Kafka (runs automatically via Docker Compose)
- Ollama with Llama 3 model (required for the Agentic Execution service LLM calls)
- liboqs / pyoqs (optional; without it, PQC algorithms fall back to classical equivalents)
- HashiCorp Vault (optional; without it, secrets use in-memory fallback)

---

## Local Development Setup

**1. Clone the repository:**

```bash
git clone <repository-url>
cd cyberS
```

**2. Create a virtual environment and install dependencies:**

```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
.venv\Scripts\activate         # Windows
pip install -r requirements.txt
pip install -e ".[dev]"
```

**3. Start infrastructure via Docker Compose:**

```bash
docker-compose up -d neo4j kafka
```

This starts Neo4j (ports 7474, 7687) and Kafka (port 9092). Default Neo4j credentials: `neo4j` / `password`.

**4. Start all services via Docker Compose:**

```bash
docker-compose up --build
```

This builds and starts all eight services. Alternatively, run services individually for development.

**5. Run the integration demo:**

```bash
python demo_run.py
```

This starts all five core services as local processes, health-checks each one, and runs an end-to-end integration test with a sample AcmeCorp vendor payload (SBOM + rating + telemetry).

**6. Run individual demos:**

```bash
python demo_scheduler.py      # Demonstrates ML-enhanced job scheduling
python demo_remediation.py    # Demonstrates remediation workflows
```

---

## Kubernetes Deployment

Kubernetes manifests are in `k8s/` using Kustomize.

**Base resources** (`k8s/base/`):
- Namespace definition
- Service deployments (all five core services)
- API gateway deployment
- Redis deployment
- Network policies restricting inter-service traffic
- Istio mTLS and authorization policies
- OPA Gatekeeper constraints
- HPA autoscaling rules
- KEDA ScaledObjects for scale-to-zero inference
- HA failover configuration

**Environment overlays** (`k8s/overlays/`):

| Overlay | Purpose |
|---|---|
| `development/` | Local or dev cluster settings |
| `staging/` | Pre-production environment |
| `production/` | Production hardened configuration |
| `region-us-east/` | US East regional overrides |
| `region-eu-west/` | EU West regional overrides |

**Deploy to a cluster:**

```bash
# Development
kustomize build k8s/overlays/development | kubectl apply -f -

# Production
kustomize build k8s/overlays/production | kubectl apply -f -
```

The deployment assumes an Istio service mesh with strict mTLS PeerAuthentication. Ingress routing, TLS termination, and external DNS are not included in the manifests and must be configured separately.

---

## CI/CD Pipeline

Defined in `.github/workflows/ci-cd.yml`. Runs on push and pull requests to `main`, `master`, `dev`, and `staging` branches.

**Jobs:**

| Job | What it does | Dependencies |
|---|---|---|
| `lint-and-format` | Runs Black formatter check and Flake8 linter (fatal errors only: E9, F63, F7, F82) | None |
| `security-scan` | Runs Bandit static security analysis (medium severity and above) | None |
| `unit-tests` | Installs full requirements and runs pytest | Requires lint-and-format + security-scan to pass |
| `k8s-validate` | Validates Kustomize builds for development, staging, and production overlays | None |

---

## Testing

**Test files at project root:**

| File | Coverage |
|---|---|
| `test_binary_mbom.py` | Binary analysis and Model Bill of Materials |
| `test_compliance_framework.py` | Compliance engine framework mapping |
| `test_correlation.py` | Correlation engine entity matching |
| `test_explainability.py` | SHAP explainability service |
| `test_graph_engine.py` | Graph operations |
| `test_remediation.py` | Remediation engine workflows |
| `test_scale_reliability.py` | Scale and reliability under load |

**Test files in `tests/` directory:**

| File | Coverage |
|---|---|
| `test_enterprise_connectors.py` | Enterprise connector integrations |
| `test_mlops.py` | MLOps pipeline, evaluation, feedback |
| `test_ot_connectors.py` | OT/ICS/SCADA connectors |

**Run all tests:**

```bash
pytest
```

**Automated security testing:**

```bash
python automation/red_team_pen_test.py
```

This runs six automated penetration tests against the running services. Results are written to `red_team_report.json`.

---

## Configuration Reference

Configuration is managed via environment variables, loaded through Pydantic `BaseSettings` in `core/config.py`.

| Variable | Default | Description |
|---|---|---|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `password` | Neo4j password |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker address |
| `GOVERNANCE_URL` | `http://localhost:8001` | Governance service URL |
| `FUSION_URL` | `http://localhost:8002` | Semantic Fusion service URL |
| `INFERENCE_URL` | `http://localhost:8003` | Predictive Inference service URL |
| `VAULT_ADDR` | `http://127.0.0.1:8200` | HashiCorp Vault address |
| `VAULT_TOKEN` | — | Vault authentication token |

---

## Current Limitations

The following items are not production-ready in the current state of the codebase:

- **GNN entity resolution** uses TF-IDF character n-grams as a stand-in. A trained GNN model is not yet integrated.
- **Enterprise connectors** return mock data. Live API integrations (Ariba, ServiceNow, Jira, Sentinel, Splunk) require credentials and endpoint configuration.
- **Kafka connectors** produce synthetic data for development purposes.
- **LLM agents** require a running Ollama instance with Llama 3. Without it, the Agentic Execution service cannot process natural language reasoning.
- **PQC cryptography** falls back to classical algorithms (Ed25519, AES-GCM simulation) when liboqs is not installed. The fallback provides no post-quantum resistance.
- **Vault integration** falls back to in-memory secret storage when Vault is unreachable.
- **Multi-modal ML models** require training before use. The training pipeline exists but pre-trained weights are not shipped.
- **Neo4j graph client** includes an in-memory fallback used during testing. This is not suitable for production workloads.
- **Automated red team tests** require all services to be running locally and validated against a test environment only.
- **Kubernetes manifests** do not include ingress configuration, TLS certificates, or external DNS setup.
- **DVC remote** is configured as a local filesystem path (`dvc_remote/`), not a cloud storage backend.

---
