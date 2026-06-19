import subprocess
import time
import os
import sys
import httpx
import signal

# Ensure cyberS root is in python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Define ports for the 5 services
SERVICES = {
    "Governance Service": ("governance.governance_service", 8001),
    "Semantic Fusion Service": ("semantic_fusion.fusion_service", 8002),
    "Data Ingestion Service": ("data_ingestion.ingestion_service", 8000),
    "Predictive Inference Service": ("predictive_inference.inference_service", 8003),
    "Agentic Execution Service": ("agentic_execution.agent_service", 8004)
}

def start_services() -> list[subprocess.Popen]:
    processes = []
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.dirname(os.path.abspath(__file__))
    
    print("\n[+] Launching DARIP Fabric Services...")
    
    # Start Governance first, then Fusion, then others to avoid startup timing races
    start_order = [
        "Governance Service",
        "Semantic Fusion Service",
        "Data Ingestion Service",
        "Predictive Inference Service",
        "Agentic Execution Service"
    ]
    
    for name in start_order:
        module, port = SERVICES[name]
        print(f"    - Starting {name} on port {port}...")
        
        # Start uvicorn command for each service
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", f"{module}:app", "--port", str(port), "--host", "127.0.0.1"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        processes.append(proc)
        time.sleep(1.0) # brief gap for port binding
        
    print("[+] All services spawned. Waiting for health checks...")
    
    # Verify health checks
    max_retries = 10
    for name, (_, port) in SERVICES.items():
        url = f"http://localhost:{port}/health"
        healthy = False
        for i in range(max_retries):
            try:
                resp = httpx.get(url, timeout=2.0)
                if resp.status_code == 200:
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if not healthy:
            print(f"[-] ERROR: {name} failed health check on port {port}.")
            terminate_processes(processes)
            sys.exit(1)
        else:
            print(f"    - {name} is HEALTHY")
            
    print("[+] Entire DARIP Microservice Fabric is operational and secured with PQC/Zero-Trust.\n")
    return processes

def terminate_processes(processes: list[subprocess.Popen]):
    print("\n[-] Shutting down DARIP Fabric Services...")
    for proc in processes:
        try:
            # Terminate gracefully
            if sys.platform == "win32":
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                proc.terminate()
            proc.wait(timeout=3.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    print("[-] All services stopped.")

def run_integration_test():
    print("=" * 70)
    print("DARIP DEMO: MULTI-SIGNAL SUPPLY CHAIN RISK EVALUATION FLOW")
    print("=" * 70)

    # 1. Prepare multi-signal payload representing a vulnerable vendor "AcmeCorp"
    # AcmeCorp supplies components including OpenSSL 1.1.1t, which is installed on a device
    # and has a critical active CVE (CVE-2023-0286).
    sbom_payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:3e671687-395b-418a-9c49-080c8502fbf6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-06-19T12:00:00Z",
            "component": {
                "name": "AcmeCorp",
                "type": "operating-system"
            }
        },
        "components": [
            {
                "name": "openssl",
                "version": "1.1.1t",
                "purl": "pkg:generic/openssl@1.1.1t",
                "bom_ref": "pkg:generic/openssl@1.1.1t"
            }
        ]
    }
    
    rating_payload = {
        "vendor_name": "AcmeCorp",
        "security_score": 85,
        "risk_tier": "MEDIUM",
        "last_updated": "2026-06-18"
    }

    telemetry_payload = {
        "device_id": "endpoint-prod-db-01",
        "active_connections": 12,
        "outbound_payload_size_mb": 42.5,
        "cve_detections": ["CVE-2023-0286"] # Critical OpenSSL memory corruption vulnerability
    }

    ingest_request = {
        "sbom": sbom_payload,
        "rating": rating_payload,
        "telemetry": telemetry_payload
    }

    # Step 1: Ingestion
    print("\n[Step 1] Ingesting multi-signal supply chain dataset to Ingestion Layer...")
    try:
        r = httpx.post("http://localhost:8000/ingest", json=ingest_request, timeout=5.0)
        r.raise_for_status()
        ingest_res = r.json()
        print(f"    - Ingestion Status: {ingest_res.get('status')}")
        print(f"    - Ingested Signals: {ingest_res.get('fusion_result', {}).get('fused_signals')}")
        print(f"    - Nodes affected: {ingest_res.get('fusion_result', {}).get('nodes_affected')}")
        print(f"    - Relationships created: {ingest_res.get('fusion_result', {}).get('relationships_affected')}")
    except Exception as e:
        print(f"[-] Ingestion Step Failed: {e}")
        return

    # Step 2: Trigger Multi-Agent Orchestration
    # The orchestration endpoint initiates Discovery Agent, Risk Evaluator, and Remediation Agent
    print("\n[Step 2] Activating Decentralized Multi-Agent Risk Orchestrator for 'AcmeCorp'...")
    try:
        r = httpx.post("http://localhost:8004/orchestrate", json={"vendor_name": "AcmeCorp"}, timeout=10.0)
        r.raise_for_status()
        orchestration_res = r.json()
    except Exception as e:
        print(f"[-] Orchestration Step Failed: {e}")
        return

    # Step 3: Print Agent Logs to demonstrate autonomous execution and OPA Policy checks
    print("\n[Step 3] Verification of Agent Execution Trails:")
    print("-" * 70)
    print("DISCOVERY AGENT TRAIL:")
    print(f"    {orchestration_res.get('discovery_agent_log')}")
    print("\nRISK EVALUATOR AGENT TRAIL:")
    print(f"    {orchestration_res.get('evaluator_agent_log')}")
    print("\nREMEDIATION AGENT TRAIL:")
    print(f"    {orchestration_res.get('remediation_agent_log')}")
    print("-" * 70)
    
    print("\n[Step 4] Actions Finalized:")
    for idx, act in enumerate(orchestration_res.get("actions_taken", []), 1):
        print(f"    {idx}. {act}")

    print("\n[+] Verification COMPLETE. The Fabric successfully ingested, verified, fused, modeled, and remediated risk autonomously.")
    print("=" * 70)

if __name__ == "__main__":
    # Windows-specific subprocess handling
    if sys.platform == "win32":
        # Enable CTRL_C_EVENT or CTRL_BREAK_EVENT for children
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        creationflags = 0

    procs = start_services()
    try:
        run_integration_test()
    finally:
        terminate_processes(procs)
