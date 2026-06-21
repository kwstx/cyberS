import pytest
import os
import json
import shutil
from data_ingestion.sbom.parser import SBOMParser
from data_ingestion.mbom.parser import MBOMParser
from data_ingestion.ingestion_service import app, handle_quarantine, DLQ_DIR
from fastapi.testclient import TestClient

client = TestClient(app)

def setup_module(module):
    """Ensure DLQ directory is clean for testing"""
    if os.path.exists(DLQ_DIR):
        shutil.rmtree(DLQ_DIR)
    os.makedirs(DLQ_DIR, exist_ok=True)

def teardown_module(module):
    """Cleanup DLQ directory after tests"""
    if os.path.exists(DLQ_DIR):
        shutil.rmtree(DLQ_DIR)

def test_sbom_parser_corrupted_payload():
    # Corrupted dict - components is not a list
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "name": "Corrupted Component"
            }
        },
        "components": "this-should-be-a-list-but-is-a-string"
    }
    
    # Parser should handle it gracefully without throwing an error
    res = SBOMParser.parse(payload)
    assert res.format == "CycloneDX"
    assert len(res.components) == 0
    assert res.vendor == "Corrupted Component"

def test_sbom_parser_individual_component_corrupted():
    # One good component, one malformed component (e.g. not a dict)
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "name": "good-dep",
                "version": "1.0.0"
            },
            "corrupted-non-dict-component-item"
        ]
    }
    
    # Should skip the corrupted item and still parse the good one
    res = SBOMParser.parse(payload)
    assert len(res.components) == 1
    assert res.components[0].name == "good-dep"

def test_mbom_parser_malformed_framework():
    # MBOM architecture contains corrupted data types
    payload = {
        "model_name": "TestModel",
        "version": "2.0.0",
        "architecture": "not-a-dict",
        "datasets": [
            {
                "name": "good-dataset"
            },
            None  # Corrupted dataset
        ]
    }
    
    # Parser should fall back to default architecture and parse good datasets, skipping corrupted ones
    res = MBOMParser.parse(payload)
    assert res.model_name == "TestModel"
    assert res.architecture.name == "unknown_arch"
    assert len(res.datasets) == 1
    assert res.datasets[0].name == "good-dataset"

@pytest.mark.asyncio
async def test_dlq_quarantine():
    # Clear DLQ
    if os.path.exists(DLQ_DIR):
        shutil.rmtree(DLQ_DIR)
    os.makedirs(DLQ_DIR, exist_ok=True)
    
    test_payload = {"some": "malformed_data"}
    await handle_quarantine(test_payload, "Test error validation failure", "test_source")
    
    # Verify file is written to DLQ directory
    files = os.listdir(DLQ_DIR)
    assert len(files) == 1
    assert files[0].startswith("malformed_test_source_")
    
    with open(os.path.join(DLQ_DIR, files[0]), "r") as f:
        data = json.load(f)
        assert data["source"] == "test_source"
        assert data["error"] == "Test error validation failure"
        assert data["payload"] == test_payload

def test_http_ingest_malformed_fails_safe_to_dlq():
    # Send request with invalid format (e.g. sbom validation fails validation schema check)
    # The SBOM validation fails when we pass an invalid format which raises an exception, which routes to DLQ
    payload = {
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            # missing required metadata / component names / corrupted components that will trigger value error
        },
        "provenance": {
            "signature": "bad-signature" # will cause validation failure in ProvenanceValidator
        }
    }
    
    # Should get intercepted, quarantined in DLQ, and returned with 422
    response = client.post("/ingest", json=payload)
    assert response.status_code == 422
    assert "Signal parsing error (sent to DLQ)" in response.json()["detail"]
    
    # Verify it was quarantined
    files = os.listdir(DLQ_DIR)
    assert any(f.startswith("malformed_http_ingestion_validation") for f in files)
