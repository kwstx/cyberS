import pytest
from predictive_inference.explainer import ExplainerService
from predictive_inference.inference_service import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_explainer_service():
    explainer = ExplainerService()
    
    avg_vendor_rating = 80.0
    active_cves_count = 2
    vendor_count = 3
    
    # Calculate exact SHAP values
    shap_vals = explainer.explain_prediction(avg_vendor_rating, active_cves_count, vendor_count)
    
    # Assert keys match features
    assert "Ecosystem Rating Risk" in shap_vals
    assert "Active CVE Risk" in shap_vals
    assert "Supply Chain Depth" in shap_vals
    
    # Expected SHAP values:
    # Ecosystem Rating Risk = (100 - 80) * 0.4 = 20 * 0.4 = 8.0
    assert shap_vals["Ecosystem Rating Risk"] == 8.0
    
    # Active CVE Risk = 2 * 15.0 = 30.0
    assert shap_vals["Active CVE Risk"] == 30.0
    
    # Supply Chain Depth = 3 * 4.0 = 12.0
    assert shap_vals["Supply Chain Depth"] == 12.0

def test_inference_service_predict_provenance():
    response = client.post("/predict", json={"vendor_name": "TestVendorCorp"})
    
    assert response.status_code == 200
    data = response.json()
    
    # SHAP should be present in the output
    assert "shap_values" in data
    assert data["shap_values"]["Ecosystem Rating Risk"] >= 0.0
    
    # The AuditEvent should have fired and written to the ledger
    from governance.audit_ledger import audit_ledger
    logs = audit_ledger.get_logs()
    
    # Check if the latest log is our prediction
    last_log = logs[-1]["event"]
    assert last_log["action"] == "risk_assessment_generated"
    assert last_log["actor"] == "predictive_inference"
    assert last_log["target"] == "TestVendorCorp"
    assert "shap_values" in last_log["details"]
    assert "model_version" in last_log["details"]
