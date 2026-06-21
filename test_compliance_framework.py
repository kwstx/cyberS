import pytest
from governance.rbac import FineGrainedRBAC
from governance.compliance_engine import ComplianceEngine
from governance.audit_ledger import ImmutableAuditLedger
import os
import json

def test_fine_grained_rbac():
    # Admin has wildcard access
    assert FineGrainedRBAC.is_authorized(["admin"], "delete:assets", "asset:123") == True
    
    # Auditor can read reports
    assert FineGrainedRBAC.is_authorized(["auditor"], "read:reports", "report:soc2") == True
    
    # Auditor cannot write assets (explicit deny)
    assert FineGrainedRBAC.is_authorized(["auditor"], "write:assets", "asset:123") == False
    
    # Analyst can write exposures but not delete assets
    assert FineGrainedRBAC.is_authorized(["analyst"], "write:exposures", "exposure:456") == True
    assert FineGrainedRBAC.is_authorized(["analyst"], "delete:assets", "asset:123") == False

def test_compliance_engine_ml_mapping():
    engine = ComplianceEngine()
    
    # Map a requirement
    results = engine.map_requirement_to_controls("We need to encrypt our databases")
    assert len(results) > 0
    # The highest confidence should be SOC2 CC6.1 or similar
    assert results[0]["confidence_score"] > 0.0

def test_audit_ledger():
    ledger_path = "test_audit_ledger.json"
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
        
    ledger = ImmutableAuditLedger(ledger_path=ledger_path)
    
    # Genesis block created
    logs = ledger.get_logs()
    assert len(logs) == 1
    assert logs[0]["event"]["type"] == "GENESIS"
    
    # Append event
    ledger.append_event({"type": "TEST", "data": "test"})
    
    # Verify integrity
    assert ledger.verify_integrity() == True
    
    # Tamper with ledger
    with open(ledger_path, "r+") as f:
        data = json.load(f)
        data[1]["event"]["data"] = "tampered"
        f.seek(0)
        json.dump(data, f)
        f.truncate()
        
    assert ledger.verify_integrity() == False
    
    # Cleanup
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
