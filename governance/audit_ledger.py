import json
import hashlib
import os
import time
from typing import Dict, Any, List

class ImmutableAuditLedger:
    """
    A blockchain-inspired append-only ledger for storing immutable audit logs.
    It uses SHA-256 chaining to guarantee immutability and detect tampering.
    """
    def __init__(self, ledger_path: str = "data/audit_ledger.json"):
        self.ledger_path = ledger_path
        dirname = os.path.dirname(self.ledger_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        self._ensure_ledger_exists()

    def _ensure_ledger_exists(self):
        if not os.path.exists(self.ledger_path):
            # Create Genesis block
            genesis = {
                "index": 0,
                "timestamp": time.time(),
                "event": {"type": "GENESIS"},
                "prev_hash": "0" * 64,
                "hash": ""
            }
            genesis["hash"] = self._calculate_hash(genesis)
            with open(self.ledger_path, "w") as f:
                json.dump([genesis], f, indent=2)

    def _calculate_hash(self, block: Dict[str, Any]) -> str:
        # We hash the string representation of the block (excluding its own hash field)
        block_copy = block.copy()
        if "hash" in block_copy:
            del block_copy["hash"]
        block_string = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def append_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with open(self.ledger_path, "r+") as f:
            ledger = json.load(f)
            last_block = ledger[-1]
            
            new_block = {
                "index": last_block["index"] + 1,
                "timestamp": time.time(),
                "event": event,
                "prev_hash": last_block["hash"]
            }
            new_block["hash"] = self._calculate_hash(new_block)
            
            ledger.append(new_block)
            
            f.seek(0)
            json.dump(ledger, f, indent=2)
            f.truncate()
            
        return new_block

    def verify_integrity(self) -> bool:
        """Verify the cryptographic hash chain."""
        if not os.path.exists(self.ledger_path):
            return True
            
        with open(self.ledger_path, "r") as f:
            ledger = json.load(f)
            
        for i in range(1, len(ledger)):
            current_block = ledger[i]
            prev_block = ledger[i-1]
            
            if current_block["prev_hash"] != prev_block["hash"]:
                return False
                
            if current_block["hash"] != self._calculate_hash(current_block):
                return False
                
        return True

    def get_logs(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.ledger_path):
            return []
        with open(self.ledger_path, "r") as f:
            return json.load(f)

# Global singleton instance
audit_ledger = ImmutableAuditLedger()
