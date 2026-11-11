import unittest
from audittrail.engine import TamperProofAuditLedger

class TestTamperProofAuditTrail(unittest.TestCase):
    def test_valid_chain(self):
        ledger = TamperProofAuditLedger()
        b0 = ledger.record_mutation(
            doctype="GL Entry",
            docname="GL-2026-001",
            action="INSERT",
            modified_by="auditor@enterprise.com",
            payload_snapshot={"debit": 500000, "credit": 0, "account": "1110 - Bank"}
        )
        self.assertEqual(b0.block_index, 0)
        self.assertEqual(b0.prev_hash, TamperProofAuditLedger.GENESIS_HASH)

        b1 = ledger.record_mutation(
            doctype="GL Entry",
            docname="GL-2026-001",
            action="SUBMIT",
            modified_by="cfo@enterprise.com",
            payload_snapshot={"docstatus": 1}
        )
        self.assertEqual(b1.prev_hash, b0.current_hash)

        result = ledger.verify_chain_integrity()
        self.assertTrue(result.is_valid)
        self.assertEqual(result.total_blocks_checked, 2)

    def test_tamper_detection(self):
        ledger = TamperProofAuditLedger()
        ledger.record_mutation(
            doctype="Sales Invoice",
            docname="SINV-901",
            action="INSERT",
            modified_by="sales@enterprise.com",
            payload_snapshot={"grand_total": 120000}
        )
        ledger.record_mutation(
            doctype="Sales Invoice",
            docname="SINV-902",
            action="INSERT",
            modified_by="sales@enterprise.com",
            payload_snapshot={"grand_total": 450000}
        )

        # Malicious tampering with database snapshot
        ledger.chain[0].payload_snapshot["grand_total"] = 10000

        result = ledger.verify_chain_integrity()
        self.assertFalse(result.is_valid)
        self.assertEqual(result.corrupted_block_index, 0)
        self.assertIn("Hash mismatch", result.reason)

if __name__ == "__main__":
    unittest.main()
