"""Tamper-Proof Audit Trail Ledger with SHA-256 Cryptographic Hash Chaining."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class MutationRecord:
    block_index: int
    doctype: str
    docname: str
    action: str  # INSERT, UPDATE, SUBMIT, CANCEL
    modified_by: str
    timestamp_utc: str
    payload_snapshot: Dict[str, Any]
    prev_hash: str
    current_hash: str


@dataclass
class AuditVerificationResult:
    is_valid: bool
    total_blocks_checked: int
    corrupted_block_index: Optional[int] = None
    reason: Optional[str] = None


class TamperProofAuditLedger:
    """Enterprise Cryptographic Audit Trail for MCA & CARO 2020 Statutory Compliance."""

    GENESIS_HASH = "0" * 64

    def __init__(self):
        self.chain: List[MutationRecord] = []

    def _calculate_hash(
        self,
        index: int,
        doctype: str,
        docname: str,
        action: str,
        modified_by: str,
        timestamp: str,
        payload: Dict[str, Any],
        prev_hash: str
    ) -> str:
        serialized_payload = json.dumps(payload, sort_keys=True)
        raw_string = f"{index}|{doctype}|{docname}|{action}|{modified_by}|{timestamp}|{serialized_payload}|{prev_hash}"
        return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

    def record_mutation(
        self,
        doctype: str,
        docname: str,
        action: str,
        modified_by: str,
        payload_snapshot: Dict[str, Any]
    ) -> MutationRecord:
        index = len(self.chain)
        prev_hash = self.chain[-1].current_hash if self.chain else self.GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()

        current_hash = self._calculate_hash(
            index=index,
            doctype=doctype,
            docname=docname,
            action=action,
            modified_by=modified_by,
            timestamp=timestamp,
            payload=payload_snapshot,
            prev_hash=prev_hash
        )

        record = MutationRecord(
            block_index=index,
            doctype=doctype,
            docname=docname,
            action=action,
            modified_by=modified_by,
            timestamp_utc=timestamp,
            payload_snapshot=payload_snapshot,
            prev_hash=prev_hash,
            current_hash=current_hash
        )
        self.chain.append(record)
        return record

    def verify_chain_integrity(self) -> AuditVerificationResult:
        if not self.chain:
            return AuditVerificationResult(is_valid=True, total_blocks_checked=0)

        for i, block in enumerate(self.chain):
            # Check prev_hash
            expected_prev = self.GENESIS_HASH if i == 0 else self.chain[i - 1].current_hash
            if block.prev_hash != expected_prev:
                return AuditVerificationResult(
                    is_valid=False,
                    total_blocks_checked=i + 1,
                    corrupted_block_index=i,
                    reason=f"Broken prev_hash chain link at block {i}"
                )

            # Re-compute hash
            recomputed = self._calculate_hash(
                index=block.block_index,
                doctype=block.doctype,
                docname=block.docname,
                action=block.action,
                modified_by=block.modified_by,
                timestamp=block.timestamp_utc,
                payload=block.payload_snapshot,
                prev_hash=block.prev_hash
            )
            if block.current_hash != recomputed:
                return AuditVerificationResult(
                    is_valid=False,
                    total_blocks_checked=i + 1,
                    corrupted_block_index=i,
                    reason=f"Hash mismatch at block {i}: payload or metadata altered"
                )

        return AuditVerificationResult(is_valid=True, total_blocks_checked=len(self.chain))
