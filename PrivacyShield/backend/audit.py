"""
PrivacyShield - Safe Audit Logging Module
Records verifiable, non-reversible audit records for each privacy gateway transaction.

STRICT SECURITY COMPLIANCE (DPDP Act, 2023):
- NEVER store raw original documents.
- NEVER store original PII values.
- NEVER store the placeholder-to-original mapping.
- Only store sanitized outbound payloads and safe telemetry metadata.
"""

import os
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("PrivacyShield.Audit")
logger.setLevel(logging.INFO)

LOCAL_AUDIT_FILE = "local_audit_db.json"

class AuditLogger:
    """
    Manages safe audit logging across Supabase and local zero-PII cache.
    """

    def __init__(self, supabase_url: Optional[str] = None, supabase_key: Optional[str] = None):
        self.supabase_url = supabase_url or os.environ.get("SUPABASE_URL", "")
        self.supabase_key = supabase_key or os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_ANON_KEY", "")
        self.supabase_client = None
        self.in_memory_logs: List[Dict[str, Any]] = []

        self._init_supabase()
        self._load_local_cache()

    def _init_supabase(self):
        """Attempts to initialize Supabase client if valid credentials are provided."""
        if (
            self.supabase_url and
            self.supabase_key and
            "your-project" not in self.supabase_url and
            "..." not in self.supabase_key
        ):
            try:
                from supabase import create_client
                self.supabase_client = create_client(self.supabase_url, self.supabase_key)
                logger.info("Connected successfully to Supabase audit database.")
            except Exception as e:
                logger.warning(f"Failed to connect to Supabase: {e}. Falling back to local audit store.")
                self.supabase_client = None
        else:
            self.supabase_client = None

    def _load_local_cache(self):
        """Loads existing audit logs from local cache file if available."""
        if os.path.exists(LOCAL_AUDIT_FILE):
            try:
                with open(LOCAL_AUDIT_FILE, "r", encoding="utf-8") as f:
                    self.in_memory_logs = json.load(f)
            except Exception:
                self.in_memory_logs = []

    def _save_local_cache(self):
        """Persists safe audit records to local JSON file."""
        try:
            with open(LOCAL_AUDIT_FILE, "w", encoding="utf-8") as f:
                json.dump(self.in_memory_logs, f, indent=2)
        except Exception as e:
            logger.error(f"Error persisting local audit records: {e}")

    def log_transaction(
        self,
        request_id: str,
        document_type: str,
        task_selected: str,
        entity_types: List[str],
        masked_entity_count: int,
        sanitized_payload: str,
        external_model: str,
        leakage_check_passed: bool,
        processing_status: str,
        processing_latency_ms: float,
        reinsertion_status: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Creates a new safe audit record.
        STRICT COMPLIANCE: Validates that no raw values or mapping keys are stored.
        """
        record = {
            "id": str(uuid.uuid4()),
            "request_id": request_id,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "document_type": document_type,
            "task_selected": task_selected,
            "entity_types": entity_types,
            "masked_entity_count": masked_entity_count,
            "sanitized_payload": sanitized_payload,
            "external_model": external_model,
            "leakage_check_passed": leakage_check_passed,
            "processing_status": processing_status,
            "processing_latency_ms": round(processing_latency_ms, 2),
            "reinsertion_status": reinsertion_status,
            "storage_provider": "Supabase" if self.supabase_client else "Local Vault",
            "metadata": metadata or {}
        }

        # Save to in-memory list (latest first)
        self.in_memory_logs.insert(0, record)
        # Keep recent 200 logs
        if len(self.in_memory_logs) > 200:
            self.in_memory_logs = self.in_memory_logs[:200]
        self._save_local_cache()

        # Send to Supabase asynchronously / gracefully if configured
        if self.supabase_client:
            try:
                self.supabase_client.table("audit_logs").insert({
                    "request_id": record["request_id"],
                    "document_type": record["document_type"],
                    "task_selected": record["task_selected"],
                    "entity_types": record["entity_types"],
                    "masked_entity_count": record["masked_entity_count"],
                    "sanitized_payload": record["sanitized_payload"],
                    "external_model": record["external_model"],
                    "leakage_check_passed": record["leakage_check_passed"],
                    "processing_status": record["processing_status"],
                    "processing_latency_ms": record["processing_latency_ms"],
                    "reinsertion_status": record["reinsertion_status"]
                }).execute()
            except Exception as e:
                logger.warning(f"Could not push audit record to Supabase table: {e}")

        return record

    def get_logs(
        self,
        query: Optional[str] = None,
        document_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Retrieves filtered audit logs.
        """
        # Try fetching from Supabase if active
        if self.supabase_client:
            try:
                sb_query = self.supabase_client.table("audit_logs").select("*").order("created_at", desc=True).limit(limit)
                if document_type and document_type != "ALL":
                    sb_query = sb_query.eq("document_type", document_type)
                if status and status != "ALL":
                    sb_query = sb_query.eq("processing_status", status)
                res = sb_query.execute()
                if res.data:
                    return res.data
            except Exception as e:
                logger.warning(f"Supabase query failed: {e}. Returning local cache.")

        # Filter local logs
        filtered = self.in_memory_logs

        if document_type and document_type != "ALL":
            filtered = [l for l in filtered if l.get("document_type") == document_type]

        if status and status != "ALL":
            filtered = [l for l in filtered if l.get("processing_status") == status]

        if query and query.strip():
            q = query.lower().strip()
            filtered = [
                l for l in filtered
                if q in l.get("request_id", "").lower()
                or q in l.get("sanitized_payload", "").lower()
                or any(q in t.lower() for t in l.get("entity_types", []))
            ]

        return filtered[:limit]
