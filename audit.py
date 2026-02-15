
import json
import logging
import os
import socket
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class AuditLogger:
    def __init__(self, log_path: Path = Path("madara_audit.jsonl")):
        self.log_path = log_path
        # Ensure log directory exists? 
        # For now assume current directory or user provided path is valid.
    
    def log_wipe_operation(
        self,
        file_path: Path,
        file_size: int,
        sha256_before: str,
        standard_used: str,
        result: Dict[str, Any]
    ):
        """
        Registra en formato JSON Lines cada operación
        """
        try:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file": str(file_path.absolute()),
                "size_bytes": file_size,
                "sha256_before": sha256_before,
                "standard": standard_used,
                "passes": result.get("passes_completed", 0),
                "verified": result.get("verified", False),
                "duration_sec": result.get("duration", 0.0),
                "user": os.getlogin(),
                "hostname": socket.gethostname(),
                "success": result.get("success", False),
                "error": result.get("error"),
                "strategy": result.get("strategy", "Unknown")
            }
            
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            # Fallback logging if audit fails (critical error)
            logging.error(f"Failed to write to audit log: {e}")

    def get_logs(self):
        """Generator to read logs"""
        if not self.log_path.exists():
            return
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
