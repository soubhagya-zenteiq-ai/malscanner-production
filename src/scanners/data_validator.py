import csv
import json
import logging
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

logger = logging.getLogger(__name__)

# Malicious patterns to hunt inside data columns
SUSPICIOUS_CONTENT_PATTERNS = [
    "/bin/bash", "powershell.exe", "base64 -d", 
    "netcat", "/dev/tcp", "curl http", "wget http"
]

class DataValidator:
    def __init__(self):
        pass

    def _check_cell(self, cell_content):
        """Logic to check if a single cell contains malicious content."""
        if not cell_content or not isinstance(cell_content, str):
            return True, None

        # 1. Formula Injection Check
        if cell_content.strip().startswith(('=', '+', '-', '@')):
            return False, f"Formula Injection detected: '{cell_content[:20]}...'"
        
        # 2. Hidden Command Strings
        for pattern in SUSPICIOUS_CONTENT_PATTERNS:
            if pattern in cell_content.lower():
                return False, f"Malicious command string detected: '{pattern}'"
        
        return True, None

    def validate(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.csv':
            return self._validate_csv(file_path)
        elif ext == '.parquet':
            return self._validate_parquet(file_path)
        elif ext in ['.json', '.jsonl']:
            return self._validate_json(file_path)
        return {"passed": True}

    def _validate_csv(self, file_path):
        """Scans every single row/cell of a CSV of any size using streaming."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row_num, row in enumerate(reader, 1):
                    for cell in row:
                        passed, reason = self._check_cell(cell)
                        if not passed:
                            return {"passed": False, "reason": f"Row {row_num}: {reason}"}
            return {"passed": True}
        except Exception as e:
            return {"passed": False, "reason": f"Malformed CSV: {str(e)}"}

    def _validate_json(self, file_path):
        """Deep scans JSON/JSONL for formula injections in every value."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Handle JSONL (Line-by-line)
                if file_path.endswith('.jsonl'):
                    for line_num, line in enumerate(f, 1):
                        data = json.loads(line)
                        res = self._check_recursive(data)
                        if not res[0]:
                            return {"passed": False, "reason": f"Line {line_num}: {res[1]}"}
                else:
                    # Generic JSON
                    data = json.load(f)
                    res = self._check_recursive(data)
                    if not res[0]:
                        return {"passed": False, "reason": res[1]}
            return {"passed": True}
        except Exception as e:
            return {"passed": False, "reason": f"JSON structural error: {str(e)}"}

    def _validate_parquet(self, file_path):
        """Scans Parquet file columns for malicious patterns."""
        try:
            table = pq.read_table(file_path)
            # Convert to batches to save memory during scan
            batches = table.to_batches(max_chunksize=1000)
            for batch in batches:
                df = batch.to_pandas()
                for column in df.columns:
                    # Only check string-like columns
                    if df[column].dtype == object or df[column].dtype == 'string':
                        for val in df[column]:
                            passed, reason = self._check_cell(val)
                            if not passed:
                                return {"passed": False, "reason": f"Parquet Data Violation: {reason}"}
            return {"passed": True}
        except Exception as e:
            return {"passed": False, "reason": f"Parquet error: {str(e)}"}

    def _check_recursive(self, data):
        """Recursively scans complex JSON objects for bad data."""
        if isinstance(data, dict):
            for v in data.values():
                res = self._check_recursive(v)
                if not res[0]: return res
        elif isinstance(data, list):
            for item in data:
                res = self._check_recursive(item)
                if not res[0]: return res
        elif isinstance(data, str):
            return self._check_cell(data)
        return True, None

import os # Ensure os is imported
