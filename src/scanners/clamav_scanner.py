import pyclamd
import logging
import os
import mmap
from ..utils.config_loader import config_manager

logger = logging.getLogger(__name__)

class ClamAvScanner:
    def __init__(self):
        try:
            socket_path = config_manager.get('scanners.clamav.socket_path', '/var/run/clamav/clamd.ctl')
            self.cd = pyclamd.ClamdUnixSocket(filename=socket_path)
            if not self.cd.ping():
                raise ConnectionError
        except Exception:
            # Note: In production we use logging, not print.
            logger.error("ClamAV Daemon not found. Ensure clamd is running.")
            self.cd = None

    def scan(self, file_path):
        if not self.cd:
            return {"passed": False, "reason": "ClamAV engine is offline. Security policy requires an active scan."}

        try:
            # We use scan_stream() to bypass Linux file permission issues.
            # We use mmap to bypass Python memory exhaustion (OOM) issues.
            # This is the most 'Production-Ready' way to interface with ClamAV.
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return {"passed": True} # Empty files are clean by definition in ClamAV

            with open(file_path, 'rb') as f:
                # Map file into memory (OS level, doesn't bloat Python heap)
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    scan_result = self.cd.scan_stream(mm)
            
            if scan_result is None:
                return {"passed": True}
            else:
                # scan_result format for streams: {'stream': ('FOUND', 'VirusName')}
                virus_name = scan_result.get('stream', ('UNKNOWN', 'ERROR'))[1]
                return {"passed": False, "reason": f"Malware Detected: {virus_name}"}
        except Exception as e:
            return {"passed": False, "reason": f"ClamAV Engine Error: {str(e)}"}
