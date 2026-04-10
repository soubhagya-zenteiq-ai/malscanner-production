# security_analyzer/core.py
import os
import logging
from ..utils.config_loader import config_manager
from ..scanners.magic_scanner import MagicScanner
from ..scanners.clamav_scanner import ClamAvScanner
from ..scanners.pdf_scanner import PDFScanner
from ..scanners.text_sanitizer import TextSanitizer
from ..scanners.data_validator import DataValidator
from ..scanners.zst_validator import ZstdValidator
from ..scanners.yara_scanner import YARAScanner

# Configure detailed logging
log_level = config_manager.get('logging.level', 'INFO').upper()
log_path = config_manager.get('logging.path', 'data/logs/app.log')

# If path is relative, make it absolute relative to project root
if not os.path.isabs(log_path):
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_path = os.path.join(base_dir, log_path)

log_format = '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'

# Ensure log directory exists
os.makedirs(os.path.dirname(log_path), exist_ok=True)

logging.basicConfig(
    level=getattr(logging, log_level),
    format=log_format,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_path)
    ]
)
logger = logging.getLogger("malscanner.core")

class SecurityAnalyzer:
    def __init__(self):
        self.magic_scanner = MagicScanner()
        self.clamav_scanner = ClamAvScanner()
        self.pdf_scanner = PDFScanner()
        self.text_sanitizer = TextSanitizer()
        self.data_validator = DataValidator()
        self.zst_validator = ZstdValidator()
        self.yara_scanner = YARAScanner()

    def analyze(self, file_path):
        logger.info(f"Starting analysis for: {file_path}")
        if not os.path.exists(file_path):
            return {"status": "error", "message": "File not found"}

        limit_mb = config_manager.get('limits.max_file_size_mb', 50)
        max_bytes = limit_mb * 1024 * 1024
        file_size = os.path.getsize(file_path)
        if file_size > max_bytes:
            logger.warning(f"File {file_path} exceeds maximum allowed size ({max_bytes} bytes)")
            return {"status": "🔴 REJECTED", "reason": f"File exceeds maximum size limit of {limit_mb}MB (DoS protection)."}

        # 1. Identity Check
        logger.info(f"[Phase 1/4] Identity Check (Magic/MIME) for {file_path}")
        ext = os.path.splitext(file_path)[1].lower()
        identity_result = self.magic_scanner.scan(file_path, ext)
        if not identity_result['passed']:
            logger.error(f"Identity check FAILED: {identity_result['reason']}")
            return {"status": "🔴 REJECTED", "reason": f"Identity Check Failed: {identity_result['reason']}", "detected_mime": identity_result.get("mime")}
        
        detected_mime = identity_result['mime']
        logger.info(f"Identity check PASSED (MIME: {detected_mime})")

        # 2. Malaria/Virus Check
        logger.info(f"[Phase 2/4] Virus Scanning (ClamAV) for {file_path}")
        clamav_result = self.clamav_scanner.scan(file_path)
        if not clamav_result['passed']:
            logger.error(f"Virus scan FAILED: {clamav_result['reason']}")
            return {"status": "🔴 REJECTED", "reason": f"Malware Detected: {clamav_result['reason']}", "detected_mime": detected_mime}
        logger.info("Virus scan PASSED (No threats found)")

        # 3. YARA Payload Scan
        logger.info(f"[Phase 3/4] Deep Inspection (YARA Rules) for {file_path}")
        yara_result = self.yara_scanner.scan(file_path)
        if not yara_result['passed']:
            logger.error(f"YARA Deep Inspection FAILED: {yara_result['reason']}")
            return {"status": "🔴 REJECTED", "reason": f"YARA Match: {yara_result['reason']}", "detected_mime": detected_mime}
        logger.info("YARA Deep Inspection PASSED")

        # 4. Format-specific Checks
        logger.info(f"[Phase 4/4] Heuristic Analysis ({ext}) for {file_path}")
        if ext == '.pdf':
            pdf_result = self.pdf_scanner.scan(file_path)
            if not pdf_result['passed']:
                logger.error(f"PDF Heuristics FAILED: {pdf_result['reason']}")
                return {"status": "🔴 REJECTED", "reason": f"PDF Malicious Content Detected: {pdf_result['reason']}", "detected_mime": detected_mime}
        
        elif ext in ['.txt', '.md', '.xml']:
            txt_result = self.text_sanitizer.sanitize(file_path)
            if not txt_result['passed']:
                logger.warning(f"Text sanitization failed for {file_path}: {txt_result['reason']}")
                return {"status": "🔴 REJECTED", "reason": f"XSS/Malicious Text Content Detected: {txt_result['reason']}", "detected_mime": detected_mime}

        elif ext in ['.csv', '.parquet', '.json', '.jsonl']:
            data_result = self.data_validator.validate(file_path)
            if not data_result['passed']:
                logger.warning(f"Data validation failed for {file_path}: {data_result['reason']}")
                return {"status": "🔴 REJECTED", "reason": f"Data Integrity/Validation Failed: {data_result['reason']}", "detected_mime": detected_mime}
        
        elif ext == '.zst':
            zst_result = self.zst_validator.validate(file_path)
            if not zst_result['passed']:
                logger.warning(f"ZST validation failed for {file_path}: {zst_result['reason']}")
                return {"status": "🔴 REJECTED", "reason": f"ZST Bomb Detected/Validation Failed: {zst_result['reason']}", "detected_mime": detected_mime}

        logger.info(f"File {file_path} safely passed all checks.")
        return {"status": "🟢 SAFE", "message": "File passed all security and structural checks.", "detected_mime": detected_mime}

    def cleanup(self):
        pass
