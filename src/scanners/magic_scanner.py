import magic
from ..utils.config_loader import config_manager

class MagicScanner:
    def scan(self, file_path, extension):
        try:
            true_mime = magic.from_file(file_path, mime=True)
            whitelist = config_manager.get('whitelist', {})
            expected_mimes = whitelist.get(extension)
            
            if not expected_mimes:
                return {"passed": False, "reason": f"Extension {extension} is not in the whitelist.", "mime": true_mime}
            elif true_mime in expected_mimes:
                return {"passed": True, "mime": true_mime}
            else:
                return {"passed": False, "reason": f"SPOOFING DETECTED! Expected {expected_mimes}, got {true_mime}.", "mime": true_mime}
        except Exception as e:
            return {"passed": False, "reason": f"Magic check error: {str(e)}"}
