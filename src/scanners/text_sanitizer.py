import bleach
import os
from ..utils.config_loader import config_manager

class TextSanitizer:
    def sanitize(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # bleach.clean removes executable tags (like <script>)
            allowed_tags = config_manager.get('scanners.bleach.allowed_tags', [])
            allowed_attrs = config_manager.get('scanners.bleach.allowed_attributes', {})
            
            cleaned_content = bleach.clean(
                content, 
                tags=allowed_tags, 
                attributes=allowed_attrs, 
                strip=True
            )

            if content != cleaned_content:
                # Malicious XSS or tags found and removed
                return {"passed": False, "reason": "XSS or executable HTML tags detected in Markdown/Text."}
            
            return {"passed": True}

        except UnicodeDecodeError:
            # Not valid text
            return {"passed": False, "reason": "File is not valid UTF-8 text."}
        except Exception as e:
            return {"passed": False, "reason": f"Text sanitization error: {str(e)}"}
