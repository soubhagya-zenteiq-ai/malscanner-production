import yara
import os
import logging
from ..utils.config_loader import config_manager

logger = logging.getLogger(__name__)

class YARAScanner:
    def __init__(self, rules_dir=None):
        if rules_dir is None:
            rules_dir = config_manager.get('scanners.yara.rules_dir', 'yara')
        
        # If path is relative, make it absolute relative to project root
        if not os.path.isabs(rules_dir):
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            rules_dir = os.path.join(base_dir, rules_dir)
            
        self.rules_dir = os.path.abspath(os.path.expanduser(rules_dir))
        self.rule_sets = []
        self.load_rules()

    def load_rules(self):
        """Safely load and compile individual YARA rules."""
        if not os.path.exists(self.rules_dir):
            logger.error(f"YARA rules directory not found: {self.rules_dir}")
            return

        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    path = os.path.join(root, file)
                    try:
                        compiled = yara.compile(filepath=path)
                        self.rule_sets.append(compiled)
                    except Exception as e:
                        logger.debug(f"Skipping complex YARA rule {file}: {e}")
                        continue
        logger.info(f"YARA Scanner initialized with {len(self.rule_sets)} rule sets.")

    def scan(self, file_path):
        """Scan file against all loaded YARA rules."""
        if not self.rule_sets:
            return {"passed": True, "reason": "No YARA rules loaded."}

        try:
            abs_path = os.path.abspath(file_path)
            matches = []
            for rule_set in self.rule_sets:
                m = rule_set.match(abs_path)
                if m:
                    matches.extend(m)
            
            if matches:
                # Get the most descriptive match for the reason
                rule_names = [m.rule for m in matches[:3]]
                return {
                    "passed": False,
                    "reason": f"YARA Match: {', '.join(rule_names)}{'...' if len(matches) > 3 else ''}"
                }
            return {"passed": True, "reason": "No YARA matches found."}
        except Exception as e:
            logger.error(f"YARA Scan Error: {e}")
            return {"passed": True, "reason": f"YARA Error: {e}"}
