import os
import yaml
import logging

logger = logging.getLogger(__name__)

class ConfigLoader:
    def __init__(self, config_path=None):
        if config_path is None:
            # Default to the production.yml in the config directory
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            config_path = os.path.join(base_dir, "config", "production.yml")
        
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            logger.warning(f"Config file not found at {self.config_path}. Overriding with defaults.")
            return {}
        
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading YAML config: {e}")
            return {}

    def get(self, key_path, default=None):
        """Retrieve a value using a dot-separated path (e.g., 'limits.max_file_size_mb')."""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

# Singleton instance for easy access across the app
config_manager = ConfigLoader()
