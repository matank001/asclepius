"""Configuration loader for validator settings."""

import yaml
from pathlib import Path
from typing import Dict, List, Optional


class ValidatorConfig:
    """Loads and manages validator configuration."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize validator config.
        
        Args:
            config_path: Path to validators.yaml file. If None, uses default location.
        """
        if config_path is None:
            # Default to validators.yaml in project root
            config_path = Path(__file__).parent.parent / "validators.yaml"
        
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Validator config not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def get_validator_for_mime_type(self, mime_type: str) -> Optional[str]:
        """
        Get validator name for a given MIME type.
        
        Args:
            mime_type: MIME type string (e.g., "application/pdf")
            
        Returns:
            Validator name or None if not supported
        """
        validators = self.get_validators_for_mime_type(mime_type)
        return validators[0] if validators else None
    
    def get_validators_for_mime_type(self, mime_type: str) -> List[str]:
        """
        Get all validator names for a given MIME type.
        
        Args:
            mime_type: MIME type string (e.g., "application/pdf")
            
        Returns:
            List of validator names
        """
        if not mime_type:
            return []
        
        validators = self.config.get('validators', {})
        matching_validators = []
        
        for validator_name, validator_info in validators.items():
            mime_types = validator_info.get('mime_types', [])
            
            # Check for "all" wildcard
            if "all" in mime_types:
                matching_validators.append(validator_name)
            elif mime_type in mime_types:
                matching_validators.append(validator_name)
        
        return matching_validators
    
    def get_validator_for_extension(self, extension: str) -> Optional[str]:
        """
        Get validator name for a given file extension.
        
        Args:
            extension: File extension (e.g., ".pdf")
            
        Returns:
            Validator name or None if not supported
        """
        validators = self.get_validators_for_extension(extension)
        return validators[0] if validators else None
    
    def get_validators_for_extension(self, extension: str) -> List[str]:
        """
        Get all validator names for a given file extension.
        
        Args:
            extension: File extension (e.g., ".pdf")
            
        Returns:
            List of validator names
        """
        if not extension:
            return []
        
        # Normalize extension
        if not extension.startswith('.'):
            extension = f'.{extension}'
        extension = extension.lower()
        
        validators = self.config.get('validators', {})
        matching_validators = []
        
        for validator_name, validator_info in validators.items():
            extensions = validator_info.get('extensions', [])
            
            # Check for "all" wildcard
            if "all" in extensions:
                matching_validators.append(validator_name)
            elif extension in extensions:
                matching_validators.append(validator_name)
        
        return matching_validators
    
    def get_setting(self, key: str, default=None):
        """
        Get a global configuration setting.
        
        Args:
            key: Setting key
            default: Default value if key not found
            
        Returns:
            Setting value or default
        """
        return self.config.get('settings', {}).get(key, default)
    
    def get_validator_setting(self, validator_name: str, key: str, default=None):
        """
        Get a validator-specific configuration setting.
        
        Args:
            validator_name: Name of the validator
            key: Setting key
            default: Default value if key not found
            
        Returns:
            Setting value or default
        """
        validators = self.config.get('validators', {})
        validator_config = validators.get(validator_name, {})
        return validator_config.get('settings', {}).get(key, default)
    
    def get_supported_mime_types(self) -> List[str]:
        """Get list of all supported MIME types."""
        mime_types = []
        validators = self.config.get('validators', {})
        
        for validator_info in validators.values():
            mime_types.extend(validator_info.get('mime_types', []))
        
        return mime_types
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of all supported file extensions."""
        extensions = []
        validators = self.config.get('validators', {})
        
        for validator_info in validators.values():
            extensions.extend(validator_info.get('extensions', []))
        
        return extensions
