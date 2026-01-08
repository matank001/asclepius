"""File validators for backup integrity checking."""

from pathlib import Path
import filetype
import inspect
import importlib
import pkgutil
from typing import Dict, Type

from .base import FileValidator
from ..config import ValidatorConfig


# Global config instance
_config = None

# Validator registry: maps validator class names to classes
_validator_registry: Dict[str, Type[FileValidator]] = {}


def register_validator(validator_class: Type[FileValidator]):
    """
    Register a validator class.
    
    Args:
        validator_class: Validator class to register
    """
    class_name = validator_class.__name__
    _validator_registry[class_name] = validator_class


def get_registered_validators() -> Dict[str, Type[FileValidator]]:
    """Get all registered validators."""
    return _validator_registry.copy()


def auto_discover_validators():
    """
    Automatically discover and register all validator classes in this package.
    
    Scans all Python modules in the validators package and registers any class
    that inherits from FileValidator (except FileValidator itself).
    """
    # Get the validators package path
    package_path = Path(__file__).parent
    package_name = __name__
    
    # Import all modules in this package
    for importer, module_name, ispkg in pkgutil.iter_modules([str(package_path)]):
        # Skip __init__ and non-validator files
        if module_name.startswith('_') or module_name == 'base':
            continue
        
        try:
            # Import the module
            full_module_name = f"{package_name}.{module_name}"
            module = importlib.import_module(full_module_name)
            
            # Find all classes in the module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Check if it's a FileValidator subclass (but not FileValidator itself)
                if (inspect.isclass(obj) and 
                    issubclass(obj, FileValidator) and 
                    obj is not FileValidator):
                    register_validator(obj)
        
        except Exception as e:
            # Log but don't fail if a module can't be imported
            print(f"Warning: Could not import validator module {module_name}: {e}")


# Auto-discover validators on module import
auto_discover_validators()


def get_config() -> ValidatorConfig:
    """Get or create validator configuration."""
    global _config
    if _config is None:
        _config = ValidatorConfig()
    return _config


def detect_file_type(file_path: Path) -> tuple[str, str]:
    """
    Detect file type using filetype library.
    
    Args:
        file_path: Path to file
        
    Returns:
        Tuple of (mime_type, extension)
    """
    # Try to detect using filetype library (reads file header)
    kind = filetype.guess(str(file_path))
    
    if kind is not None:
        return kind.mime, kind.extension
    
    # Fallback to file extension
    return None, file_path.suffix.lower()


def get_validators(file_path: Path) -> list[FileValidator]:
    """
    Get all appropriate validators for a file based on its actual type.
    
    Args:
        file_path: Path to the file to validate
        
    Returns:
        List of FileValidator instances
    """
    config = get_config()
    
    # Detect actual file type
    mime_type, detected_ext = detect_file_type(file_path)
    
    # Try to get validators by MIME type first
    validator_class_names = []
    if mime_type:
        validator_class_names = config.get_validators_for_mime_type(mime_type)
    
    # Fallback to extension-based detection
    if not validator_class_names:
        file_ext = file_path.suffix.lower()
        validator_class_names = config.get_validators_for_extension(file_ext)
    
    # Instantiate all matching validators
    validators = []
    for validator_class_name in validator_class_names:
        if validator_class_name in _validator_registry:
            validator_class = _validator_registry[validator_class_name]
            validators.append(validator_class())
    
    # If no validators found, return unsupported validator
    if not validators:
        class UnsupportedValidator(FileValidator):
            def validate(self, file_path: Path):
                return False, f"Unsupported file type: {file_path.suffix}"
        validators.append(UnsupportedValidator())
    
    return validators


def get_validator(file_path: Path) -> FileValidator:
    """
    Get first appropriate validator for a file (for backward compatibility).
    
    Args:
        file_path: Path to the file to validate
        
    Returns:
        FileValidator instance
    """
    validators = get_validators(file_path)
    return validators[0]


__all__ = [
    'FileValidator',
    'get_validator',
    'get_validators',
    'detect_file_type',
    'get_registered_validators',
]
