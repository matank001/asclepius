"""MarkItDown-based file validator with entropy checking."""

from pathlib import Path
from typing import Tuple
from markitdown import MarkItDown

from .base import FileValidator
from .entropy_validator import EntropyValidator


class MarkItDownValidator(FileValidator):
    """Validator that uses MarkItDown to parse files and checks text entropy."""
    
    def __init__(self):
        """Initialize MarkItDown validator."""
        from ..config import ValidatorConfig
        
        # Load validator-specific configuration
        config = ValidatorConfig()
        check_entropy = config.get_validator_setting('MarkItDownValidator', 'check_entropy', True)
        
        self.md = MarkItDown()
        self.entropy_validator = EntropyValidator() if check_entropy else None
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """
        Try to parse the file with MarkItDown and validate text entropy.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"
        
        # Try to parse with MarkItDown
        try:
            result = self.md.convert(str(file_path))
            if not result or not result.text_content:
                return False, f"✗ Empty or invalid content: {file_path.name}"
            
            # Validate entropy of extracted text
            if self.entropy_validator:
                text = result.text_content.strip()
                is_valid, entropy_msg = self.entropy_validator.validate_text(text)
                
                if not is_valid:
                    return False, f"✗ {file_path.name}: {entropy_msg}"
                
                return True, f"✓ Valid: {file_path.name} ({entropy_msg})"
            else:
                return True, f"✓ Valid: {file_path.name}"
                
        except Exception as e:
            return False, f"✗ Parse error in {file_path.name}: {str(e)}"
