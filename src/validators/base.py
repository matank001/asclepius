"""Base validator class."""

from pathlib import Path
from typing import Tuple


class FileValidator:
    """Base class for file validators."""
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate a file.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        raise NotImplementedError
    
    def format_error(self, file_path: Path, error: str) -> str:
        """
        Format error message consistently.
        
        Args:
            file_path: Path to the file
            error: Error message
            
        Returns:
            Formatted error message: [FILE_PATH] [VALIDATOR]: [ERROR]
        """
        validator_name = self.__class__.__name__
        return f"✗ [{file_path}] [{validator_name}]: {error}"
    
    def format_valid(self, file_path: Path, message: str = None) -> str:
        """
        Format valid message consistently.
        
        Args:
            file_path: Path to the file
            message: Optional additional message
            
        Returns:
            Formatted valid message
        """
        if message:
            return f"✓ Valid: {file_path.name} ({message})"
        return f"✓ Valid: {file_path.name}"
