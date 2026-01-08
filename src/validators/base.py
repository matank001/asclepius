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
