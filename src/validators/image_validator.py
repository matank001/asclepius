"""Image file validator using PIL."""

from pathlib import Path
from typing import Tuple
from PIL import Image

from .base import FileValidator


class ImageValidator(FileValidator):
    """Validator that checks image structural integrity using PIL."""
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate image file structural integrity.
        
        Args:
            file_path: Path to the image file to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"
        
        # Try to open and verify image structure
        try:
            with Image.open(file_path) as img:
                # Verify structural integrity
                img.verify()
                
            # Re-open to get metadata (verify() closes the image)
            with Image.open(file_path) as img:
                format_name = img.format
                width, height = img.size
                mode = img.mode
                
            return True, self.format_valid(file_path, f"{format_name}, {width}x{height}, {mode}")
            
        except Exception as e:
            return False, self.format_error(file_path, str(e))
