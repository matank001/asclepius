"""Email file (EML) validator."""

from pathlib import Path
from typing import Tuple
import datetime
import eml_parser

from .base import FileValidator


def json_serial(obj):
    """JSON serializer for datetime objects."""
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


class EmailValidator(FileValidator):
    """Validator that checks email file (EML) structure and content."""
    
    def __init__(self):
        """Initialize email validator."""
        self.ep = eml_parser.EmlParser()
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate email file structure.
        
        Args:
            file_path: Path to the email file to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"
        
        try:
            # Check if email file is parseable
            with open(file_path, 'rb') as fhdl:
                raw_email = fhdl.read()
            
            # Attempt to parse - will raise exception if invalid
            parsed_eml = self.ep.decode_email_bytes(raw_email)
            
            # Basic validation - check if we got a valid structure
            if not isinstance(parsed_eml, dict):
                return False, f"✗ Invalid email structure in {file_path.name}"
            
            # Check for minimum required headers
            header = parsed_eml.get('header', {})
            if not header.get('from'):
                return False, f"✗ Invalid email {file_path.name}: Missing 'From' header"
            
            return True, f"✓ Valid: {file_path.name}"
        
        except Exception as e:
            return False, f"✗ Email parse error in {file_path.name}: {str(e)}"
