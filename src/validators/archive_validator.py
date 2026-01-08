"""Archive file validator with recursive content validation."""

from pathlib import Path
from typing import Tuple
import zipfile
import tarfile
import tempfile
import shutil

from .base import FileValidator


class ArchiveValidator(FileValidator):
    """Validator that checks archive integrity and optionally validates contents."""
    
    def __init__(self):
        """Initialize archive validator."""
        from ..config import ValidatorConfig
        
        config = ValidatorConfig()
        self.recursive_validate = config.get_validator_setting('ArchiveValidator', 'recursive_validate', False)
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate archive file integrity and optionally its contents.
        
        Args:
            file_path: Path to the archive file to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"
        
        extension = file_path.suffix.lower()
        
        # Check archive integrity
        try:
            if extension in ['.zip']:
                return self._validate_zip(file_path)
            elif extension in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz']:
                return self._validate_tar(file_path)
            else:
                # Skip unsupported archive types (e.g., .npz, .jar, etc.)
                return True, self.format_valid(file_path)
        
        except Exception as e:
            return False, self.format_error(file_path, str(e))
    
    def _validate_zip(self, file_path: Path) -> Tuple[bool, str]:
        """Validate ZIP archive."""
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Test archive integrity
                bad_file = zf.testzip()
                if bad_file:
                    return False, self.format_error(file_path, f"Corrupted file in archive: {bad_file}")
                
                file_count = len(zf.namelist())
                
                # If recursive validation is enabled, validate contents
                if self.recursive_validate:
                    return self._validate_archive_contents(zf, file_path, file_count, 'zip')
                
                return True, self.format_valid(file_path, f"ZIP, {file_count} files")
        
        except zipfile.BadZipFile as e:
            return False, self.format_error(file_path, str(e))
    
    def _validate_tar(self, file_path: Path) -> Tuple[bool, str]:
        """Validate TAR archive."""
        try:
            with tarfile.open(file_path, 'r:*') as tf:
                # Count files
                file_count = len([m for m in tf.getmembers() if m.isfile()])
                
                # If recursive validation is enabled, validate contents
                if self.recursive_validate:
                    return self._validate_archive_contents(tf, file_path, file_count, 'tar')
                
                return True, self.format_valid(file_path, f"TAR, {file_count} files")
        
        except tarfile.TarError as e:
            return False, self.format_error(file_path, str(e))
    
    def _validate_archive_contents(self, archive, file_path: Path, file_count: int, archive_type: str) -> Tuple[bool, str]:
        """Validate contents of archive recursively."""
        from . import get_validators
        from ..validation import validate_files
        
        # Create temporary directory for extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Extract archive
                if archive_type == 'zip':
                    archive.extractall(temp_path)
                else:  # tar
                    archive.extractall(temp_path)
                
                # Get all extracted files, excluding archive validator to avoid recursion
                extracted_files = []
                for extracted_file in temp_path.rglob('*'):
                    if not extracted_file.is_file():
                        continue
                    
                    # Check if any non-archive validators exist for this file
                    validators = [v for v in get_validators(extracted_file) 
                                 if not isinstance(v, ArchiveValidator)]
                    
                    if validators:
                        extracted_files.append(extracted_file)
                
                if not extracted_files:
                    return True, self.format_valid(file_path, f"{archive_type.upper()}, {file_count} files")
                
                # Validate using shared function (but collect results quietly)
                import io
                import contextlib
                
                # Capture output to check for errors
                output_buffer = io.StringIO()
                with contextlib.redirect_stdout(output_buffer):
                    valid_count, invalid_count, skipped_count = validate_files(extracted_files)
                
                # If there are invalid files, extract error messages
                if invalid_count > 0:
                    output = output_buffer.getvalue()
                    error_lines = [line for line in output.split('\n') if '✗' in line]
                    issues = "; ".join(error_lines[:3])  # Show first 3
                    if len(error_lines) > 3:
                        issues += f" and {len(error_lines) - 3} more"
                    return False, self.format_error(file_path, f"Contains invalid files: {issues}")
                
                return True, self.format_valid(file_path, f"{archive_type.upper()}, {file_count} files, all validated")
            
            except Exception as e:
                return False, self.format_error(file_path, f"Error validating archive contents: {str(e)}")
