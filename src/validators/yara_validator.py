"""YARA-based malware detection validator."""

from pathlib import Path
from typing import Tuple
import yara
import click

from .base import FileValidator


class YaraValidator(FileValidator):
    """Validator that scans files using YARA rules for malware detection."""
    
    # Class variable to track if warning has been shown
    _warning_shown = False
    _rules_available = False
    
    def __init__(self):
        """Initialize YARA validator and load rules."""
        from ..config import ValidatorConfig
        
        config = ValidatorConfig()
        rules_dir = config.get_setting('yara_rules_path', 'yara-rules')
        
        self.rules = None
        self.rules_path = Path(__file__).parent.parent.parent / rules_dir
        self.yara_available = self._check_yara_available()
        self.load_error = None
        
        if self.yara_available:
            self._load_rules()
            
        # Update class variable to track if any instance has rules
        if self.rules:
            YaraValidator._rules_available = True
            
        # Show warning once if rules aren't available
        if not self.rules and not YaraValidator._warning_shown:
            if self.rules_path.exists():
                error_msg = f": {self.load_error}" if self.load_error else ""
                click.echo(click.style(f"⚠ Warning: YARA rules found but failed to compile{error_msg}", fg='yellow'))
                click.echo(click.style("  YARA validation will be skipped.", fg='yellow'))
            else:
                click.echo(click.style("⚠ Warning: YARA rules not found (clone yara-rules repository). YARA validation will be skipped.", fg='yellow'))
            YaraValidator._warning_shown = True
    
    def is_enabled(self) -> bool:
        """Check if YARA validator is enabled (has rules loaded)."""
        return self.rules is not None
    
    def _check_yara_available(self) -> bool:
        """Check if YARA is properly installed."""
        try:
            import yara
            return True
        except ImportError:
            return False
    
    def _load_rules(self):
        """Load YARA rules from the yara-rules directory."""
        if not self.rules_path.exists():
            return
        
        try:
            # Try to load the main index file
            index_file = self.rules_path / "index.yar"
            if index_file.exists():
                self.rules = yara.compile(str(index_file))
            else:
                # Fallback: compile individual rule files
                rule_files = {}
                for rule_file in self.rules_path.rglob("*.yar"):
                    if rule_file.is_file() and not rule_file.name.startswith('index'):
                        namespace = rule_file.stem
                        rule_files[namespace] = str(rule_file)
                
                if rule_files:
                    self.rules = yara.compile(filepaths=rule_files)
        
        except Exception as e:
            # Store error for display in startup warning
            self.load_error = str(e)
            self.rules = None
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """
        Scan file with YARA rules for malware detection.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"
        
        # Skip validation silently if YARA is not available or rules not loaded
        if not self.yara_available or not self.rules:
            # Return as valid - validation is skipped silently
            return True, self.format_valid(file_path)
        
        # Scan file with YARA rules
        try:
            matches = self.rules.match(str(file_path))
            
            if matches:
                # File matched malware signatures
                match_names = [m.rule for m in matches[:3]]  # Show first 3 matches
                if len(matches) > 3:
                    match_names.append(f"and {len(matches) - 3} more")
                
                matches_str = ", ".join(match_names)
                return False, self.format_error(file_path, f"MALWARE DETECTED: {matches_str}")
            
            # No matches - file appears clean
            return True, self.format_valid(file_path, "YARA scan passed")
        
        except Exception as e:
            return False, self.format_error(file_path, str(e))
