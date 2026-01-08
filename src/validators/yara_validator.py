"""YARA-based malware detection validator."""

from pathlib import Path
from typing import Tuple
import yara

from .base import FileValidator


class YaraValidator(FileValidator):
    """Validator that scans files using YARA rules for malware detection."""
    
    def __init__(self):
        """Initialize YARA validator and load rules."""
        from ..config import ValidatorConfig
        
        config = ValidatorConfig()
        rules_dir = config.get_setting('yara_rules_path', 'yara-rules')
        
        self.rules = None
        self.rules_path = Path(__file__).parent.parent.parent / rules_dir
        self.yara_available = self._check_yara_available()
        
        if self.yara_available:
            self._load_rules()
    
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
            print(f"Warning: Could not load YARA rules: {e}")
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
        
        # Check if YARA is available
        if not self.yara_available:
            return False, f"⊘ Skipped: {file_path.name} - YARA not installed"
        
        # Check if rules are loaded
        if not self.rules:
            return False, f"⊘ Skipped: {file_path.name} - YARA rules not loaded (clone yara-rules repository)"
        
        # Scan file with YARA rules
        try:
            matches = self.rules.match(str(file_path))
            
            if matches:
                # File matched malware signatures
                match_names = [m.rule for m in matches[:3]]  # Show first 3 matches
                if len(matches) > 3:
                    match_names.append(f"and {len(matches) - 3} more")
                
                matches_str = ", ".join(match_names)
                return False, f"✗ MALWARE DETECTED in {file_path.name}: {matches_str}"
            
            # No matches - file appears clean
            return True, f"✓ Clean: {file_path.name} (YARA scan passed)"
        
        except Exception as e:
            return False, f"✗ YARA scan error in {file_path.name}: {str(e)}"
