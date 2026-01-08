"""Entropy-based text validator for detecting corrupted or suspicious content."""

import math
from collections import Counter
from typing import Tuple


class EntropyValidator:
    """Validates text content using entropy analysis."""
    
    # Entropy thresholds (bits per character)
    MIN_ENTROPY = 1.5  # Too low = repetitive/corrupted
    MAX_ENTROPY = 5.5  # Too high = random/encrypted/binary
    
    def __init__(self, min_entropy: float = MIN_ENTROPY, max_entropy: float = MAX_ENTROPY):
        """
        Initialize entropy validator.
        
        Args:
            min_entropy: Minimum acceptable entropy (bits per character)
            max_entropy: Maximum acceptable entropy (bits per character)
        """
        self.min_entropy = min_entropy
        self.max_entropy = max_entropy
    
    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Entropy in bits per character
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        text_length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def validate_text(self, text: str, min_length: int = 10) -> Tuple[bool, str]:
        """
        Validate text content using entropy analysis.
        
        Args:
            text: Text content to validate
            min_length: Minimum text length to analyze
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Skip entropy analysis for short text - consider it valid
        if not text or len(text) < min_length:
            return True, "Valid (text too short for entropy analysis)"
        
        entropy = self.calculate_entropy(text)
        
        if entropy < self.min_entropy:
            return False, f"Low entropy detected ({entropy:.2f} bits/char) - possible corruption or repetitive content"
        
        if entropy > self.max_entropy:
            return False, f"High entropy detected ({entropy:.2f} bits/char) - possible binary/encrypted data"
        
        return True, f"Normal entropy ({entropy:.2f} bits/char)"
