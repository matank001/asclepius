"""Video file validator using ffmpeg."""

from pathlib import Path
from typing import Tuple
import ffmpeg
import shutil

from .base import FileValidator


class VideoValidator(FileValidator):
    """Validator that checks video file integrity using ffmpeg."""
    
    def __init__(self):
        """Initialize video validator and check for ffprobe."""
        self.ffprobe_available = shutil.which('ffprobe') is not None
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate video file integrity.
        
        Args:
            file_path: Path to the video file to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"
        
        # Check if ffprobe is available
        if not self.ffprobe_available:
            return False, f"⊘ Skipped: {file_path.name} - ffprobe not installed (install ffmpeg to validate videos)"
        
        # Try to probe video file with ffmpeg
        try:
            probe = ffmpeg.probe(str(file_path))
            
            # Get video stream info
            video_streams = [s for s in probe.get('streams', []) if s.get('codec_type') == 'video']
            audio_streams = [s for s in probe.get('streams', []) if s.get('codec_type') == 'audio']
            
            if not video_streams:
                return False, f"✗ No video stream found in {file_path.name}"
            
            # Get primary video stream info
            video = video_streams[0]
            codec = video.get('codec_name', 'unknown')
            width = video.get('width', 0)
            height = video.get('height', 0)
            duration = float(probe.get('format', {}).get('duration', 0))
            
            # Check for corruption indicators
            corruption_indicators = []
            
            # Check for missing or invalid dimensions
            if width == 0 or height == 0:
                corruption_indicators.append("invalid dimensions")
            
            # Check for missing pixel format
            pix_fmt = video.get('pix_fmt')
            if not pix_fmt or pix_fmt == 'none':
                corruption_indicators.append("unspecified pixel format")
            
            # Check codec parameters
            codec_tag = video.get('codec_tag_string', '')
            if not codec_tag or codec_tag == '0x00000000':
                corruption_indicators.append("missing codec parameters")
            
            # Check for extremely short or zero duration (suspicious)
            if duration < 0.1 and duration != 0:  # Allow 0 for images/single frame
                corruption_indicators.append(f"suspicious duration ({duration:.3f}s)")
            
            # If corruption detected, report as invalid
            if corruption_indicators:
                issues = ", ".join(corruption_indicators)
                return False, f"✗ Video corruption in {file_path.name}: {issues}"
            
            # Build info message
            info_parts = [f"{codec}", f"{width}x{height}"]
            if duration > 0:
                info_parts.append(f"{duration:.1f}s")
            if audio_streams:
                audio_codec = audio_streams[0].get('codec_name', 'unknown')
                info_parts.append(f"audio:{audio_codec}")
            
            info = ", ".join(info_parts)
            return True, f"✓ Valid: {file_path.name} ({info})"
            
        except ffmpeg.Error as e:
            error_msg = e.stderr.decode() if e.stderr else str(e)
            # Extract relevant error message
            lines = error_msg.split('\n')
            relevant_lines = [l for l in lines if 'error' in l.lower() or 'invalid' in l.lower()]
            error_summary = relevant_lines[0] if relevant_lines else "ffmpeg probe failed"
            return False, f"✗ Video corruption in {file_path.name}: {error_summary}"
        
        except Exception as e:
            return False, f"✗ Error validating {file_path.name}: {str(e)}"
