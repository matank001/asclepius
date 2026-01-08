"""Shared validation logic for files and directories."""

from pathlib import Path
import click
from .validators import get_validators


def validate_files(files_to_validate: list[Path]) -> tuple[int, int, int]:
    """
    Validate a list of files.
    
    Args:
        files_to_validate: List of file paths to validate
        
    Returns:
        Tuple of (valid_count, invalid_count, skipped_count)
    """
    valid_count = 0
    invalid_count = 0
    skipped_count = 0
    
    for file_path in files_to_validate:
        validators = get_validators(file_path)
        
        # Track if file passed all validators
        all_valid = True
        file_skipped = False
        messages = []
        
        # Run all validators on this file
        for validator in validators:
            is_valid, message = validator.validate(file_path)
            
            if "Unsupported file type" in message or "Skipped:" in message:
                file_skipped = True
                messages.append(message)
            elif not is_valid:
                all_valid = False
                messages.append(message)
        
        # Report results
        if file_skipped:
            skipped_count += 1
            for msg in messages:
                if "Unsupported file type" in msg:
                    click.echo(f"⊘ Unsupported: {file_path.name} - {msg}")
                else:
                    click.echo(msg)
        elif all_valid:
            valid_count += 1
            # Don't print valid files - only show invalid ones
        else:
            invalid_count += 1
            for msg in messages:
                # Color invalid messages in red
                colored_msg = click.style(msg, fg='red')
                click.echo(colored_msg, err=True)
    
    return valid_count, invalid_count, skipped_count


def print_summary(valid_count: int, invalid_count: int, skipped_count: int):
    """
    Print validation summary.
    
    Args:
        valid_count: Number of valid files
        invalid_count: Number of invalid files
        skipped_count: Number of skipped files
    """
    click.echo(f"\n{'='*60}")
    click.echo(f"Summary:")
    
    # Color valid count in green
    valid_text = click.style(f"  Valid:   {valid_count}", fg='green')
    click.echo(valid_text)
    
    # Color invalid count in red
    invalid_text = click.style(f"  Invalid: {invalid_count}", fg='red')
    click.echo(invalid_text)
    
    if skipped_count > 0:
        click.echo(f"  Skipped: {skipped_count} (unsupported types)")
    click.echo(f"{'='*60}")
