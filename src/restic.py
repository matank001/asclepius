"""Restic repository validation."""

import os
import subprocess
import shutil
import json
import tempfile
from pathlib import Path
import click


def check_restic_repository(repo: str, password: str) -> bool:
    """
    Check Restic repository integrity.
    
    Args:
        repo: Restic repository path
        password: Restic repository password
        
    Returns:
        True if check passed, False otherwise
    """
    # Check if restic is installed
    if not shutil.which('restic'):
        click.echo(click.style("✗ Restic not installed", fg='red'))
        click.echo("Install restic: https://restic.readthedocs.io/")
        return False
    
    click.echo(f"\nChecking Restic repository: {repo}")
    click.echo("=" * 60)
    
    # Set up environment
    env = os.environ.copy()
    env["RESTIC_REPOSITORY"] = repo
    env["RESTIC_PASSWORD"] = password
    
    try:
        # Run restic check
        result = subprocess.run(
            ["restic", "check", "--read-data"],
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            click.echo(click.style("✓ Restic repository check passed", fg='green'))
            # Show output
            if result.stdout:
                click.echo(result.stdout)
            return True
        else:
            click.echo(click.style(f"✗ Restic repository check failed", fg='red'))
            if result.stderr:
                click.echo(result.stderr, err=True)
            return False
    
    except Exception as e:
        click.echo(click.style(f"✗ Error running restic check: {str(e)}", fg='red'))
        return False


def restore_and_validate(repo: str, password: str, snapshot_id: str = None, rand_sample: int = None) -> bool:
    """
    Restore snapshot(s) and validate contents.
    
    Args:
        repo: Restic repository path
        password: Restic repository password
        snapshot_id: Specific snapshot ID (optional, None/empty = validate all snapshots)
        rand_sample: Number of random files to sample from each snapshot (optional)
        
    Returns:
        True if validation passed, False otherwise
    """
    import random
    from .validation import validate_files, print_summary
    
    # Set up environment
    env = os.environ.copy()
    env["RESTIC_REPOSITORY"] = repo
    env["RESTIC_PASSWORD"] = password
    
    try:
        # Get snapshots list
        click.echo(f"\nGetting snapshots from repository...")
        result = subprocess.run(
            ["restic", "snapshots", "--json"],
            env=env,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            click.echo(click.style("✗ Failed to get snapshots", fg='red'))
            if result.stderr:
                click.echo(result.stderr, err=True)
            return False
        
        snapshots = json.loads(result.stdout)
        
        if not snapshots:
            click.echo(click.style("✗ No snapshots found in repository", fg='red'))
            return False
        
        # Determine which snapshots to validate
        if snapshot_id:
            # Validate specific snapshot
            snapshots_to_validate = [(snapshot_id, f"Snapshot {snapshot_id}")]
            click.echo(f"Validating specific snapshot: {snapshot_id}\n")
        else:
            # Validate all snapshots
            snapshots_to_validate = [(s['short_id'], s['time']) for s in snapshots]
            click.echo(f"Validating all {len(snapshots_to_validate)} snapshots\n")
        
        # Track overall results
        all_passed = True
        
        # Validate each snapshot
        for snap_id, snap_time in snapshots_to_validate:
            click.echo(f"{'='*60}")
            click.echo(f"Snapshot: {snap_id} ({snap_time})")
            click.echo(f"{'='*60}")
            
            # Create temporary directory for restoration
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir) / "restore"
                
                click.echo(f"Restoring snapshot...")
                result = subprocess.run(
                    ["restic", "restore", snap_id, "--target", str(temp_path)],
                    env=env,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    click.echo(click.style(f"✗ Failed to restore snapshot {snap_id}", fg='red'))
                    if result.stderr:
                        click.echo(result.stderr, err=True)
                    all_passed = False
                    continue
                
                click.echo(click.style("✓ Snapshot restored successfully", fg='green'))
                
                # Get all files from restored directory
                all_files = [f for f in temp_path.rglob('*') if f.is_file()]
                
                if not all_files:
                    click.echo(click.style(f"✗ No files found in snapshot {snap_id}", fg='red'))
                    all_passed = False
                    continue
                
                # Apply random sampling if requested
                if rand_sample:
                    if rand_sample > len(all_files):
                        click.echo(f"Warning: Requested sample size ({rand_sample}) is greater than total files ({len(all_files)}). Validating all files.")
                        files_to_validate = all_files
                    else:
                        files_to_validate = random.sample(all_files, rand_sample)
                        click.echo(f"Randomly selected {len(files_to_validate)} files from {len(all_files)} total files")
                else:
                    files_to_validate = all_files
                    click.echo(f"Found {len(files_to_validate)} files to validate")
                
                click.echo("")
                
                # Validate restored files
                valid_count, invalid_count, skipped_count = validate_files(files_to_validate)
                
                # Print summary
                print_summary(valid_count, invalid_count, skipped_count)
                
                if invalid_count > 0:
                    all_passed = False
                
                click.echo("")  # Extra line between snapshots
        
        # Overall result
        if len(snapshots_to_validate) > 1:
            click.echo(f"{'='*60}")
            if all_passed:
                click.echo(click.style(f"✓ All {len(snapshots_to_validate)} snapshots validated successfully", fg='green'))
            else:
                click.echo(click.style("✗ Some snapshots failed validation", fg='red'))
            click.echo(f"{'='*60}")
        
        return all_passed
    
    except json.JSONDecodeError as e:
        click.echo(click.style(f"✗ Failed to parse snapshots JSON: {str(e)}", fg='red'))
        return False
    
    except Exception as e:
        click.echo(click.style(f"✗ Error during restore and validate: {str(e)}", fg='red'))
        return False
