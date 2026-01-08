#!/usr/bin/env python3
"""Asclepius - File Integrity Validator for Backups."""

import click
import random
from pathlib import Path
from src.validation import validate_files, print_summary
from src.restic import check_restic_repository, restore_and_validate


@click.command()
@click.option('-f', '--file', 'file_path', type=click.Path(exists=True), help='Validate a single file')
@click.option('-d', '--dir', 'dir_path', type=click.Path(exists=True), help='Validate all files in a directory')
@click.option('--rand-sample', type=int, default=None, help='Randomly sample N files from directory (requires -d)')
@click.option('--restic-repo', type=str, default=None, help='Restic repository path')
@click.option('--restic-passwd', type=str, default=None, help='Restic repository password')
@click.option('--recover', is_flag=True, default=False, help='Restore and validate latest snapshot')
@click.option('--snapshot', type=str, default=None, help='Specific snapshot ID (use with --recover)')
def main(file_path, dir_path, rand_sample, restic_repo, restic_passwd, recover, snapshot):
    """Validate file integrity for backups using MarkItDown parser."""
    
    # Check if restic validation is requested
    if restic_repo or restic_passwd or recover:
        if not (restic_repo and restic_passwd):
            click.echo("Error: Both --restic-repo and --restic-passwd are required for restic operations")
            raise click.Abort()
        
        # Check if snapshot is specified without recover
        if snapshot and not recover:
            click.echo("Error: --snapshot requires --recover")
            raise click.Abort()
        
        # Run restic check
        result = check_restic_repository(restic_repo, restic_passwd)
        if not result:
            raise SystemExit(1)
        
        # If restore/recover is requested
        if recover:
            result = restore_and_validate(restic_repo, restic_passwd, snapshot, rand_sample)
            if not result:
                raise SystemExit(1)
            return
        
        # If no file/dir validation requested, exit after restic check
        if not file_path and not dir_path:
            return
    
    if not file_path and not dir_path:
        click.echo("Error: Please specify either --file, --dir, or --restic-repo")
        raise click.Abort()
    
    if file_path and dir_path:
        click.echo("Error: Please specify only one of --file or --dir")
        raise click.Abort()
    
    # Check if rand_sample is used without directory
    if rand_sample and not dir_path:
        click.echo("Error: --rand-sample requires --dir")
        raise click.Abort()
    
    files_to_validate = []
    
    if file_path:
        files_to_validate = [Path(file_path)]
    elif dir_path:
        dir_path = Path(dir_path)
        # Get all files recursively
        all_files = [f for f in dir_path.rglob('*') if f.is_file()]
        total_files = len(all_files)
        
        # Apply random sampling if requested
        if rand_sample:
            if rand_sample > total_files:
                click.echo(f"Warning: Requested sample size ({rand_sample}) larger than total files ({total_files})")
                click.echo(f"Using all {total_files} files\n")
                files_to_validate = all_files
            else:
                files_to_validate = random.sample(all_files, rand_sample)
                click.echo(f"Randomly sampled {rand_sample} files from {total_files} total files in {dir_path}\n")
        else:
            files_to_validate = all_files
            click.echo(f"Found {len(files_to_validate)} files in {dir_path}\n")
    
    if not files_to_validate:
        click.echo("No files found to validate")
        return
    
    # Validate files using shared function
    valid_count, invalid_count, skipped_count = validate_files(files_to_validate)
    
    # Print summary
    print_summary(valid_count, invalid_count, skipped_count)
    
    if invalid_count > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
