# Asclepius

<div align="center">
  <img src="logo.png" alt="Asclepius Logo" width="200"/>
</div>


Asclepius validates backup integrity by restoring files and actively testing their recoverability. Instead of trusting metadata, it attempts to parse real file formats (documents, images, videos, archives, emails) to confirm backups can actually be read.

## Installation

```bash
git clone <repository-url>
cd asclepius
uv sync
```

## Additional Dependencies

### FFmpeg (for video validation)

```bash
# macOS
brew install ffmpeg

# Ubuntu/Debian
sudo apt install ffmpeg

# Arch Linux
sudo pacman -S ffmpeg
```

## Usage

### Single File Validation

```bash
uv run asclepius -f /path/to/file.pdf
```

### Directory Validation

```bash
# Validate all files in directory
uv run asclepius -d /path/to/backups

# Randomly sample N files from directory
uv run asclepius -d /path/to/backups --rand-sample 100
```

### Restic Integration

Unlike `restic check` which verifies repository structure and data integrity, Asclepius performs **functional validation** by restoring snapshots and testing if files are actually readable and parseable.

#### Repository Check Only

Runs `restic check --read-data` to verify repository integrity:

```bash
uv run asclepius --restic-repo /path/to/repo --restic-passwd your-password
```

#### Restore & Validate All Snapshots

Restores each snapshot to a temporary directory and validates all files:

```bash
# Validate all files in all snapshots
uv run asclepius --restic-repo /path/to/repo --restic-passwd your-password --recover

# Validate random 100 files from each snapshot (faster for large backups)
uv run asclepius --restic-repo /path/to/repo --restic-passwd your-password --recover --rand-sample 100
```

#### Restore & Validate Specific Snapshot

Restores and validates a single snapshot by ID:

```bash
# Validate all files in specific snapshot
uv run asclepius --restic-repo /path/to/repo --restic-passwd your-password --recover --snapshot ab4eb95a

# Validate random 50 files from specific snapshot
uv run asclepius --restic-repo /path/to/repo --restic-passwd your-password --recover --snapshot ab4eb95a --rand-sample 50
```

## Validators

- **Documents** (PDF, DOCX, PPTX, etc.) - MarkItDown parsing + entropy analysis
- **Images** (JPEG, PNG, GIF, etc.) - PIL structural verification
- **Videos** (MP4, AVI, MKV, etc.) - FFprobe corruption detection
- **Archives** (ZIP, TAR) - Integrity check + recursive content validation
- **Emails** (EML) - Parse validation + header verification
- **Malware** (All formats) - YARA rule scanning

## Configuration

Validators are configured in `validators.yaml`. Each validator specifies supported MIME types, file extensions, and validation settings.
