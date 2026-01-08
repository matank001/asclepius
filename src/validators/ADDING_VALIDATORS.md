# Adding New Validators

The validator system is **fully automatic** - just create a validator class and it will be discovered. No need to modify `__init__.py`!

## Step 1: Create Validator Class

Create a new file in `src/validators/` (e.g., `my_validator.py`):

```python
"""My custom validator."""

from pathlib import Path
from typing import Tuple
from .base import FileValidator


class MyCustomValidator(FileValidator):
    """Validates my custom file type."""
    
    def validate(self, file_path: Path) -> Tuple[bool, str]:
        """Validate the file."""
        if not file_path.exists():
            return False, f"File does not exist: {file_path}"
        
        if not file_path.is_file():
            return False, f"Not a file: {file_path}"
        
        try:
            # Your validation logic here
            # Example: check file can be read
            with open(file_path, 'rb') as f:
                data = f.read()
            
            return True, f"✓ Valid: {file_path.name}"
        
        except Exception as e:
            return False, f"✗ Error in {file_path.name}: {str(e)}"
```

## Step 2: Add to `validators.yaml`

Add your validator configuration using the **class name**:

```yaml
validators:
  MyCustomValidator:  # Must match the class name exactly
    description: "My custom file validator"
    mime_types:
      - "application/x-custom"
    extensions:
      - ".myext"
      - ".custom"
```

## That's It!

The validator will be **automatically discovered** when the module loads. No need to:
- ❌ Import it in `__init__.py`
- ❌ Register it manually
- ❌ Modify any other code

Just create the file and add the config. The system will:
- ✅ Scan the `validators/` directory
- ✅ Find all classes inheriting from `FileValidator`
- ✅ Register them automatically
- ✅ Make them available for file matching

## Multiple Validators per File Type

A file can be validated by **multiple validators**! Simply add the same extension or MIME type to multiple validators in `validators.yaml`:

```yaml
validators:
  ImageValidator:
    extensions:
      - ".jpg"
      - ".png"
  
  MetadataValidator:  # Your custom validator
    extensions:
      - ".jpg"  # Same extension!
      - ".png"
```

When a `.jpg` file is validated, **both** `ImageValidator` and `MetadataValidator` will run. The file is only marked as valid if **all** validators pass.

## Notes

- Validator names in `validators.yaml` **must match** the class name exactly
- The system uses file type detection (not just extensions) for accurate matching
- Validators are instantiated dynamically based on configuration
- Multiple validators can validate the same file - all must pass for the file to be valid