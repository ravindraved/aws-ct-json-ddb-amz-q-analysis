"""
Security utilities for CloudTrail analyzer following Amazon secure coding guidelines.
"""
import re
import hashlib
from pathlib import Path
from typing import Union, Optional


class SecurityUtils:
    """Security utilities for input validation and sanitization."""
    
    # Regex patterns for validation
    SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
    LOG_SAFE_PATTERN = re.compile(r'[\r\n\t]')
    
    @staticmethod
    def sanitize_for_logging(value: Union[str, Path, None]) -> str:
        """
        Sanitize input for safe logging to prevent log injection attacks.
        
        Args:
            value: Input value to sanitize
            
        Returns:
            Sanitized string safe for logging
        """
        if value is None:
            return "None"
        
        # Convert to string and limit length
        str_value = str(value)[:500]  # Limit log entry length
        
        # Remove/replace dangerous characters
        sanitized = SecurityUtils.LOG_SAFE_PATTERN.sub('_', str_value)
        
        # Additional sanitization for common injection patterns
        sanitized = sanitized.replace('\x00', '_')  # Null bytes
        sanitized = sanitized.replace('\x1b', '_')  # Escape sequences
        
        return sanitized
    
    @staticmethod
    def validate_file_path(file_path: Union[str, Path], base_path: Union[str, Path]) -> Path:
        """
        Validate and resolve file path to prevent path traversal attacks.
        
        Args:
            file_path: File path to validate
            base_path: Base directory path
            
        Returns:
            Validated and resolved Path object
            
        Raises:
            ValueError: If path is invalid or contains traversal attempts
        """
        try:
            # Convert to Path objects and resolve
            base = Path(base_path).resolve()
            target = Path(file_path)
            
            # If target is absolute, make it relative to base
            if target.is_absolute():
                # Extract relative part after base path
                try:
                    target = target.relative_to(base)
                except ValueError:
                    # If not under base, reject
                    raise ValueError(f"Path {file_path} is outside base directory")
            
            # Resolve the final path
            resolved = (base / target).resolve()
            
            # Ensure resolved path is still under base directory
            try:
                resolved.relative_to(base)
            except ValueError:
                raise ValueError(f"Path traversal detected in {file_path}")
            
            return resolved
            
        except Exception as e:
            raise ValueError(f"Invalid file path {file_path}: {e}")
    
    @staticmethod
    def validate_filename(filename: str) -> bool:
        """
        Validate filename for security.
        
        Args:
            filename: Filename to validate
            
        Returns:
            True if filename is safe
        """
        if not filename or len(filename) > 255:
            return False
        
        # Check for dangerous patterns
        if '..' in filename or filename.startswith('.'):
            return False
        
        # Allow only safe characters
        return bool(SecurityUtils.SAFE_FILENAME_PATTERN.match(filename))
    
    @staticmethod
    def secure_hash_file(file_path: Path, algorithm: str = 'sha256') -> str:
        """
        Generate secure hash of file using SHA-256 or stronger.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha384, sha512)
            
        Returns:
            Hex digest of file hash
            
        Raises:
            ValueError: If algorithm is not secure
        """
        # Only allow secure hash algorithms
        allowed_algorithms = {'sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_384', 'sha3_512'}
        
        if algorithm not in allowed_algorithms:
            raise ValueError(f"Insecure hash algorithm: {algorithm}. Use one of {allowed_algorithms}")
        
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def validate_s3_key(s3_key: str) -> bool:
        """
        Validate S3 key for security.
        
        Args:
            s3_key: S3 object key to validate
            
        Returns:
            True if S3 key is safe
        """
        if not s3_key or len(s3_key) > 1024:
            return False
        
        # Check for dangerous patterns
        if '..' in s3_key or s3_key.startswith('/'):
            return False
        
        # S3 keys should not contain control characters
        if any(ord(c) < 32 for c in s3_key):
            return False
        
        return True
    
    @staticmethod
    def create_secure_temp_path(base_dir: Path, prefix: str = "temp_") -> Path:
        """
        Create a secure temporary file path.
        
        Args:
            base_dir: Base directory for temp file
            prefix: Filename prefix
            
        Returns:
            Secure temporary file path
        """
        import secrets
        import time
        
        # Generate secure random suffix
        random_suffix = secrets.token_hex(8)
        timestamp = int(time.time())
        
        filename = f"{prefix}{timestamp}_{random_suffix}"
        
        return base_dir / filename