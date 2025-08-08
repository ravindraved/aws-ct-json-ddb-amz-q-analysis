import gzip
import json
from pathlib import Path
from typing import Dict, Any

from common.logging_config import get_logger
from common.security_utils import SecurityUtils

class FileDecompressor:
    def __init__(self):
        self.logger = get_logger('decompressor')
    
    def decompress_file(self, gz_path: Path, json_path: Path) -> bool:
        """Decompress gz file to JSON."""
        try:
            # Resolve paths and basic security validation
            resolved_gz = gz_path.resolve()
            resolved_json = json_path.resolve()
            
            # Basic safety check - ensure we're not accessing system directories
            for path in [resolved_gz, resolved_json]:
                path_str = str(path)
                if any(dangerous in path_str for dangerous in ['/etc/', '/usr/', '/bin/', '/sbin/', '/root/']):
                    raise ValueError(f"Unsafe file path: {path}")
            
            resolved_json.parent.mkdir(parents=True, exist_ok=True)
            gz_path = resolved_gz
            json_path = resolved_json
            
            with gzip.open(gz_path, 'rt', encoding='utf-8') as gz_file:
                with open(json_path, 'w', encoding='utf-8') as json_file:
                    json_file.write(gz_file.read())
            
            safe_gz = SecurityUtils.sanitize_for_logging(gz_path)
            safe_json = SecurityUtils.sanitize_for_logging(json_path)
            self.logger.debug(f"Successfully decompressed {safe_gz} to {safe_json}")
            return True
            
        except Exception as e:
            safe_gz = SecurityUtils.sanitize_for_logging(str(gz_path))
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Failed to decompress {safe_gz}: {safe_error}")
            return False
    
    def validate_json(self, json_path: Path) -> bool:
        """Validate JSON structure."""
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Basic CloudTrail structure validation
            if not isinstance(data, dict):
                safe_path = SecurityUtils.sanitize_for_logging(json_path)
                self.logger.error(f"Invalid JSON structure in {safe_path}: not a dictionary")
                return False
            
            if 'Records' not in data:
                safe_path = SecurityUtils.sanitize_for_logging(json_path)
                self.logger.error(f"Invalid CloudTrail structure in {safe_path}: missing 'Records' field")
                return False
            
            if not isinstance(data['Records'], list):
                safe_path = SecurityUtils.sanitize_for_logging(json_path)
                self.logger.error(f"Invalid CloudTrail structure in {safe_path}: 'Records' is not a list")
                return False
            
            safe_path = SecurityUtils.sanitize_for_logging(json_path)
            self.logger.debug(f"Successfully validated JSON structure in {safe_path}")
            return True
            
        except json.JSONDecodeError as e:
            safe_path = SecurityUtils.sanitize_for_logging(json_path)
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Invalid JSON in {safe_path}: {safe_error}")
            return False
        except Exception as e:
            safe_path = SecurityUtils.sanitize_for_logging(json_path)
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Error validating JSON {safe_path}: {safe_error}")
            return False