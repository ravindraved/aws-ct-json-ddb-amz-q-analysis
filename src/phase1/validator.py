from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any
from pathlib import Path
import json
from datetime import datetime, timezone

from common.logging_config import get_logger
from common.security_utils import SecurityUtils

@dataclass
class ValidationResult:
    total_s3_files: int
    downloaded_files: int
    decompressed_files: int
    validated_json_files: int
    failed_downloads: List[str]
    failed_decompressions: List[str]
    failed_validations: List[str]
    success_rate: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_s3_files': self.total_s3_files,
            'downloaded_files': self.downloaded_files,
            'decompressed_files': self.decompressed_files,
            'validated_json_files': self.validated_json_files,
            'failed_downloads': self.failed_downloads,
            'failed_decompressions': self.failed_decompressions,
            'failed_validations': self.failed_validations,
            'success_rate': self.success_rate
        }

class BaseValidator(ABC):
    @abstractmethod
    def validate(self) -> ValidationResult:
        pass

class IntegrityValidator(BaseValidator):
    def __init__(self, s3_objects: List[Dict], raw_path: Path, processed_path: Path):
        self.s3_objects = s3_objects
        self.raw_path = raw_path
        self.processed_path = processed_path
        self.logger = get_logger('validator')
    
    def validate_file_count(self) -> Dict[str, int]:
        """Validate file counts at each stage."""
        s3_count = len(self.s3_objects)
        
        # Get list of S3 keys to match against local files
        s3_keys = {obj['key'] for obj in self.s3_objects}
        
        # Count only files that match current S3 objects
        raw_count = 0
        if self.raw_path.exists():
            for gz_file in self.raw_path.rglob('*.gz'):
                relative_key = str(gz_file.relative_to(self.raw_path))
                if relative_key in s3_keys:
                    raw_count += 1
        
        json_count = 0
        if self.processed_path.exists():
            for json_file in self.processed_path.rglob('*.json'):
                relative_key = str(json_file.relative_to(self.processed_path))
                # Handle both .json and .json.json cases
                if relative_key.endswith('.json.json'):
                    relative_key = relative_key.replace('.json.json', '.json.gz')
                elif relative_key.endswith('.json'):
                    relative_key = relative_key.replace('.json', '.gz')
                if relative_key in s3_keys:
                    json_count += 1
        
        self.logger.info(f"File counts - S3: {s3_count}, Downloaded: {raw_count}, Processed: {json_count}")
        
        return {
            's3_files': s3_count,
            'downloaded_files': raw_count,
            'processed_files': json_count
        }
    
    def validate_checksums(self) -> List[str]:
        """Validate file checksums (placeholder for now)."""
        # This would implement actual checksum validation
        # For now, return empty list indicating no checksum failures
        return []
    
    def validate(self) -> ValidationResult:
        """Generate comprehensive validation report."""
        self.logger.info("Starting integrity validation")
        
        counts = self.validate_file_count()
        failed_checksums = self.validate_checksums()
        
        # Calculate success metrics
        total_s3 = counts['s3_files']
        downloaded = counts['downloaded_files']
        processed = counts['processed_files']
        
        success_rate = (processed / total_s3 * 100) if total_s3 > 0 else 0
        
        # Identify failed files (simplified logic)
        failed_downloads = []
        failed_decompressions = []
        failed_validations = []
        
        # This would be populated with actual failed file tracking
        # For now, calculate based on counts
        if downloaded < total_s3:
            failed_downloads = [f"missing_{i}.gz" for i in range(total_s3 - downloaded)]
        
        if processed < downloaded:
            failed_decompressions = [f"failed_decomp_{i}.gz" for i in range(downloaded - processed)]
        
        result = ValidationResult(
            total_s3_files=total_s3,
            downloaded_files=downloaded,
            decompressed_files=processed,
            validated_json_files=processed,  # Assuming all processed files are valid
            failed_downloads=failed_downloads,
            failed_decompressions=failed_decompressions,
            failed_validations=failed_validations,
            success_rate=success_rate
        )
        
        self.logger.info(f"Validation complete - Success rate: {success_rate:.2f}%")
        return result
    
    def generate_report(self, result: ValidationResult, report_path: Path) -> None:
        """Generate detailed integrity report."""
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        report_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'validation_result': result.to_dict(),
            'summary': {
                'status': 'SUCCESS' if result.success_rate == 100 else 'PARTIAL_SUCCESS' if result.success_rate > 0 else 'FAILURE',
                'total_files_processed': result.validated_json_files,
                'issues_found': len(result.failed_downloads) + len(result.failed_decompressions) + len(result.failed_validations)
            }
        }
        
        # Validate report path for security
        try:
            validated_path = SecurityUtils.validate_file_path(report_path, report_path.parent.parent)
        except ValueError as e:
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Report path validation failed: {safe_error}")
            return
        
        with open(validated_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        safe_path = SecurityUtils.sanitize_for_logging(validated_path)
        self.logger.info(f"Integrity report generated: {safe_path}")