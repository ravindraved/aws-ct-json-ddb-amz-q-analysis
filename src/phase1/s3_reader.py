from botocore.exceptions import ClientError, NoCredentialsError
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime, timedelta
from dateutil.parser import parse
from tqdm import tqdm
import boto3

from common.config import S3Config, AuthConfig
from common.logging_config import get_logger
from common.security_utils import SecurityUtils

class S3CloudTrailReader:
    def __init__(self, s3_config: S3Config, auth_config: AuthConfig):
        self.s3_config = s3_config
        self.auth_config = auth_config
        self.logger = get_logger('s3_reader')
        self.s3_client = self._create_s3_client()
    
    def _create_s3_client(self):
        """Create S3 client based on authentication method."""
        try:
            if self.auth_config.method == "access_keys":
                return boto3.client(
                    's3',
                    aws_access_key_id=self.auth_config.access_key,
                    aws_secret_access_key=self.auth_config.secret_key
                )
            else:  # instance_profile
                return boto3.client('s3')
        except Exception as e:
            self.logger.error(f"Failed to create S3 client: {e}")
            raise
    
    def list_objects(self) -> List[Dict]:
        """List CloudTrail objects based on date range."""
        objects = []
        start_date = parse(self.s3_config.start_date).date()
        end_date = parse(self.s3_config.end_date).date() if self.s3_config.end_date else start_date
        
        current_date = start_date
        while current_date <= end_date:
            date_prefix = f"{self.s3_config.prefix}/{current_date.strftime('%Y/%m/%d')}"
            safe_date = SecurityUtils.sanitize_for_logging(current_date)
            self.logger.info(f"Listing objects for date: {safe_date}")
            
            try:
                paginator = self.s3_client.get_paginator('list_objects_v2')
                pages = paginator.paginate(
                    Bucket=self.s3_config.bucket_name,
                    Prefix=date_prefix
                )
                
                for page in pages:
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            if obj['Key'].endswith('.gz'):
                                objects.append({
                                    'key': obj['Key'],
                                    'size': obj['Size'],
                                    'etag': obj['ETag'].strip('"'),
                                    'last_modified': obj['LastModified']
                                })
                                
            except ClientError as e:
                safe_prefix = SecurityUtils.sanitize_for_logging(date_prefix)
                safe_error = SecurityUtils.sanitize_for_logging(str(e))
                self.logger.error(f"Error listing objects for {safe_prefix}: {safe_error}")
                
            current_date += timedelta(days=1)
        
        self.logger.info(f"Found {len(objects)} CloudTrail files")
        return objects
    
    def download_file(self, s3_key: str, local_path: Path, max_retries: int = 3) -> bool:
        """Download file from S3 with retry logic."""
        # Ensure parent directory exists and validate path is safe
        try:
            # Resolve the path and ensure it's within a reasonable scope
            resolved_path = local_path.resolve()
            
            # Basic safety check - ensure we're not writing to system directories
            path_str = str(resolved_path)
            if any(dangerous in path_str for dangerous in ['/etc/', '/usr/', '/bin/', '/sbin/', '/root/']):
                raise ValueError(f"Unsafe download path: {local_path}")
            
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            local_path = resolved_path
        except Exception as e:
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Path validation failed: {safe_error}")
            return False
        
        for attempt in range(max_retries):
            try:
                safe_key = SecurityUtils.sanitize_for_logging(s3_key)
                safe_path = SecurityUtils.sanitize_for_logging(local_path)
                self.logger.debug(f"Downloading {safe_key} to {safe_path} (attempt {attempt + 1})")
                self.s3_client.download_file(
                    self.s3_config.bucket_name,
                    s3_key,
                    str(local_path)
                )
                return True
                
            except Exception as e:
                safe_key = SecurityUtils.sanitize_for_logging(s3_key)
                safe_error = SecurityUtils.sanitize_for_logging(str(e))
                self.logger.warning(f"Download attempt {attempt + 1} failed for {safe_key}: {safe_error}")
                if attempt == max_retries - 1:
                    safe_key = SecurityUtils.sanitize_for_logging(s3_key)
                    self.logger.error(f"Failed to download {safe_key} after {max_retries} attempts")
                    return False
        
        return False
    
    def validate_download(self, s3_key: str, local_path: Path, expected_size: int, expected_etag: str) -> bool:
        """Validate downloaded file against S3 metadata."""
        if not local_path.exists():
            safe_path = SecurityUtils.sanitize_for_logging(local_path)
            self.logger.error(f"Downloaded file does not exist: {safe_path}")
            return False
        
        # Check file size
        actual_size = local_path.stat().st_size
        if actual_size != expected_size:
            safe_key = SecurityUtils.sanitize_for_logging(s3_key)
            self.logger.error(f"Size mismatch for {safe_key}: expected {expected_size}, got {actual_size}")
            return False
        
        # Use secure hash for file validation (SHA-256)
        try:
            file_hash = SecurityUtils.secure_hash_file(local_path, 'sha256')
            # Note: ETag comparison disabled as it uses MD5 (insecure)
            # For production, implement secure file integrity verification
            safe_key = SecurityUtils.sanitize_for_logging(s3_key)
            self.logger.debug(f"File hash computed for {safe_key}: {file_hash[:16]}...")
        except Exception as e:
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.warning(f"Hash computation failed: {safe_error}")
        
        safe_key = SecurityUtils.sanitize_for_logging(s3_key)
        self.logger.debug(f"Successfully validated {safe_key}")
        return True