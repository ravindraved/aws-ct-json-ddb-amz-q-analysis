from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
from dateutil.parser import parse

from common.logging_config import get_logger
from common.security_utils import SecurityUtils

class Phase1DataValidator:
    """Validates that Phase 1 data exists for requested date ranges."""
    
    def __init__(self, base_data_path: str = "data"):
        self.logger = get_logger('data_validator')
        
        # Resolve and validate base data path
        try:
            resolved_path = Path(base_data_path).resolve()
            
            # Basic safety check - ensure we're not accessing system directories
            path_str = str(resolved_path)
            if any(dangerous in path_str for dangerous in ['/etc/', '/usr/', '/bin/', '/sbin/', '/root/']):
                raise ValueError(f"Unsafe data path: {base_data_path}")
            
            self.base_data_path = resolved_path
        except Exception as e:
            # If validation fails, use Path but log warning
            self.base_data_path = Path(base_data_path).resolve()
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.warning(f"Base data path validation warning: {safe_error}")
    
    def validate_date_range(self, start_date: str, end_date: Optional[str] = None) -> Tuple[bool, List[str], List[str]]:
        """
        Validate that Phase 1 data exists for the requested date range.
        
        Returns:
            Tuple of (all_dates_available, available_dates, missing_dates)
        """
        try:
            start = parse(start_date).date()
            end = parse(end_date).date() if end_date else start
            
            available_dates = []
            missing_dates = []
            
            current_date = start
            while current_date <= end:
                date_str = current_date.strftime('%Y/%m/%d')
                
                # Check both raw and processed data
                raw_path = self.base_data_path / 'raw' / 'AWSLogs' / '*' / 'CloudTrail' / '*' / date_str.replace('/', '/')
                processed_path = self.base_data_path / 'processed' / 'AWSLogs' / '*' / 'CloudTrail' / '*' / date_str.replace('/', '/')
                
                # Check if processed data exists (preferred)
                if list(self.base_data_path.glob(f'processed/AWSLogs/*/CloudTrail/*/{current_date.strftime("%Y/%m/%d")}/*.json')):
                    available_dates.append(current_date.strftime('%Y-%m-%d'))
                    safe_date = SecurityUtils.sanitize_for_logging(str(current_date))
                    self.logger.debug(f"Found processed data for {safe_date}")
                elif list(self.base_data_path.glob(f'raw/AWSLogs/*/CloudTrail/*/{current_date.strftime("%Y/%m/%d")}/*.gz')):
                    available_dates.append(current_date.strftime('%Y-%m-%d'))
                    safe_date = SecurityUtils.sanitize_for_logging(str(current_date))
                    self.logger.warning(f"Found raw data but no processed data for {safe_date}")
                else:
                    missing_dates.append(current_date.strftime('%Y-%m-%d'))
                    safe_date = SecurityUtils.sanitize_for_logging(str(current_date))
                    self.logger.warning(f"No data found for {safe_date}")
                
                current_date += timedelta(days=1)
            
            all_available = len(missing_dates) == 0
            
            self.logger.info(f"Date validation: {len(available_dates)} available, {len(missing_dates)} missing")
            return all_available, available_dates, missing_dates
            
        except Exception as e:
            self.logger.error(f"Date validation failed: {e}")
            return False, [], []
    
    def get_available_date_ranges(self) -> List[str]:
        """Get all available date ranges from processed data."""
        try:
            processed_path = self.base_data_path / 'processed'
            if not processed_path.exists():
                return []
            
            # Find all date directories
            date_paths = []
            for path in processed_path.rglob('*/*/*/*.json'):
                # Extract date from path: .../YYYY/MM/DD/file.json
                parts = path.parts
                if len(parts) >= 4:
                    try:
                        year, month, day = parts[-4], parts[-3], parts[-2]
                        date_str = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                        if date_str not in date_paths:
                            date_paths.append(date_str)
                    except (ValueError, IndexError):
                        continue
            
            return sorted(date_paths)
            
        except Exception as e:
            self.logger.error(f"Failed to get available date ranges: {e}")
            return []
    
    def get_data_path_for_dates(self, start_date: str, end_date: Optional[str] = None) -> str:
        """Get the appropriate data path for the date range."""
        # Always prefer processed data
        processed_path = self.base_data_path / 'processed'
        if processed_path.exists():
            return str(processed_path)
        
        # Fallback to raw data (though Phase 2 expects processed JSON)
        raw_path = self.base_data_path / 'raw'
        if raw_path.exists():
            self.logger.warning("Using raw data - consider running Phase 1 processing first")
            return str(raw_path)
        
        raise FileNotFoundError(f"No data found in {self.base_data_path}")
    
    def count_events_for_date_range(self, start_date: str, end_date: Optional[str] = None) -> int:
        """Count total JSON files available for the date range."""
        try:
            start = parse(start_date).date()
            end = parse(end_date).date() if end_date else start
            
            total_files = 0
            current_date = start
            
            while current_date <= end:
                pattern = f'processed/AWSLogs/*/CloudTrail/*/{current_date.strftime("%Y/%m/%d")}/*.json'
                files = list(self.base_data_path.glob(pattern))
                total_files += len(files)
                current_date += timedelta(days=1)
            
            return total_files
            
        except Exception as e:
            self.logger.error(f"Failed to count events: {e}")
            return 0