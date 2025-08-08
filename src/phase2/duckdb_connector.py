import duckdb
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod

from common.logging_config import get_logger
from common.security_utils import SecurityUtils

class BaseConnector(ABC):
    @abstractmethod
    def connect(self, db_path: str) -> Any:
        pass
    
    @abstractmethod
    def execute_query(self, sql: str) -> pd.DataFrame:
        pass

class DuckDBConnector(BaseConnector):
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.logger = get_logger('duckdb_connector')
        self.conn = None
        self.connect(db_path)
    
    def connect(self, db_path: str) -> duckdb.DuckDBPyConnection:
        """Connect to DuckDB database."""
        try:
            self.conn = duckdb.connect(db_path)
            safe_path = SecurityUtils.sanitize_for_logging(db_path)
            self.logger.info(f"Connected to DuckDB at {safe_path}")
            return self.conn
        except Exception as e:
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Failed to connect to DuckDB: {safe_error}")
            raise
    
    def execute_query(self, sql: str) -> pd.DataFrame:
        """Execute SQL query and return DataFrame."""
        try:
            safe_sql = SecurityUtils.sanitize_for_logging(sql[:100])
            self.logger.debug(f"Executing query: {safe_sql}...")
            result = self.conn.execute(sql).fetchdf()
            self.logger.info(f"Query returned {len(result)} rows")
            return result
        except Exception as e:
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Query execution failed: {safe_error}")
            raise
    
    def create_cloudtrail_view(self, json_path: str, view_name: str = "cloudtrail") -> bool:
        """Create a view from CloudTrail JSON files."""
        try:
            # Use DuckDB's JSON reading with ignore_errors for robustness
            sql = f"""
            CREATE OR REPLACE VIEW {view_name} AS
            SELECT 
                json_extract_string(record, '$.eventVersion') as eventVersion,
                json_extract(record, '$.userIdentity') as userIdentity,
                json_extract_string(record, '$.eventTime') as eventTime,
                json_extract_string(record, '$.eventSource') as eventSource,
                json_extract_string(record, '$.eventName') as eventName,
                json_extract_string(record, '$.awsRegion') as awsRegion,
                json_extract_string(record, '$.sourceIPAddress') as sourceIPAddress,
                json_extract_string(record, '$.userAgent') as userAgent,
                json_extract(record, '$.requestParameters') as requestParameters,
                json_extract(record, '$.responseElements') as responseElements,
                json_extract_string(record, '$.requestID') as requestID,
                json_extract_string(record, '$.eventID') as eventID,
                json_extract_string(record, '$.eventType') as eventType,
                json_extract_string(record, '$.recipientAccountId') as recipientAccountId,
                json_extract_string(record, '$.sharedEventID') as sharedEventID,
                json_extract_string(record, '$.vpcEndpointId') as vpcEndpointId,
                json_extract_string(record, '$.eventCategory') as eventCategory,
                record as raw_record
            FROM (
                SELECT unnest(Records) as record
                FROM read_json('{json_path}/**/*.json', ignore_errors=true, union_by_name=true)
            )
            """
            
            self.conn.execute(sql)
            safe_view = SecurityUtils.sanitize_for_logging(view_name)
            safe_path = SecurityUtils.sanitize_for_logging(json_path)
            self.logger.info(f"Created CloudTrail view '{safe_view}' from {safe_path}")
            return True
            
        except Exception as e:
            safe_error = SecurityUtils.sanitize_for_logging(str(e))
            self.logger.error(f"Failed to create CloudTrail view: {safe_error}")
            return False
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.logger.info("DuckDB connection closed")