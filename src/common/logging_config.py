import logging
import sys
from pathlib import Path
import re

def setup_logging(log_level: str = "INFO", log_file: str = None) -> logging.Logger:
    """Setup logging configuration for the application."""
    
    # Create formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s] [%(funcName)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create logger
    logger = logging.getLogger('cloudtrail_analyzer')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        # Validate and resolve log file path for security
        log_path = Path(log_file).resolve()
        
        # Ensure resolved path doesn't escape to dangerous locations
        resolved_str = str(log_path)
        if any(dangerous in resolved_str for dangerous in ['/etc/', '/usr/', '/bin/', '/sbin/', '/root/']):
            raise ValueError(f"Unsafe log file path: {log_file}")
        
        # Sanitize filename
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', log_path.name)
        log_path = log_path.parent / safe_filename
        
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Sanitize log file path for logging
        safe_log_file = re.sub(r'[\r\n\t]', '_', str(log_file))
        logger.info(f"Logging configured with file output: {safe_log_file}")
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific module."""
    return logging.getLogger(f'cloudtrail_analyzer.{name}')