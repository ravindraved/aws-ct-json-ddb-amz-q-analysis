from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime
import yaml
import logging

@dataclass
class S3Config:
    bucket_arn: str
    prefix: str
    start_date: str
    end_date: Optional[str] = None
    
    @property
    def bucket_name(self) -> str:
        return self.bucket_arn.split(':::')[-1]

@dataclass 
class AuthConfig:
    method: str  # "instance_profile" or "access_keys"
    access_key: Optional[str] = None
    secret_key: Optional[str] = None

@dataclass
class Phase1Config:
    s3_config: S3Config
    auth_config: AuthConfig
    local_base_path: str = "/data"
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'Phase1Config':
        s3_config = S3Config(**config_dict['s3_config'])
        auth_config = AuthConfig(**config_dict['auth_config'])
        return cls(
            s3_config=s3_config,
            auth_config=auth_config,
            local_base_path=config_dict.get('local_base_path', '/data')
        )

@dataclass
class Phase2Config:
    base_path: str
    db_path: str = "cloudtrail.duckdb"
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'Phase2Config':
        return cls(**config_dict)

class BaseConfig(ABC):
    @abstractmethod
    def validate(self) -> bool:
        pass
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        pass