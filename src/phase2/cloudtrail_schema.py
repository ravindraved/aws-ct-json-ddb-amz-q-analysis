from typing import Dict, Any, List
from dataclasses import dataclass

@dataclass
class CloudTrailField:
    name: str
    type: str
    description: str
    nullable: bool = True

class CloudTrailSchema:
    """CloudTrail schema definition for DuckDB queries."""
    
    def __init__(self):
        self.schema = self._define_schema()
    
    def _define_schema(self) -> Dict[str, CloudTrailField]:
        """Define CloudTrail record schema based on AWS documentation."""
        return {
            'eventVersion': CloudTrailField(
                'eventVersion', 'VARCHAR', 'CloudTrail record format version'
            ),
            'userIdentity': CloudTrailField(
                'userIdentity', 'JSON', 'Information about the user that made the request'
            ),
            'eventTime': CloudTrailField(
                'eventTime', 'TIMESTAMP', 'Date and time the request was made'
            ),
            'eventSource': CloudTrailField(
                'eventSource', 'VARCHAR', 'AWS service that the request was made to'
            ),
            'eventName': CloudTrailField(
                'eventName', 'VARCHAR', 'Requested action'
            ),
            'awsRegion': CloudTrailField(
                'awsRegion', 'VARCHAR', 'AWS region where the request was made'
            ),
            'sourceIPAddress': CloudTrailField(
                'sourceIPAddress', 'VARCHAR', 'IP address from which the request was made'
            ),
            'userAgent': CloudTrailField(
                'userAgent', 'VARCHAR', 'Agent through which the request was made'
            ),
            'requestParameters': CloudTrailField(
                'requestParameters', 'JSON', 'Parameters sent with the request'
            ),
            'responseElements': CloudTrailField(
                'responseElements', 'JSON', 'Response elements for actions that make changes'
            ),
            'requestID': CloudTrailField(
                'requestID', 'VARCHAR', 'Value that identifies the request'
            ),
            'eventID': CloudTrailField(
                'eventID', 'VARCHAR', 'GUID generated for every event'
            ),
            'eventType': CloudTrailField(
                'eventType', 'VARCHAR', 'Type of event (AwsApiCall, AwsServiceEvent, etc.)'
            ),
            'recipientAccountId': CloudTrailField(
                'recipientAccountId', 'VARCHAR', 'Account ID that received the request'
            ),
            'sharedEventID': CloudTrailField(
                'sharedEventID', 'VARCHAR', 'GUID generated for events delivered to multiple accounts'
            ),
            'vpcEndpointId': CloudTrailField(
                'vpcEndpointId', 'VARCHAR', 'VPC endpoint ID through which the request was made'
            ),
            'eventCategory': CloudTrailField(
                'eventCategory', 'VARCHAR', 'Category of event (Management, Data, Insight)'
            )
        }
    
    def get_schema(self) -> Dict[str, CloudTrailField]:
        """Get the complete schema definition."""
        return self.schema
    
    def get_field_names(self) -> List[str]:
        """Get list of all field names."""
        return list(self.schema.keys())
    
    def validate_json_structure(self, json_data: Dict[str, Any]) -> bool:
        """Validate if JSON data conforms to CloudTrail structure."""
        try:
            # Check for required Records field
            if 'Records' not in json_data:
                return False
            
            records = json_data['Records']
            if not isinstance(records, list):
                return False
            
            # Validate first record structure if exists
            if records:
                record = records[0]
                required_fields = ['eventVersion', 'eventTime', 'eventSource', 'eventName']
                
                for field in required_fields:
                    if field not in record:
                        return False
            
            return True
            
        except Exception:
            return False
    
    def get_create_table_sql(self, table_name: str = "cloudtrail") -> str:
        """Generate CREATE TABLE SQL for CloudTrail data."""
        fields = []
        for name, field in self.schema.items():
            nullable = "NULL" if field.nullable else "NOT NULL"
            fields.append(f"    {name} {field.type} {nullable}")
        
        return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
{chr(10).join(fields)}
        );
        """