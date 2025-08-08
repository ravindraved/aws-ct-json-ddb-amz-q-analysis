from typing import Dict, List
from dataclasses import dataclass

@dataclass
class QueryTemplate:
    name: str
    description: str
    sql: str
    category: str

class QueryTemplates:
    """Standard CloudTrail investigation query templates."""
    
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, QueryTemplate]:
        """Initialize all query templates."""
        templates = {}
        
        # Security Operations Queries
        templates.update(self._get_security_queries())
        
        # Cloud Operations Queries  
        templates.update(self._get_operations_queries())
        
        # Incident Response Queries
        templates.update(self._get_incident_response_queries())
        
        # Threat Hunting Queries
        templates.update(self._get_threat_hunting_queries())
        
        return templates
    
    def _get_security_queries(self) -> Dict[str, QueryTemplate]:
        """Security operations query templates."""
        return {
            'failed_logins': QueryTemplate(
                name='Failed Login Attempts',
                description='Find failed authentication attempts',
                sql="""
                SELECT 
                    eventTime,
                    sourceIPAddress,
                    userAgent,
                    json_extract_string(userIdentity, '$.type') as userType,
                    json_extract_string(userIdentity, '$.userName') as userName,
                    eventName,
                    json_extract_string(responseElements, '$.errorCode') as errorCode
                FROM cloudtrail 
                WHERE eventName LIKE '%Login%' 
                   OR eventName LIKE '%Auth%'
                   OR json_extract_string(responseElements, '$.errorCode') IS NOT NULL
                ORDER BY eventTime DESC
                """,
                category='security'
            ),
            
            'privilege_escalation': QueryTemplate(
                name='Privilege Escalation Events',
                description='Detect potential privilege escalation activities',
                sql="""
                SELECT 
                    eventTime,
                    eventName,
                    json_extract_string(userIdentity, '$.type') as userType,
                    json_extract_string(userIdentity, '$.userName') as userName,
                    sourceIPAddress,
                    requestParameters
                FROM cloudtrail 
                WHERE eventName IN (
                    'AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity',
                    'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy'
                )
                ORDER BY eventTime DESC
                """,
                category='security'
            ),
            
            'unusual_api_calls': QueryTemplate(
                name='Unusual API Calls',
                description='Find uncommon or suspicious API calls',
                sql="""
                SELECT 
                    eventName,
                    COUNT(*) as call_count,
                    COUNT(DISTINCT sourceIPAddress) as unique_ips,
                    COUNT(DISTINCT json_extract_string(userIdentity, '$.userName')) as unique_users
                FROM cloudtrail 
                GROUP BY eventName
                HAVING call_count < 5  -- Uncommon events
                ORDER BY call_count ASC
                """,
                category='security'
            )
        }
    
    def _get_operations_queries(self) -> Dict[str, QueryTemplate]:
        """Cloud operations query templates."""
        return {
            'resource_creation': QueryTemplate(
                name='Resource Creation Events',
                description='Track resource creation activities',
                sql="""
                SELECT 
                    eventTime,
                    eventName,
                    eventSource,
                    json_extract_string(userIdentity, '$.userName') as userName,
                    awsRegion,
                    requestParameters
                FROM cloudtrail 
                WHERE eventName LIKE '%Create%' 
                   OR eventName LIKE '%Launch%'
                   OR eventName LIKE '%Run%'
                ORDER BY eventTime DESC
                """,
                category='operations'
            ),
            
            'service_usage': QueryTemplate(
                name='Service Usage Patterns',
                description='Analyze AWS service usage patterns',
                sql="""
                SELECT 
                    eventSource,
                    COUNT(*) as event_count,
                    COUNT(DISTINCT eventName) as unique_events,
                    COUNT(DISTINCT json_extract_string(userIdentity, '$.userName')) as unique_users,
                    MIN(eventTime) as first_event,
                    MAX(eventTime) as last_event
                FROM cloudtrail 
                GROUP BY eventSource
                ORDER BY event_count DESC
                """,
                category='operations'
            ),
            
            'configuration_changes': QueryTemplate(
                name='Configuration Changes',
                description='Track configuration modification events',
                sql="""
                SELECT 
                    eventTime,
                    eventName,
                    eventSource,
                    json_extract_string(userIdentity, '$.userName') as userName,
                    sourceIPAddress,
                    requestParameters
                FROM cloudtrail 
                WHERE eventName LIKE '%Update%' 
                   OR eventName LIKE '%Modify%'
                   OR eventName LIKE '%Put%'
                   OR eventName LIKE '%Set%'
                ORDER BY eventTime DESC
                """,
                category='operations'
            )
        }
    
    def _get_incident_response_queries(self) -> Dict[str, QueryTemplate]:
        """Incident response query templates."""
        return {
            'timeline_reconstruction': QueryTemplate(
                name='Event Timeline',
                description='Reconstruct timeline of events for specific user/IP',
                sql="""
                SELECT 
                    eventTime,
                    eventName,
                    eventSource,
                    json_extract_string(userIdentity, '$.userName') as userName,
                    sourceIPAddress,
                    userAgent,
                    requestID
                FROM cloudtrail 
                WHERE sourceIPAddress = '{ip_address}'  -- Replace with actual IP
                   OR json_extract_string(userIdentity, '$.userName') = '{username}'  -- Replace with actual username
                ORDER BY eventTime ASC
                """,
                category='incident_response'
            ),
            
            'user_activity': QueryTemplate(
                name='User Activity Tracking',
                description='Track all activities for specific users',
                sql="""
                SELECT 
                    json_extract_string(userIdentity, '$.userName') as userName,
                    json_extract_string(userIdentity, '$.type') as userType,
                    COUNT(*) as total_events,
                    COUNT(DISTINCT eventName) as unique_events,
                    COUNT(DISTINCT sourceIPAddress) as unique_ips,
                    MIN(eventTime) as first_activity,
                    MAX(eventTime) as last_activity
                FROM cloudtrail 
                WHERE json_extract_string(userIdentity, '$.userName') IS NOT NULL
                GROUP BY userName, userType
                ORDER BY total_events DESC
                """,
                category='incident_response'
            )
        }
    
    def _get_threat_hunting_queries(self) -> Dict[str, QueryTemplate]:
        """Threat hunting query templates."""
        return {
            'anomalous_behavior': QueryTemplate(
                name='Anomalous Behavior Detection',
                description='Detect unusual patterns in user behavior',
                sql="""
                SELECT 
                    sourceIPAddress,
                    COUNT(*) as event_count,
                    COUNT(DISTINCT eventName) as unique_events,
                    COUNT(DISTINCT json_extract_string(userIdentity, '$.userName')) as unique_users,
                    COUNT(DISTINCT awsRegion) as regions_accessed
                FROM cloudtrail 
                GROUP BY sourceIPAddress
                HAVING event_count > 100  -- High activity threshold
                   OR regions_accessed > 2  -- Multi-region access
                ORDER BY event_count DESC
                """,
                category='threat_hunting'
            ),
            
            'data_exfiltration': QueryTemplate(
                name='Potential Data Exfiltration',
                description='Look for signs of data exfiltration',
                sql="""
                SELECT 
                    eventTime,
                    eventName,
                    json_extract_string(userIdentity, '$.userName') as userName,
                    sourceIPAddress,
                    requestParameters
                FROM cloudtrail 
                WHERE eventName IN (
                    'GetObject', 'CopyObject', 'DownloadDBLogFilePortion',
                    'GetQueryResults', 'GetQueryExecution'
                )
                ORDER BY eventTime DESC
                """,
                category='threat_hunting'
            )
        }
    
    def get_template(self, template_name: str) -> QueryTemplate:
        """Get specific query template."""
        return self.templates.get(template_name)
    
    def get_templates_by_category(self, category: str) -> List[QueryTemplate]:
        """Get all templates for a specific category."""
        return [t for t in self.templates.values() if t.category == category]
    
    def list_templates(self) -> List[str]:
        """List all available template names."""
        return list(self.templates.keys())