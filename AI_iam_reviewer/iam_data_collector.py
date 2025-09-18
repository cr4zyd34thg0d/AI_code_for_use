#!/usr/bin/env python3
"""
IAM Data Collector for AI-Powered Security Analysis
FedRAMP High Environment

This Lambda function collects IAM data for AI analysis, including:
- Role and user enumeration with metadata
- Policy attachment and inline policy collection
- Access Advisor data for usage patterns
- Compliance context and business metadata

Optimized for cost efficiency and FedRAMP High security requirements.
"""

import os
import json
import boto3
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from botocore.exceptions import ClientError, BotoCoreError
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class IAMDataCollector:
    """Collects and processes IAM data for AI analysis"""
    
    def __init__(self):
        # Initialize AWS clients
        self.iam = boto3.client('iam')
        self.sts = boto3.client('sts')
        self.dynamodb = boto3.resource('dynamodb')
        self.s3 = boto3.client('s3')
        self.lambda_client = boto3.client('lambda')
        
        # Environment configuration
        self.cache_table_name = os.environ.get('CACHE_TABLE')
        self.reports_bucket = os.environ.get('REPORTS_BUCKET')
        self.batch_size = int(os.environ.get('BATCH_SIZE', '10'))
        self.bedrock_region = os.environ.get('BEDROCK_REGION', 'us-gov-west-1')
        self.compliance_framework = os.environ.get('COMPLIANCE_FRAMEWORK', 'NIST-800-53')
        
        # Initialize DynamoDB table
        if self.cache_table_name:
            self.cache_table = self.dynamodb.Table(self.cache_table_name)
        
        # Get account context
        try:
            caller_identity = self.sts.get_caller_identity()
            self.account_id = caller_identity['Account']
            self.partition = self._get_partition(caller_identity['Arn'])
        except Exception as e:
            logger.error(f"Failed to get caller identity: {e}")
            raise
    
    def _get_partition(self, arn: str) -> str:
        """Determine AWS partition from ARN"""
        if arn.startswith('arn:aws-us-gov:'):
            return 'aws-us-gov'
        elif arn.startswith('arn:aws-cn:'):
            return 'aws-cn'
        else:
            return 'aws'
    
    def _generate_entity_hash(self, entity_data: Dict) -> str:
        """Generate consistent hash for entity data"""
        # Create deterministic hash based on key attributes
        hash_input = json.dumps(entity_data, sort_keys=True, default=str)
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _is_analysis_needed(self, entity_id: str, entity_hash: str) -> bool:
        """Check if entity needs analysis based on cache"""
        try:
            response = self.cache_table.get_item(
                Key={
                    'entity_id': entity_id,
                    'analysis_date': datetime.now(timezone.utc).strftime('%Y-%m-%d')
                }
            )
            
            if 'Item' in response:
                cached_hash = response['Item'].get('entity_hash', '')
                return cached_hash != entity_hash
            
            return True  # No cache entry, analysis needed
            
        except Exception as e:
            logger.warning(f"Cache check failed for {entity_id}: {e}")
            return True  # Default to analysis if cache fails
    
    def _cache_analysis_result(self, entity_id: str, entity_hash: str, 
                              analysis_data: Dict) -> None:
        """Cache analysis result in DynamoDB"""
        try:
            ttl = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp())
            
            self.cache_table.put_item(
                Item={
                    'entity_id': entity_id,
                    'analysis_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
                    'entity_hash': entity_hash,
                    'analysis_data': analysis_data,
                    'ttl': ttl,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'compliance_framework': self.compliance_framework
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to cache analysis for {entity_id}: {e}")
    
    def collect_roles(self) -> List[Dict[str, Any]]:
        """Collect IAM roles with comprehensive metadata"""
        roles = []
        
        try:
            paginator = self.iam.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    try:
                        # Basic role information
                        role_data = {
                            'type': 'role',
                            'name': role['RoleName'],
                            'arn': role['Arn'],
                            'path': role['Path'],
                            'created_date': role['CreateDate'].isoformat(),
                            'max_session_duration': role.get('MaxSessionDuration', 3600),
                            'description': role.get('Description', ''),
                            'tags': role.get('Tags', [])
                        }
                        
                        # Trust policy (assume role policy)
                        role_data['trust_policy'] = role.get('AssumeRolePolicyDocument', {})
                        
                        # Attached managed policies
                        role_data['attached_policies'] = self._get_attached_policies(
                            role['RoleName'], 'role'
                        )
                        
                        # Inline policies
                        role_data['inline_policies'] = self._get_inline_policies(
                            role['RoleName'], 'role'
                        )
                        
                        # Access Advisor data (usage information)
                        role_data['access_advisor'] = self._get_access_advisor_data(
                            role['Arn']
                        )
                        
                        # Business context from tags
                        role_data['business_context'] = self._extract_business_context(
                            role.get('Tags', [])
                        )
                        
                        # Risk indicators
                        role_data['risk_indicators'] = self._calculate_risk_indicators(role_data)
                        
                        roles.append(role_data)
                        
                    except Exception as e:
                        logger.error(f"Failed to process role {role['RoleName']}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to collect roles: {e}")
            raise
        
        logger.info(f"Collected {len(roles)} roles for analysis")
        return roles
    
    def collect_users(self) -> List[Dict[str, Any]]:
        """Collect IAM users with comprehensive metadata"""
        users = []
        
        try:
            paginator = self.iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    try:
                        # Basic user information
                        user_data = {
                            'type': 'user',
                            'name': user['UserName'],
                            'arn': user['Arn'],
                            'path': user['Path'],
                            'created_date': user['CreateDate'].isoformat(),
                            'password_last_used': user.get('PasswordLastUsed', '').isoformat() if user.get('PasswordLastUsed') else None,
                            'tags': user.get('Tags', [])
                        }
                        
                        # Attached managed policies
                        user_data['attached_policies'] = self._get_attached_policies(
                            user['UserName'], 'user'
                        )
                        
                        # Inline policies
                        user_data['inline_policies'] = self._get_inline_policies(
                            user['UserName'], 'user'
                        )
                        
                        # Access keys information
                        user_data['access_keys'] = self._get_access_keys_info(
                            user['UserName']
                        )
                        
                        # MFA devices
                        user_data['mfa_devices'] = self._get_mfa_devices(
                            user['UserName']
                        )
                        
                        # Business context from tags
                        user_data['business_context'] = self._extract_business_context(
                            user.get('Tags', [])
                        )
                        
                        # Risk indicators
                        user_data['risk_indicators'] = self._calculate_risk_indicators(user_data)
                        
                        users.append(user_data)
                        
                    except Exception as e:
                        logger.error(f"Failed to process user {user['UserName']}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to collect users: {e}")
            raise
        
        logger.info(f"Collected {len(users)} users for analysis")
        return users
    
    def _get_attached_policies(self, entity_name: str, entity_type: str) -> List[Dict]:
        """Get attached managed policies for role or user"""
        policies = []
        
        try:
            if entity_type == 'role':
                paginator = self.iam.get_paginator('list_attached_role_policies')
                page_iterator = paginator.paginate(RoleName=entity_name)
            else:
                paginator = self.iam.get_paginator('list_attached_user_policies')
                page_iterator = paginator.paginate(UserName=entity_name)
            
            for page in page_iterator:
                for policy in page['AttachedPolicies']:
                    try:
                        # Get policy details
                        policy_details = self.iam.get_policy(PolicyArn=policy['PolicyArn'])
                        policy_version = self.iam.get_policy_version(
                            PolicyArn=policy['PolicyArn'],
                            VersionId=policy_details['Policy']['DefaultVersionId']
                        )
                        
                        policies.append({
                            'name': policy['PolicyName'],
                            'arn': policy['PolicyArn'],
                            'type': 'managed',
                            'document': policy_version['PolicyVersion']['Document'],
                            'version_id': policy_details['Policy']['DefaultVersionId'],
                            'is_aws_managed': policy['PolicyArn'].startswith(f'arn:{self.partition}:iam::aws:policy/')
                        })
                        
                    except Exception as e:
                        logger.warning(f"Failed to get policy details for {policy['PolicyArn']}: {e}")
                        policies.append({
                            'name': policy['PolicyName'],
                            'arn': policy['PolicyArn'],
                            'type': 'managed',
                            'error': str(e)
                        })
                        
        except Exception as e:
            logger.error(f"Failed to get attached policies for {entity_name}: {e}")
        
        return policies
    
    def _get_inline_policies(self, entity_name: str, entity_type: str) -> List[Dict]:
        """Get inline policies for role or user"""
        policies = []
        
        try:
            if entity_type == 'role':
                paginator = self.iam.get_paginator('list_role_policies')
                page_iterator = paginator.paginate(RoleName=entity_name)
                get_policy_func = lambda name: self.iam.get_role_policy(RoleName=entity_name, PolicyName=name)
            else:
                paginator = self.iam.get_paginator('list_user_policies')
                page_iterator = paginator.paginate(UserName=entity_name)
                get_policy_func = lambda name: self.iam.get_user_policy(UserName=entity_name, PolicyName=name)
            
            for page in page_iterator:
                for policy_name in page['PolicyNames']:
                    try:
                        policy_doc = get_policy_func(policy_name)
                        
                        policies.append({
                            'name': policy_name,
                            'type': 'inline',
                            'document': policy_doc['PolicyDocument']
                        })
                        
                    except Exception as e:
                        logger.warning(f"Failed to get inline policy {policy_name} for {entity_name}: {e}")
                        policies.append({
                            'name': policy_name,
                            'type': 'inline',
                            'error': str(e)
                        })
                        
        except Exception as e:
            logger.error(f"Failed to get inline policies for {entity_name}: {e}")
        
        return policies
    
    def _get_access_advisor_data(self, entity_arn: str) -> Dict:
        """Get Access Advisor data for entity"""
        try:
            # Generate service last accessed details
            job_response = self.iam.generate_service_last_accessed_details(Arn=entity_arn)
            job_id = job_response['JobId']
            
            # Poll for completion (with timeout)
            max_wait = 60  # seconds
            wait_time = 0
            poll_interval = 2
            
            while wait_time < max_wait:
                details_response = self.iam.get_service_last_accessed_details(JobId=job_id)
                
                if details_response['JobStatus'] == 'COMPLETED':
                    services = details_response.get('ServicesLastAccessed', [])
                    
                    # Process service access data
                    access_data = {
                        'job_completion_date': details_response['JobCompletionDate'].isoformat(),
                        'services_accessed': len([s for s in services if s.get('LastAuthenticated')]),
                        'total_services': len(services),
                        'last_activity': None,
                        'services': []
                    }
                    
                    # Find most recent activity
                    most_recent = None
                    for service in services:
                        service_data = {
                            'service_name': service['ServiceName'],
                            'service_namespace': service['ServiceNamespace'],
                            'last_authenticated': service.get('LastAuthenticated', '').isoformat() if service.get('LastAuthenticated') else None,
                            'total_authenticated_entities': service.get('TotalAuthenticatedEntities', 0)
                        }
                        
                        access_data['services'].append(service_data)
                        
                        if service.get('LastAuthenticated'):
                            if most_recent is None or service['LastAuthenticated'] > most_recent:
                                most_recent = service['LastAuthenticated']
                    
                    if most_recent:
                        access_data['last_activity'] = most_recent.isoformat()
                    
                    return access_data
                
                elif details_response['JobStatus'] == 'FAILED':
                    logger.warning(f"Access Advisor job failed for {entity_arn}")
                    break
                
                time.sleep(poll_interval)
                wait_time += poll_interval
            
            logger.warning(f"Access Advisor job timed out for {entity_arn}")
            return {'error': 'timeout', 'job_id': job_id}
            
        except Exception as e:
            logger.warning(f"Failed to get Access Advisor data for {entity_arn}: {e}")
            return {'error': str(e)}
    
    def _get_access_keys_info(self, username: str) -> List[Dict]:
        """Get access key information for user"""
        try:
            response = self.iam.list_access_keys(UserName=username)
            keys = []
            
            for key_metadata in response['AccessKeyMetadata']:
                keys.append({
                    'access_key_id': key_metadata['AccessKeyId'],
                    'status': key_metadata['Status'],
                    'created_date': key_metadata['CreateDate'].isoformat()
                })
            
            return keys
            
        except Exception as e:
            logger.warning(f"Failed to get access keys for {username}: {e}")
            return []
    
    def _get_mfa_devices(self, username: str) -> List[Dict]:
        """Get MFA devices for user"""
        try:
            response = self.iam.list_mfa_devices(UserName=username)
            devices = []
            
            for device in response['MFADevices']:
                devices.append({
                    'serial_number': device['SerialNumber'],
                    'enable_date': device['EnableDate'].isoformat()
                })
            
            return devices
            
        except Exception as e:
            logger.warning(f"Failed to get MFA devices for {username}: {e}")
            return []
    
    def _extract_business_context(self, tags: List[Dict]) -> Dict:
        """Extract business context from resource tags"""
        context = {
            'environment': None,
            'application': None,
            'owner': None,
            'cost_center': None,
            'compliance_scope': None,
            'criticality': None
        }
        
        # Common tag mappings
        tag_mappings = {
            'environment': ['Environment', 'Env', 'Stage'],
            'application': ['Application', 'App', 'Service', 'Project'],
            'owner': ['Owner', 'Team', 'Contact'],
            'cost_center': ['CostCenter', 'Cost-Center', 'BillingCode'],
            'compliance_scope': ['Compliance', 'ComplianceScope', 'Scope'],
            'criticality': ['Criticality', 'Priority', 'Tier']
        }
        
        for tag in tags:
            key = tag.get('Key', '')
            value = tag.get('Value', '')
            
            for context_key, possible_keys in tag_mappings.items():
                if key in possible_keys:
                    context[context_key] = value
                    break
        
        return context
    
    def _calculate_risk_indicators(self, entity_data: Dict) -> Dict:
        """Calculate risk indicators for entity"""
        risk_indicators = {
            'high_privilege_policies': 0,
            'wildcard_policies': 0,
            'unused_duration_days': None,
            'missing_mfa': False,
            'old_access_keys': 0,
            'cross_account_trust': False,
            'admin_access': False
        }
        
        # Analyze policies for risk indicators
        all_policies = entity_data.get('attached_policies', []) + entity_data.get('inline_policies', [])
        
        for policy in all_policies:
            if 'document' in policy:
                doc = policy['document']
                if isinstance(doc, dict):
                    statements = doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    
                    for stmt in statements:
                        if isinstance(stmt, dict):
                            actions = stmt.get('Action', [])
                            resources = stmt.get('Resource', [])
                            
                            if not isinstance(actions, list):
                                actions = [actions]
                            if not isinstance(resources, list):
                                resources = [resources]
                            
                            # Check for wildcards
                            if '*' in actions or '*' in resources:
                                risk_indicators['wildcard_policies'] += 1
                            
                            # Check for admin access
                            if '*' in actions and '*' in resources:
                                risk_indicators['admin_access'] = True
                            
                            # Check for high-privilege actions
                            high_priv_actions = ['iam:*', 'sts:AssumeRole', '*']
                            if any(action in high_priv_actions for action in actions):
                                risk_indicators['high_privilege_policies'] += 1
        
        # Check trust policy for cross-account access (roles only)
        if entity_data.get('type') == 'role':
            trust_policy = entity_data.get('trust_policy', {})
            if isinstance(trust_policy, dict):
                statements = trust_policy.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                
                for stmt in statements:
                    if isinstance(stmt, dict):
                        principal = stmt.get('Principal', {})
                        if isinstance(principal, dict):
                            aws_principals = principal.get('AWS', [])
                            if not isinstance(aws_principals, list):
                                aws_principals = [aws_principals]
                            
                            for aws_principal in aws_principals:
                                if isinstance(aws_principal, str) and ':' in aws_principal:
                                    principal_account = aws_principal.split(':')[4]
                                    if principal_account != self.account_id:
                                        risk_indicators['cross_account_trust'] = True
        
        # Check for missing MFA (users only)
        if entity_data.get('type') == 'user':
            mfa_devices = entity_data.get('mfa_devices', [])
            risk_indicators['missing_mfa'] = len(mfa_devices) == 0
            
            # Check for old access keys
            access_keys = entity_data.get('access_keys', [])
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)
            
            for key in access_keys:
                if key.get('status') == 'Active':
                    created_date = datetime.fromisoformat(key['created_date'].replace('Z', '+00:00'))
                    if created_date < cutoff_date:
                        risk_indicators['old_access_keys'] += 1
        
        # Calculate unused duration
        access_advisor = entity_data.get('access_advisor', {})
        if access_advisor.get('last_activity'):
            last_activity = datetime.fromisoformat(access_advisor['last_activity'].replace('Z', '+00:00'))
            unused_duration = datetime.now(timezone.utc) - last_activity
            risk_indicators['unused_duration_days'] = unused_duration.days
        
        return risk_indicators
    
    def process_entities_for_analysis(self, entities: List[Dict]) -> List[Dict]:
        """Process entities and prepare for AI analysis"""
        analysis_queue = []
        
        for entity in entities:
            try:
                # Generate entity hash for change detection
                entity_hash = self._generate_entity_hash(entity)
                entity_id = f"{entity['type']}:{entity['name']}"
                
                # Check if analysis is needed
                if self._is_analysis_needed(entity_id, entity_hash):
                    # Prepare entity for AI analysis
                    analysis_entity = {
                        'entity_id': entity_id,
                        'entity_hash': entity_hash,
                        'entity_data': entity,
                        'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                        'compliance_framework': self.compliance_framework
                    }
                    
                    analysis_queue.append(analysis_entity)
                    logger.info(f"Queued {entity_id} for AI analysis")
                else:
                    logger.info(f"Skipping {entity_id} - no changes detected")
                    
            except Exception as e:
                logger.error(f"Failed to process entity {entity.get('name', 'unknown')}: {e}")
                continue
        
        return analysis_queue
    
    def save_analysis_batch(self, batch: List[Dict], batch_number: int) -> str:
        """Save analysis batch to S3 for processing"""
        try:
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
            key = f"analysis/batches/{timestamp}-batch-{batch_number:03d}.json"
            
            batch_data = {
                'batch_number': batch_number,
                'timestamp': timestamp,
                'entity_count': len(batch),
                'entities': batch,
                'metadata': {
                    'account_id': self.account_id,
                    'partition': self.partition,
                    'compliance_framework': self.compliance_framework,
                    'bedrock_region': self.bedrock_region
                }
            }
            
            self.s3.put_object(
                Bucket=self.reports_bucket,
                Key=key,
                Body=json.dumps(batch_data, default=str, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
            logger.info(f"Saved batch {batch_number} with {len(batch)} entities to s3://{self.reports_bucket}/{key}")
            return key
            
        except Exception as e:
            logger.error(f"Failed to save analysis batch {batch_number}: {e}")
            raise
    
    def trigger_bedrock_analysis(self, s3_key: str) -> None:
        """Trigger Bedrock analysis Lambda for the batch"""
        try:
            # Get Bedrock analyzer function name from environment or construct it
            analyzer_function = os.environ.get('BEDROCK_ANALYZER_FUNCTION')
            if not analyzer_function:
                # Construct function name based on stack naming convention
                stack_name = os.environ.get('AWS_LAMBDA_FUNCTION_NAME', '').replace('ai-iam-data-collector-', '')
                analyzer_function = f"ai-iam-bedrock-analyzer-{stack_name}"
            
            payload = {
                'source': 'data_collector',
                's3_bucket': self.reports_bucket,
                's3_key': s3_key,
                'analysis_mode': 'batch'
            }
            
            self.lambda_client.invoke(
                FunctionName=analyzer_function,
                InvocationType='Event',  # Asynchronous invocation
                Payload=json.dumps(payload)
            )
            
            logger.info(f"Triggered Bedrock analysis for {s3_key}")
            
        except Exception as e:
            logger.error(f"Failed to trigger Bedrock analysis for {s3_key}: {e}")
            # Don't raise - this is not critical for data collection

def lambda_handler(event, context):
    """Main Lambda handler for IAM data collection"""
    
    logger.info(f"Starting IAM data collection with event: {json.dumps(event, default=str)}")
    
    try:
        collector = IAMDataCollector()
        
        # Determine collection mode
        mode = event.get('mode', 'scheduled')
        full_analysis = event.get('full_analysis', True)
        
        logger.info(f"Collection mode: {mode}, Full analysis: {full_analysis}")
        
        # Collect IAM entities
        all_entities = []
        
        if full_analysis:
            # Collect roles
            logger.info("Collecting IAM roles...")
            roles = collector.collect_roles()
            all_entities.extend(roles)
            
            # Collect users
            logger.info("Collecting IAM users...")
            users = collector.collect_users()
            all_entities.extend(users)
        else:
            # Incremental collection based on event
            logger.info("Performing incremental collection...")
            # Implementation for incremental collection would go here
            pass
        
        logger.info(f"Collected {len(all_entities)} total entities")
        
        # Process entities for analysis
        analysis_queue = collector.process_entities_for_analysis(all_entities)
        logger.info(f"Queued {len(analysis_queue)} entities for AI analysis")
        
        # Create batches for processing
        batch_keys = []
        batch_size = collector.batch_size
        
        for i in range(0, len(analysis_queue), batch_size):
            batch = analysis_queue[i:i + batch_size]
            batch_number = (i // batch_size) + 1
            
            # Save batch to S3
            s3_key = collector.save_analysis_batch(batch, batch_number)
            batch_keys.append(s3_key)
            
            # Trigger Bedrock analysis
            collector.trigger_bedrock_analysis(s3_key)
        
        # Return summary
        result = {
            'status': 'success',
            'entities_collected': len(all_entities),
            'entities_queued': len(analysis_queue),
            'batches_created': len(batch_keys),
            'batch_keys': batch_keys,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Data collection completed successfully: {json.dumps(result, default=str)}")
        return result
        
    except Exception as e:
        logger.error(f"Data collection failed: {e}")
        
        error_result = {
            'status': 'error',
            'error_message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return error_result