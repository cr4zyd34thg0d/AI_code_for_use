#!/usr/bin/env python3
"""
Bedrock-Powered IAM Policy Analyzer
FedRAMP High Environment

This Lambda function uses Amazon Bedrock Claude models to perform intelligent
IAM policy analysis, providing contextual security insights beyond traditional
rule-based approaches.

Key Features:
- AI-powered policy risk assessment
- Business context understanding
- Compliance framework mapping
- Natural language explanations
- Cost-optimized prompt engineering
"""

import os
import json
import boto3
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from botocore.exceptions import ClientError
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class BedrockPolicyAnalyzer:
    """AI-powered IAM policy analyzer using Amazon Bedrock"""
    
    def __init__(self):
        # Initialize AWS clients
        self.bedrock = boto3.client('bedrock-runtime', region_name=os.environ.get('BEDROCK_REGION', 'us-gov-west-1'))
        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.securityhub = boto3.client('securityhub')
        self.sts = boto3.client('sts')
        
        # Environment configuration
        self.bedrock_model = os.environ.get('BEDROCK_MODEL', 'anthropic.claude-3-haiku-20240307-v1:0')
        self.max_tokens = int(os.environ.get('MAX_TOKENS', '4000'))
        self.cache_table_name = os.environ.get('CACHE_TABLE')
        self.reports_bucket = os.environ.get('REPORTS_BUCKET')
        self.risk_threshold = os.environ.get('RISK_THRESHOLD', 'MEDIUM')
        self.compliance_framework = os.environ.get('COMPLIANCE_FRAMEWORK', 'NIST-800-53')
        self.enable_security_hub = os.environ.get('ENABLE_SECURITY_HUB', 'true').lower() == 'true'
        
        # Initialize DynamoDB table
        if self.cache_table_name:
            self.cache_table = self.dynamodb.Table(self.cache_table_name)
        
        # Get account context
        caller_identity = self.sts.get_caller_identity()
        self.account_id = caller_identity['Account']
        self.region = os.environ.get('AWS_REGION', 'us-gov-west-1')
        
        # Load prompt templates
        self.prompts = self._load_prompt_templates()
    
    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load security-focused analysis prompts"""
        return self._get_security_prompts()
    
    def _get_security_prompts(self) -> Dict[str, str]:
        """Security-focused analysis prompts with hallucination prevention"""
        return {
            'iam_security_analysis': """You are a cybersecurity expert conducting IAM security analysis for a FedRAMP High government system.

CRITICAL: Base ALL findings on provided data only. Do NOT make assumptions.

ENTITY: {entity_type}:{entity_name}
TRUST POLICY: {trust_policy}
POLICIES: {attached_policies}
USAGE: {access_advisor_data}
CONTEXT: Environment={environment}, App={application}, Owner={owner}

ANALYZE FOR:
1. Excessive privileges (wildcards, broad access)
2. Missing security controls (MFA, conditions)
3. Cross-account risks
4. Privilege escalation vectors
5. Unused/stale access
6. FedRAMP violations

JSON OUTPUT REQUIRED:
{{
  "entity_id": "{entity_type}:{entity_name}",
  "security_posture": "COMPLIANT|NON_COMPLIANT|NEEDS_REVIEW",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "findings": [
    {{
      "finding_type": "EXCESSIVE_PRIVILEGES|MISSING_CONTROLS|CROSS_ACCOUNT_RISK|PRIVILEGE_ESCALATION|UNUSED_ACCESS|FEDRAMP_VIOLATION",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "title": "Specific issue (max 80 chars)",
      "evidence": "Exact policy statement causing issue",
      "remediation": "Specific fix steps",
      "fedramp_control": "NIST control (AC-2, AC-6, etc)"
    }}
  ],
  "proactive_recommendations": ["Specific security improvements"]
}}""",

            'role_persona_analysis': """Analyze IAM role for proper persona-based access control in FedRAMP High environment.

ROLE: {role_name}
TRUST: {trust_policy}
POLICIES: {policies_summary}
USAGE: {usage_data}

CLASSIFY INTO ONE PERSONA:
- HUMAN_INTERACTIVE: Console/CLI access, needs MFA
- SERVICE_EXECUTION: AWS service usage, service principals
- APPLICATION_WORKLOAD: App runtime, scoped resources
- CROSS_ACCOUNT_ACCESS: External access, strict conditions
- ADMINISTRATIVE_BREAK_GLASS: Emergency access, heavy monitoring
- AUTOMATION_PIPELINE: CI/CD usage, deployment permissions

JSON OUTPUT:
{{
  "role_name": "{role_name}",
  "persona_classification": {{
    "primary_persona": "HUMAN_INTERACTIVE|SERVICE_EXECUTION|APPLICATION_WORKLOAD|CROSS_ACCOUNT_ACCESS|ADMINISTRATIVE_BREAK_GLASS|AUTOMATION_PIPELINE",
    "confidence": 1-10,
    "evidence": "Specific evidence for classification"
  }},
  "security_alignment": {{
    "trust_policy_appropriate": true|false,
    "permissions_scoped": true|false,
    "fedramp_compliant": true|false
  }},
  "baseline_compliance": {{
    "meets_baseline": true|false,
    "required_changes": ["Specific changes needed"]
  }}
}}""",

            'compliance_validation': """Validate IAM configuration against FedRAMP High baseline requirements.

ENTITY: {entity_name} ({entity_type})
CONFIG: {configuration_data}

VALIDATE AGAINST:
- AC-2: Account Management
- AC-6: Least Privilege  
- AU-6: Audit Review
- CA-7: Continuous Monitoring
- SI-4: System Monitoring

JSON OUTPUT:
{{
  "compliance_assessment": {{
    "overall_compliance": "COMPLIANT|NON_COMPLIANT|PARTIALLY_COMPLIANT",
    "compliance_score": 1-100
  }},
  "control_validation": [
    {{
      "control_id": "AC-2|AC-6|AU-6|CA-7|SI-4",
      "implementation_status": "IMPLEMENTED|PARTIALLY_IMPLEMENTED|NOT_IMPLEMENTED",
      "evidence": "Specific implementation evidence",
      "gaps": ["Implementation gaps"],
      "remediation": "Steps for compliance"
    }}
  ],
  "baseline_deviations": [
    {{
      "deviation": "Specific baseline deviation",
      "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
      "correction": "Required correction"
    }}
  ]
}}"""
        }
    
    def _invoke_bedrock_model(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Invoke Bedrock model with optimized parameters"""
        try:
            if max_tokens is None:
                max_tokens = self.max_tokens
            
            # Prepare request based on model type
            if 'claude-3' in self.bedrock_model:
                request_body = {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": max_tokens,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.1,  # Low temperature for consistent analysis
                    "top_p": 0.9
                }
            else:
                # Fallback for other models
                request_body = {
                    "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
                    "max_tokens_to_sample": max_tokens,
                    "temperature": 0.1,
                    "top_p": 0.9
                }
            
            response = self.bedrock.invoke_model(
                modelId=self.bedrock_model,
                body=json.dumps(request_body),
                contentType='application/json',
                accept='application/json'
            )
            
            response_body = json.loads(response['body'].read())
            
            # Extract content based on model response format
            if 'claude-3' in self.bedrock_model:
                content = response_body['content'][0]['text']
            else:
                content = response_body.get('completion', '')
            
            logger.info(f"Bedrock model invoked successfully, response length: {len(content)}")
            return content
            
        except Exception as e:
            logger.error(f"Failed to invoke Bedrock model: {e}")
            raise
    
    def _extract_json_from_response(self, response: str) -> Dict:
        """Extract and validate JSON from Bedrock response"""
        try:
            # Try to find JSON in the response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                return json.loads(json_str)
            else:
                # If no JSON found, create a structured response
                return {
                    "error": "No JSON found in response",
                    "raw_response": response[:1000],  # Truncate for logging
                    "analysis_failed": True
                }
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from Bedrock response: {e}")
            return {
                "error": f"JSON parsing failed: {str(e)}",
                "raw_response": response[:1000],
                "analysis_failed": True
            }
    
    def analyze_policy(self, entity_data: Dict) -> Dict:
        """Analyze IAM policy using enhanced security-focused prompts"""
        try:
            entity_type = entity_data.get('type', 'unknown')
            entity_name = entity_data.get('name', 'unknown')
            
            # Extract and validate required data
            trust_policy = entity_data.get('trust_policy', {})
            attached_policies = entity_data.get('attached_policies', [])
            inline_policies = entity_data.get('inline_policies', [])
            access_advisor = entity_data.get('access_advisor', {})
            business_context = entity_data.get('business_context', {})
            
            # Prepare structured policy data for analysis
            policy_summary = self._prepare_policy_summary(attached_policies, inline_policies)
            
            # Extract business context safely
            environment = business_context.get('environment', 'unknown')
            application = business_context.get('application', 'unknown')
            owner = business_context.get('owner', 'unknown')
            criticality = business_context.get('criticality', 'unknown')
            
            # Prepare access advisor data
            last_activity = access_advisor.get('last_activity', 'never')
            created_date = entity_data.get('created_date', 'unknown')
            
            # Use enhanced security analysis prompt
            prompt_data = {
                'entity_type': entity_type,
                'entity_name': entity_name,
                'created_date': created_date,
                'last_activity': last_activity,
                'trust_policy': json.dumps(trust_policy, indent=2) if trust_policy else 'None',
                'attached_policies': json.dumps(policy_summary['attached'], indent=2),
                'inline_policies': json.dumps(policy_summary['inline'], indent=2),
                'access_advisor_data': json.dumps(access_advisor, indent=2),
                'environment': environment,
                'application': application,
                'owner': owner,
                'criticality': criticality
            }
            
            # Format security analysis prompt
            prompt = self.prompts['iam_security_analysis'].format(**prompt_data)
            
            # Invoke Bedrock model with validation
            response = self._invoke_bedrock_model(prompt, max_tokens=2000)
            
            # Parse and validate response
            analysis_result = self._extract_and_validate_json(response, 'iam_security_analysis')
            
            # Add security-focused metadata
            analysis_result['metadata'] = {
                'entity_id': f"{entity_type}:{entity_name}",
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'model_used': self.bedrock_model,
                'compliance_framework': self.compliance_framework,
                'prompt_type': 'iam_security_analysis',
                'security_focus': 'proactive_access_control',
                'validation_passed': True
            }
            
            # Perform additional security validation
            analysis_result = self._enhance_security_analysis(analysis_result, entity_data)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Security analysis failed for {entity_data.get('name', 'unknown')}: {e}")
            return self._create_error_response(entity_data, str(e), 'security_analysis_failure')
    
    def _prepare_policy_summary(self, attached_policies: List[Dict], inline_policies: List[Dict]) -> Dict:
        """Prepare structured policy summary for analysis"""
        summary = {
            'attached': [],
            'inline': []
        }
        
        # Process attached policies
        for policy in attached_policies:
            policy_info = {
                'name': policy.get('name', 'unknown'),
                'arn': policy.get('arn', ''),
                'type': 'aws_managed' if policy.get('is_aws_managed', False) else 'customer_managed',
                'has_wildcards': self._check_for_wildcards(policy.get('document', {})),
                'high_risk_actions': self._identify_high_risk_actions(policy.get('document', {})),
                'resource_scope': self._analyze_resource_scope(policy.get('document', {}))
            }
            summary['attached'].append(policy_info)
        
        # Process inline policies
        for policy in inline_policies:
            policy_info = {
                'name': policy.get('name', 'unknown'),
                'type': 'inline',
                'has_wildcards': self._check_for_wildcards(policy.get('document', {})),
                'high_risk_actions': self._identify_high_risk_actions(policy.get('document', {})),
                'resource_scope': self._analyze_resource_scope(policy.get('document', {}))
            }
            summary['inline'].append(policy_info)
        
        return summary
    
    def _check_for_wildcards(self, policy_doc: Dict) -> bool:
        """Check if policy contains wildcard permissions"""
        if not isinstance(policy_doc, dict):
            return False
        
        statements = policy_doc.get('Statement', [])
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
                    return True
                if any('*' in str(action) for action in actions):
                    return True
                if any('*' in str(resource) for resource in resources):
                    return True
        
        return False
    
    def _identify_high_risk_actions(self, policy_doc: Dict) -> List[str]:
        """Identify high-risk actions in policy"""
        high_risk_actions = [
            'iam:*', 'sts:AssumeRole', 'iam:PassRole', 'iam:CreateRole',
            'iam:AttachRolePolicy', 'iam:PutRolePolicy', 'iam:CreatePolicy',
            'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
            'lambda:CreateFunction', 'lambda:UpdateFunctionCode',
            'ec2:RunInstances', 'ec2:CreateSecurityGroup'
        ]
        
        found_risks = []
        
        if not isinstance(policy_doc, dict):
            return found_risks
        
        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            if isinstance(stmt, dict):
                actions = stmt.get('Action', [])
                if not isinstance(actions, list):
                    actions = [actions]
                
                for action in actions:
                    if isinstance(action, str):
                        if action in high_risk_actions or action == '*':
                            found_risks.append(action)
                        # Check for service wildcards
                        elif ':*' in action:
                            found_risks.append(action)
        
        return list(set(found_risks))  # Remove duplicates
    
    def _analyze_resource_scope(self, policy_doc: Dict) -> str:
        """Analyze resource scope of policy"""
        if not isinstance(policy_doc, dict):
            return 'unknown'
        
        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        has_wildcard_resources = False
        has_scoped_resources = False
        
        for stmt in statements:
            if isinstance(stmt, dict):
                resources = stmt.get('Resource', [])
                if not isinstance(resources, list):
                    resources = [resources]
                
                for resource in resources:
                    if isinstance(resource, str):
                        if resource == '*':
                            has_wildcard_resources = True
                        else:
                            has_scoped_resources = True
        
        if has_wildcard_resources and not has_scoped_resources:
            return 'wildcard_only'
        elif has_wildcard_resources and has_scoped_resources:
            return 'mixed_scope'
        elif has_scoped_resources:
            return 'scoped'
        else:
            return 'no_resources'
    
    def _extract_and_validate_json(self, response: str, prompt_type: str) -> Dict:
        """Extract and validate JSON response with security focus"""
        try:
            # Extract JSON from response
            analysis_result = self._extract_json_from_response(response)
            
            # Validate required fields for security analysis
            if prompt_type == 'iam_security_analysis':
                required_fields = ['entity_id', 'security_posture', 'risk_level', 'findings']
                missing_fields = [field for field in required_fields if field not in analysis_result]
                
                if missing_fields:
                    logger.warning(f"Missing required fields in analysis: {missing_fields}")
                    # Add default values for missing fields
                    if 'entity_id' not in analysis_result:
                        analysis_result['entity_id'] = 'unknown:unknown'
                    if 'security_posture' not in analysis_result:
                        analysis_result['security_posture'] = 'NEEDS_REVIEW'
                    if 'risk_level' not in analysis_result:
                        analysis_result['risk_level'] = 'MEDIUM'
                    if 'findings' not in analysis_result:
                        analysis_result['findings'] = []
            
            # Validate findings structure
            if 'findings' in analysis_result and isinstance(analysis_result['findings'], list):
                validated_findings = []
                for finding in analysis_result['findings']:
                    if isinstance(finding, dict):
                        # Ensure required finding fields
                        validated_finding = {
                            'finding_type': finding.get('finding_type', 'SECURITY_ISSUE'),
                            'severity': finding.get('severity', 'MEDIUM'),
                            'title': finding.get('title', 'Security Finding')[:80],  # Limit title length
                            'evidence': finding.get('evidence', 'No specific evidence provided'),
                            'remediation': finding.get('remediation', 'Review and remediate configuration'),
                            'fedramp_control': finding.get('fedramp_control', 'AC-6')
                        }
                        validated_findings.append(validated_finding)
                
                analysis_result['findings'] = validated_findings
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"JSON validation failed: {e}")
            return {
                'entity_id': 'unknown:unknown',
                'security_posture': 'NEEDS_REVIEW',
                'risk_level': 'HIGH',
                'findings': [{
                    'finding_type': 'ANALYSIS_ERROR',
                    'severity': 'HIGH',
                    'title': 'Analysis Processing Error',
                    'evidence': f'Failed to parse AI response: {str(e)[:200]}',
                    'remediation': 'Manual review required due to analysis error',
                    'fedramp_control': 'CA-7'
                }],
                'validation_error': True
            }
    
    def _enhance_security_analysis(self, analysis_result: Dict, entity_data: Dict) -> Dict:
        """Enhance analysis with additional security checks"""
        try:
            # Add proactive security recommendations
            if 'proactive_recommendations' not in analysis_result:
                analysis_result['proactive_recommendations'] = []
            
            # Check for common security improvements
            entity_type = entity_data.get('type', 'unknown')
            risk_indicators = entity_data.get('risk_indicators', {})
            
            # Add recommendations based on risk indicators
            if risk_indicators.get('missing_mfa', False):
                analysis_result['proactive_recommendations'].append(
                    'Implement MFA requirement for console access'
                )
            
            if risk_indicators.get('old_access_keys', 0) > 0:
                analysis_result['proactive_recommendations'].append(
                    f'Rotate {risk_indicators["old_access_keys"]} old access keys (>90 days)'
                )
            
            if risk_indicators.get('unused_duration_days', 0) > 90:
                analysis_result['proactive_recommendations'].append(
                    'Consider removing or archiving unused entity to reduce attack surface'
                )
            
            if risk_indicators.get('cross_account_trust', False):
                analysis_result['proactive_recommendations'].append(
                    'Review cross-account trust relationships and add restrictive conditions'
                )
            
            # Add baseline compliance check
            analysis_result['baseline_compliance'] = {
                'meets_fedramp_baseline': self._check_fedramp_baseline_compliance(entity_data),
                'required_improvements': self._get_baseline_improvements(entity_data)
            }
            
            return analysis_result
            
        except Exception as e:
            logger.warning(f"Failed to enhance security analysis: {e}")
            return analysis_result
    
    def _check_fedramp_baseline_compliance(self, entity_data: Dict) -> bool:
        """Check if entity meets FedRAMP High baseline requirements"""
        try:
            risk_indicators = entity_data.get('risk_indicators', {})
            
            # Basic compliance checks
            compliance_issues = []
            
            if risk_indicators.get('admin_access', False):
                compliance_issues.append('Administrative access without proper controls')
            
            if risk_indicators.get('wildcard_policies', 0) > 0:
                compliance_issues.append('Overly permissive wildcard policies')
            
            if risk_indicators.get('cross_account_trust', False):
                compliance_issues.append('Cross-account trust without proper validation')
            
            # Return True if no major compliance issues
            return len(compliance_issues) == 0
            
        except Exception as e:
            logger.warning(f"Baseline compliance check failed: {e}")
            return False
    
    def _get_baseline_improvements(self, entity_data: Dict) -> List[str]:
        """Get specific improvements needed for baseline compliance"""
        improvements = []
        
        try:
            risk_indicators = entity_data.get('risk_indicators', {})
            entity_type = entity_data.get('type', 'unknown')
            
            if risk_indicators.get('wildcard_policies', 0) > 0:
                improvements.append('Replace wildcard permissions with specific, scoped permissions')
            
            if risk_indicators.get('high_privilege_policies', 0) > 0:
                improvements.append('Review and reduce high-privilege policy attachments')
            
            if entity_type == 'user' and risk_indicators.get('missing_mfa', False):
                improvements.append('Enable MFA for user console access')
            
            if risk_indicators.get('unused_duration_days', 0) > 90:
                improvements.append('Remove or justify unused entity to maintain least privilege')
            
            return improvements
            
        except Exception as e:
            logger.warning(f"Failed to generate baseline improvements: {e}")
            return ['Manual review required for baseline compliance']
    
    def _create_error_response(self, entity_data: Dict, error_message: str, error_type: str) -> Dict:
        """Create standardized error response"""
        entity_type = entity_data.get('type', 'unknown')
        entity_name = entity_data.get('name', 'unknown')
        
        return {
            'entity_id': f"{entity_type}:{entity_name}",
            'security_posture': 'NEEDS_REVIEW',
            'risk_level': 'HIGH',
            'findings': [{
                'finding_type': 'ANALYSIS_ERROR',
                'severity': 'HIGH',
                'title': 'Security Analysis Failed',
                'evidence': f'Analysis error: {error_message[:200]}',
                'remediation': 'Manual security review required due to analysis failure',
                'fedramp_control': 'CA-7'
            }],
            'error': error_message,
            'analysis_failed': True,
            'metadata': {
                'entity_id': f"{entity_type}:{entity_name}",
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'error_type': error_type,
                'requires_manual_review': True
            }
        }
    
    def classify_role(self, role_data: Dict) -> Dict:
        """Classify IAM role using persona-based security analysis"""
        try:
            role_name = role_data.get('name', 'unknown')
            role_path = role_data.get('path', '/')
            
            # Prepare structured data for persona analysis
            trust_policy = role_data.get('trust_policy', {})
            attached_policies = role_data.get('attached_policies', [])
            business_context = role_data.get('business_context', {})
            usage_data = role_data.get('access_advisor', {})
            
            # Create policies summary for analysis
            policies_summary = {
                'attached_count': len(attached_policies),
                'aws_managed_count': len([p for p in attached_policies if p.get('is_aws_managed', False)]),
                'customer_managed_count': len([p for p in attached_policies if not p.get('is_aws_managed', False)]),
                'inline_count': len(role_data.get('inline_policies', [])),
                'high_risk_policies': [p.get('name', 'unknown') for p in attached_policies 
                                     if self._is_high_risk_policy(p)],
                'administrative_policies': [p.get('name', 'unknown') for p in attached_policies 
                                          if self._is_administrative_policy(p)]
            }
            
            # Prepare prompt data
            prompt_data = {
                'role_name': role_name,
                'role_path': role_path,
                'trust_policy': json.dumps(trust_policy, indent=2),
                'policies_summary': json.dumps(policies_summary, indent=2),
                'usage_data': json.dumps(usage_data, indent=2),
                'business_context': json.dumps(business_context, indent=2)
            }
            
            # Format persona analysis prompt
            prompt = self.prompts['role_persona_analysis'].format(**prompt_data)
            
            # Invoke Bedrock model
            response = self._invoke_bedrock_model(prompt, max_tokens=1500)
            
            # Parse and validate response
            classification_result = self._extract_and_validate_json(response, 'role_persona_analysis')
            
            # Enhance with security-focused persona validation
            classification_result = self._validate_persona_classification(classification_result, role_data)
            
            # Add metadata
            classification_result['metadata'] = {
                'role_name': role_name,
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'model_used': self.bedrock_model,
                'prompt_type': 'role_persona_analysis',
                'security_focus': 'persona_based_access_control'
            }
            
            return classification_result
            
        except Exception as e:
            logger.error(f"Role persona analysis failed for {role_data.get('name', 'unknown')}: {e}")
            return self._create_persona_error_response(role_data, str(e))
    
    def _is_high_risk_policy(self, policy: Dict) -> bool:
        """Check if policy contains high-risk permissions"""
        try:
            policy_doc = policy.get('document', {})
            if not isinstance(policy_doc, dict):
                return False
            
            # Check policy name for known high-risk patterns
            policy_name = policy.get('name', '').lower()
            high_risk_names = [
                'administratoraccess', 'poweruseraccess', 'iamfullaccess',
                'ec2fullaccess', 's3fullaccess', 'lambdafullaccess'
            ]
            
            if any(risk_name in policy_name for risk_name in high_risk_names):
                return True
            
            # Check for high-risk actions in policy document
            high_risk_actions = self._identify_high_risk_actions(policy_doc)
            return len(high_risk_actions) > 0
            
        except Exception:
            return False
    
    def _is_administrative_policy(self, policy: Dict) -> bool:
        """Check if policy provides administrative access"""
        try:
            policy_name = policy.get('name', '').lower()
            admin_patterns = ['admin', 'full', 'power', 'root', 'superuser']
            
            return any(pattern in policy_name for pattern in admin_patterns)
            
        except Exception:
            return False
    
    def _validate_persona_classification(self, classification_result: Dict, role_data: Dict) -> Dict:
        """Validate and enhance persona classification with security checks"""
        try:
            # Get classification details
            persona_classification = classification_result.get('persona_classification', {})
            primary_persona = persona_classification.get('primary_persona', 'UNKNOWN')
            
            # Perform security validation based on persona
            security_validation = self._perform_persona_security_validation(primary_persona, role_data)
            
            # Add security validation results
            classification_result['security_validation'] = security_validation
            
            # Add persona-specific security recommendations
            classification_result['persona_security_recommendations'] = self._get_persona_security_recommendations(
                primary_persona, role_data, security_validation
            )
            
            # Calculate persona confidence based on security alignment
            original_confidence = persona_classification.get('confidence', 5)
            security_penalty = len(security_validation.get('violations', []))
            adjusted_confidence = max(1, original_confidence - security_penalty)
            
            if 'persona_classification' in classification_result:
                classification_result['persona_classification']['adjusted_confidence'] = adjusted_confidence
                classification_result['persona_classification']['security_aligned'] = security_penalty == 0
            
            return classification_result
            
        except Exception as e:
            logger.warning(f"Persona validation failed: {e}")
            return classification_result
    
    def _perform_persona_security_validation(self, persona: str, role_data: Dict) -> Dict:
        """Perform security validation based on persona type"""
        validation = {
            'persona': persona,
            'compliant': True,
            'violations': [],
            'recommendations': []
        }
        
        try:
            trust_policy = role_data.get('trust_policy', {})
            risk_indicators = role_data.get('risk_indicators', {})
            
            if persona == 'HUMAN_INTERACTIVE':
                # Human roles should have MFA requirements
                if not self._has_mfa_condition(trust_policy):
                    validation['violations'].append('Missing MFA condition for human interactive role')
                    validation['compliant'] = False
                
                # Should have session duration limits
                max_session = role_data.get('max_session_duration', 3600)
                if max_session > 3600:  # 1 hour
                    validation['violations'].append('Session duration too long for human interactive role')
                    validation['compliant'] = False
            
            elif persona == 'SERVICE_EXECUTION':
                # Service roles should only trust AWS services
                if not self._has_service_principal_only(trust_policy):
                    validation['violations'].append('Service role allows non-service principals')
                    validation['compliant'] = False
            
            elif persona == 'CROSS_ACCOUNT_ACCESS':
                # Cross-account roles need strict conditions
                if not self._has_external_id_condition(trust_policy):
                    validation['violations'].append('Cross-account role missing ExternalId condition')
                    validation['compliant'] = False
                
                if risk_indicators.get('admin_access', False):
                    validation['violations'].append('Cross-account role has administrative access')
                    validation['compliant'] = False
            
            elif persona == 'ADMINISTRATIVE_BREAK_GLASS':
                # Break-glass roles need extensive monitoring
                if not self._has_comprehensive_logging(role_data):
                    validation['violations'].append('Break-glass role lacks comprehensive logging')
                    validation['compliant'] = False
            
            # Common validations for all personas
            if risk_indicators.get('wildcard_policies', 0) > 2:
                validation['violations'].append('Excessive wildcard permissions for persona type')
                validation['compliant'] = False
            
            return validation
            
        except Exception as e:
            logger.warning(f"Persona security validation failed: {e}")
            validation['violations'].append(f'Validation error: {str(e)}')
            validation['compliant'] = False
            return validation
    
    def _has_mfa_condition(self, trust_policy: Dict) -> bool:
        """Check if trust policy requires MFA"""
        try:
            statements = trust_policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for stmt in statements:
                if isinstance(stmt, dict):
                    condition = stmt.get('Condition', {})
                    if 'Bool' in condition:
                        bool_conditions = condition['Bool']
                        if 'aws:MultiFactorAuthPresent' in bool_conditions:
                            return bool_conditions['aws:MultiFactorAuthPresent'] == 'true'
            
            return False
            
        except Exception:
            return False
    
    def _has_service_principal_only(self, trust_policy: Dict) -> bool:
        """Check if trust policy only allows AWS service principals"""
        try:
            statements = trust_policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for stmt in statements:
                if isinstance(stmt, dict):
                    principal = stmt.get('Principal', {})
                    if isinstance(principal, dict):
                        # Check for Service principals
                        if 'Service' not in principal:
                            return False
                        # Check for other principal types
                        if any(key in principal for key in ['AWS', 'Federated']):
                            return False
            
            return True
            
        except Exception:
            return False
    
    def _has_external_id_condition(self, trust_policy: Dict) -> bool:
        """Check if trust policy has ExternalId condition"""
        try:
            statements = trust_policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for stmt in statements:
                if isinstance(stmt, dict):
                    condition = stmt.get('Condition', {})
                    if 'StringEquals' in condition:
                        string_conditions = condition['StringEquals']
                        if 'sts:ExternalId' in string_conditions:
                            return True
            
            return False
            
        except Exception:
            return False
    
    def _has_comprehensive_logging(self, role_data: Dict) -> bool:
        """Check if role has comprehensive logging setup"""
        # This is a simplified check - in practice, you'd check CloudTrail configuration
        # For now, we'll assume roles with specific naming patterns have logging
        role_name = role_data.get('name', '').lower()
        return 'breakglass' in role_name or 'emergency' in role_name
    
    def _get_persona_security_recommendations(self, persona: str, role_data: Dict, 
                                            security_validation: Dict) -> List[str]:
        """Get persona-specific security recommendations"""
        recommendations = []
        
        try:
            if not security_validation.get('compliant', True):
                # Add specific recommendations based on violations
                for violation in security_validation.get('violations', []):
                    if 'MFA' in violation:
                        recommendations.append('Add MFA condition to trust policy for human access')
                    elif 'session duration' in violation:
                        recommendations.append('Reduce maximum session duration to 1 hour or less')
                    elif 'service principal' in violation:
                        recommendations.append('Restrict trust policy to AWS service principals only')
                    elif 'ExternalId' in violation:
                        recommendations.append('Add ExternalId condition for cross-account access')
                    elif 'logging' in violation:
                        recommendations.append('Implement comprehensive CloudTrail logging')
                    elif 'wildcard' in violation:
                        recommendations.append('Replace wildcard permissions with specific actions')
            
            # Add persona-specific proactive recommendations
            if persona == 'HUMAN_INTERACTIVE':
                recommendations.extend([
                    'Implement IP address restrictions for console access',
                    'Add time-based access controls for business hours only',
                    'Enable session recording for audit purposes'
                ])
            elif persona == 'SERVICE_EXECUTION':
                recommendations.extend([
                    'Use resource-based policies where possible instead of IAM roles',
                    'Implement least-privilege permissions for specific service functions',
                    'Add VPC endpoint restrictions for service communications'
                ])
            elif persona == 'CROSS_ACCOUNT_ACCESS':
                recommendations.extend([
                    'Implement account ID restrictions in trust policy',
                    'Add time-based access windows for cross-account operations',
                    'Enable enhanced monitoring for cross-account activities'
                ])
            
            return list(set(recommendations))  # Remove duplicates
            
        except Exception as e:
            logger.warning(f"Failed to generate persona recommendations: {e}")
            return ['Manual review recommended for persona-specific security improvements']
    
    def _create_persona_error_response(self, role_data: Dict, error_message: str) -> Dict:
        """Create error response for persona analysis failure"""
        role_name = role_data.get('name', 'unknown')
        
        return {
            'role_name': role_name,
            'persona_classification': {
                'primary_persona': 'UNKNOWN',
                'confidence': 1,
                'evidence': f'Analysis failed: {error_message}',
                'persona_violations': ['Analysis error prevented classification']
            },
            'security_alignment': {
                'trust_policy_appropriate': False,
                'permissions_scoped': False,
                'fedramp_compliant': False
            },
            'baseline_compliance': {
                'meets_baseline': False,
                'required_changes': ['Manual review required due to analysis failure']
            },
            'error': error_message,
            'classification_failed': True,
            'metadata': {
                'role_name': role_name,
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'error_type': 'persona_analysis_failure',
                'requires_manual_review': True
            }
        }
    
    def generate_compliance_mapping(self, entity_data: Dict) -> Dict:
        """Generate compliance control mapping using AI"""
        try:
            entity_type = entity_data.get('type', 'unknown')
            entity_name = entity_data.get('name', 'unknown')
            
            # Prepare policy summary
            policies = []
            policies.extend(entity_data.get('attached_policies', []))
            policies.extend(entity_data.get('inline_policies', []))
            
            policies_summary = [
                {
                    'name': p.get('name', 'unknown'),
                    'type': p.get('type', 'unknown'),
                    'is_aws_managed': p.get('is_aws_managed', False)
                }
                for p in policies
            ]
            
            # Prepare configuration summary
            configuration = {
                'trust_policy': entity_data.get('trust_policy', {}),
                'risk_indicators': entity_data.get('risk_indicators', {}),
                'access_advisor': entity_data.get('access_advisor', {})
            }
            
            business_context = entity_data.get('business_context', {})
            
            # Format prompt
            prompt = self.prompts['compliance_mapping'].format(
                entity_name=entity_name,
                entity_type=entity_type,
                policies_summary=json.dumps(policies_summary, indent=2),
                configuration=json.dumps(configuration, indent=2),
                business_context=json.dumps(business_context, indent=2),
                compliance_framework=self.compliance_framework
            )
            
            # Invoke Bedrock model
            response = self._invoke_bedrock_model(prompt)
            
            # Parse response
            compliance_result = self._extract_json_from_response(response)
            
            # Add metadata
            compliance_result['metadata'] = {
                'entity_id': f"{entity_type}:{entity_name}",
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'model_used': self.bedrock_model,
                'compliance_framework': self.compliance_framework,
                'prompt_type': 'compliance_mapping'
            }
            
            return compliance_result
            
        except Exception as e:
            logger.error(f"Compliance mapping failed for {entity_data.get('name', 'unknown')}: {e}")
            return {
                'error': str(e),
                'compliance_mapping_failed': True,
                'metadata': {
                    'entity_id': f"{entity_data.get('type', 'unknown')}:{entity_data.get('name', 'unknown')}",
                    'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                    'error_type': 'compliance_mapping_failure'
                }
            }
    
    def create_security_hub_findings(self, analysis_results: List[Dict]) -> None:
        """Create Security Hub findings from analysis results"""
        if not self.enable_security_hub:
            logger.info("Security Hub integration disabled")
            return
        
        try:
            findings = []
            
            for result in analysis_results:
                metadata = result.get('metadata', {})
                entity_id = metadata.get('entity_id', 'unknown')
                
                # Skip if analysis failed
                if result.get('analysis_failed') or result.get('error'):
                    continue
                
                # Extract security findings from AI analysis
                security_findings = result.get('security_findings', [])
                
                for finding in security_findings:
                    severity = finding.get('severity', 'MEDIUM')
                    
                    # Filter by risk threshold
                    severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
                    threshold_level = severity_levels.get(self.risk_threshold, 2)
                    finding_level = severity_levels.get(severity, 1)
                    
                    if finding_level < threshold_level:
                        continue
                    
                    # Create Security Hub finding
                    hub_finding = {
                        'SchemaVersion': '2018-10-08',
                        'Id': f"ai-iam-analyzer/{entity_id}/{finding.get('finding_id', 'unknown')}",
                        'ProductArn': f"arn:aws-us-gov:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default",
                        'GeneratorId': 'AI-IAM-Analyzer',
                        'AwsAccountId': self.account_id,
                        'Types': ['Software and Configuration Checks/AWS Security Best Practices/IAM'],
                        'CreatedAt': datetime.now(timezone.utc).isoformat(),
                        'UpdatedAt': datetime.now(timezone.utc).isoformat(),
                        'Severity': {'Label': severity},
                        'Title': finding.get('title', 'IAM Security Finding')[:256],
                        'Description': finding.get('description', 'AI-detected IAM security issue')[:1024],
                        'Resources': [{
                            'Type': 'AwsIamRole' if 'role:' in entity_id else 'AwsIamUser',
                            'Id': entity_id,
                            'Region': self.region
                        }],
                        'Remediation': {
                            'Recommendation': {
                                'Text': finding.get('remediation', 'Review and remediate IAM configuration')[:512]
                            }
                        },
                        'RecordState': 'ACTIVE',
                        'ProductFields': {
                            'AI_Model': self.bedrock_model,
                            'Compliance_Framework': self.compliance_framework,
                            'Business_Impact': finding.get('business_impact', 'Unknown')[:256],
                            'NIST_Controls': ','.join(finding.get('nist_controls', []))
                        }
                    }
                    
                    findings.append(hub_finding)
            
            # Batch import findings
            if findings:
                # Security Hub has a limit of 100 findings per batch
                for i in range(0, len(findings), 100):
                    batch = findings[i:i + 100]
                    
                    self.securityhub.batch_import_findings(Findings=batch)
                    logger.info(f"Imported {len(batch)} findings to Security Hub")
                
                logger.info(f"Total {len(findings)} findings imported to Security Hub")
            else:
                logger.info("No findings met the risk threshold for Security Hub import")
                
        except Exception as e:
            logger.error(f"Failed to create Security Hub findings: {e}")
    
    def save_analysis_results(self, results: List[Dict], batch_info: Dict) -> str:
        """Save analysis results to S3"""
        try:
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
            key = f"analysis/results/{timestamp}-analysis-results.json"
            
            output_data = {
                'batch_info': batch_info,
                'analysis_timestamp': timestamp,
                'model_used': self.bedrock_model,
                'compliance_framework': self.compliance_framework,
                'results_count': len(results),
                'results': results,
                'summary': self._generate_analysis_summary(results)
            }
            
            self.s3.put_object(
                Bucket=self.reports_bucket,
                Key=key,
                Body=json.dumps(output_data, default=str, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
            logger.info(f"Saved analysis results to s3://{self.reports_bucket}/{key}")
            return key
            
        except Exception as e:
            logger.error(f"Failed to save analysis results: {e}")
            raise
    
    def _generate_analysis_summary(self, results: List[Dict]) -> Dict:
        """Generate summary statistics from analysis results"""
        summary = {
            'total_entities': len(results),
            'successful_analyses': 0,
            'failed_analyses': 0,
            'risk_distribution': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
            'compliance_status': {'COMPLIANT': 0, 'NON_COMPLIANT': 0, 'PARTIALLY_COMPLIANT': 0},
            'total_findings': 0,
            'critical_findings': 0
        }
        
        for result in results:
            if result.get('analysis_failed') or result.get('error'):
                summary['failed_analyses'] += 1
                continue
            
            summary['successful_analyses'] += 1
            
            # Risk level distribution
            risk_level = result.get('risk_level', 'UNKNOWN')
            if risk_level in summary['risk_distribution']:
                summary['risk_distribution'][risk_level] += 1
            
            # Compliance status
            compliance_status = result.get('compliance_status', {}).get('compliant')
            if compliance_status is True:
                summary['compliance_status']['COMPLIANT'] += 1
            elif compliance_status is False:
                summary['compliance_status']['NON_COMPLIANT'] += 1
            else:
                summary['compliance_status']['PARTIALLY_COMPLIANT'] += 1
            
            # Findings count
            findings = result.get('security_findings', [])
            summary['total_findings'] += len(findings)
            summary['critical_findings'] += len([f for f in findings if f.get('severity') == 'CRITICAL'])
        
        return summary

def lambda_handler(event, context):
    """Main Lambda handler for Bedrock IAM analysis"""
    
    logger.info(f"Starting Bedrock IAM analysis with event: {json.dumps(event, default=str)}")
    
    try:
        analyzer = BedrockPolicyAnalyzer()
        
        # Determine analysis source
        source = event.get('source', 'unknown')
        
        if source == 'data_collector':
            # Process batch from data collector
            s3_bucket = event.get('s3_bucket')
            s3_key = event.get('s3_key')
            
            if not s3_bucket or not s3_key:
                raise ValueError("Missing S3 bucket or key for batch processing")
            
            # Load batch data from S3
            response = analyzer.s3.get_object(Bucket=s3_bucket, Key=s3_key)
            batch_data = json.loads(response['Body'].read())
            
            entities = batch_data.get('entities', [])
            batch_info = batch_data.get('metadata', {})
            
            logger.info(f"Processing batch with {len(entities)} entities")
            
        elif source == 'eventbridge':
            # Process single entity from EventBridge (real-time analysis)
            # Implementation for real-time policy change analysis
            entities = [event.get('entity_data', {})]
            batch_info = {'source': 'eventbridge', 'real_time': True}
            
        else:
            raise ValueError(f"Unknown analysis source: {source}")
        
        # Perform AI analysis on entities
        analysis_results = []
        
        for entity in entities:
            try:
                entity_data = entity.get('entity_data', entity)
                entity_type = entity_data.get('type', 'unknown')
                entity_name = entity_data.get('name', 'unknown')
                
                logger.info(f"Analyzing {entity_type}: {entity_name}")
                
                # Perform policy analysis
                policy_analysis = analyzer.analyze_policy(entity_data)
                
                # Perform role classification (for roles only)
                if entity_type == 'role':
                    role_classification = analyzer.classify_role(entity_data)
                    policy_analysis['role_classification'] = role_classification
                
                # Generate compliance mapping
                compliance_mapping = analyzer.generate_compliance_mapping(entity_data)
                policy_analysis['compliance_mapping'] = compliance_mapping
                
                analysis_results.append(policy_analysis)
                
            except Exception as e:
                logger.error(f"Failed to analyze entity {entity_data.get('name', 'unknown')}: {e}")
                analysis_results.append({
                    'error': str(e),
                    'analysis_failed': True,
                    'metadata': {
                        'entity_id': f"{entity_data.get('type', 'unknown')}:{entity_data.get('name', 'unknown')}",
                        'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                        'error_type': 'entity_analysis_failure'
                    }
                })
        
        # Save analysis results
        results_key = analyzer.save_analysis_results(analysis_results, batch_info)
        
        # Create Security Hub findings
        analyzer.create_security_hub_findings(analysis_results)
        
        # Generate summary
        summary = analyzer._generate_analysis_summary(analysis_results)
        
        result = {
            'status': 'success',
            'entities_processed': len(entities),
            'successful_analyses': summary['successful_analyses'],
            'failed_analyses': summary['failed_analyses'],
            'results_s3_key': results_key,
            'summary': summary,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Bedrock analysis completed: {json.dumps(result, default=str)}")
        return result
        
    except Exception as e:
        logger.error(f"Bedrock analysis failed: {e}")
        
        error_result = {
            'status': 'error',
            'error_message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return error_result