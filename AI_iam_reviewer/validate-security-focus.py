#!/usr/bin/env python3
"""
Security-Focused Validation Script for AI IAM Reviewer
FedRAMP High Environment

This script validates that the AI-powered IAM analysis solution meets
the specific security objectives:
1. Proactive security posture improvement
2. Access control excellence
3. Persona and role management
4. FedRAMP High baseline compliance
5. Prevention of AI hallucinations

Usage:
    python3 validate-security-focus.py --stack-name ai-iam-reviewer-fedramp --region us-gov-west-1
"""

import argparse
import boto3
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityFocusValidator:
    """Validates AI IAM Reviewer security objectives"""
    
    def __init__(self, stack_name: str, region: str):
        self.stack_name = stack_name
        self.region = region
        
        # Initialize AWS clients
        self.session = boto3.Session(region_name=region)
        self.cf = self.session.client('cloudformation')
        self.lambda_client = self.session.client('lambda')
        self.s3 = self.session.client('s3')
        self.iam = self.session.client('iam')
        self.bedrock = self.session.client('bedrock-runtime')
        self.sts = self.session.client('sts')
        
        self.account_id = self.sts.get_caller_identity()['Account']
        self.validation_results = []
    
    def log_result(self, test_name: str, passed: bool, details: str = ""):
        """Log validation result"""
        status = "PASS" if passed else "FAIL"
        logger.info(f"[{status}] {test_name}: {details}")
        self.validation_results.append({
            'test': test_name,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    
    def validate_security_objectives(self) -> bool:
        """Validate all security objectives are met"""
        logger.info("Starting security-focused validation...")
        
        # 1. Validate proactive security capabilities
        self.validate_proactive_security()
        
        # 2. Validate access control excellence
        self.validate_access_control_excellence()
        
        # 3. Validate persona-based role management
        self.validate_persona_management()
        
        # 4. Validate FedRAMP High baseline compliance
        self.validate_fedramp_compliance()
        
        # 5. Validate AI hallucination prevention
        self.validate_hallucination_prevention()
        
        # 6. Test real-world security scenarios
        self.test_security_scenarios()
        
        # Generate summary
        return self.generate_validation_summary()
    
    def validate_proactive_security(self) -> None:
        """Validate proactive security capabilities"""
        logger.info("Validating proactive security capabilities...")
        
        try:
            # Check if solution can identify unused roles proactively
            test_role_data = self.create_test_role_data('unused_role', unused_days=120)
            analysis_result = self.run_test_analysis(test_role_data)
            
            # Should identify as unused and recommend removal
            findings = analysis_result.get('findings', [])
            unused_finding = any(
                'unused' in finding.get('title', '').lower() or 
                'stale' in finding.get('title', '').lower()
                for finding in findings
            )
            
            self.log_result(
                "Proactive Unused Role Detection",
                unused_finding,
                f"Found {len(findings)} findings, unused detection: {unused_finding}"
            )
            
            # Check if solution provides proactive recommendations
            proactive_recs = analysis_result.get('proactive_recommendations', [])
            has_proactive_recs = len(proactive_recs) > 0
            
            self.log_result(
                "Proactive Security Recommendations",
                has_proactive_recs,
                f"Generated {len(proactive_recs)} proactive recommendations"
            )
            
            # Check if solution identifies privilege escalation risks
            escalation_role_data = self.create_test_role_data('escalation_role', has_iam_passrole=True)
            escalation_analysis = self.run_test_analysis(escalation_role_data)
            
            escalation_findings = escalation_analysis.get('findings', [])
            escalation_detected = any(
                'escalation' in finding.get('title', '').lower() or
                'passrole' in finding.get('title', '').lower()
                for finding in escalation_findings
            )
            
            self.log_result(
                "Privilege Escalation Detection",
                escalation_detected,
                f"Detected privilege escalation risk: {escalation_detected}"
            )
            
        except Exception as e:
            self.log_result("Proactive Security Validation", False, f"Error: {str(e)}")
    
    def validate_access_control_excellence(self) -> None:
        """Validate access control excellence capabilities"""
        logger.info("Validating access control excellence...")
        
        try:
            # Test wildcard permission detection
            wildcard_role_data = self.create_test_role_data('wildcard_role', has_wildcards=True)
            wildcard_analysis = self.run_test_analysis(wildcard_role_data)
            
            wildcard_findings = wildcard_analysis.get('findings', [])
            wildcard_detected = any(
                'wildcard' in finding.get('title', '').lower() or
                'excessive' in finding.get('title', '').lower()
                for finding in wildcard_findings
            )
            
            self.log_result(
                "Wildcard Permission Detection",
                wildcard_detected,
                f"Detected wildcard permissions: {wildcard_detected}"
            )
            
            # Test least privilege assessment
            access_optimization = wildcard_analysis.get('access_optimization', {})
            has_optimization = 'unused_permissions' in access_optimization
            
            self.log_result(
                "Least Privilege Assessment",
                has_optimization,
                f"Provides access optimization: {has_optimization}"
            )
            
            # Test condition-based access control recommendations
            findings_with_conditions = [
                f for f in wildcard_findings 
                if 'condition' in f.get('remediation', '').lower() or
                   'mfa' in f.get('remediation', '').lower()
            ]
            
            self.log_result(
                "Condition-Based Access Control",
                len(findings_with_conditions) > 0,
                f"Recommends {len(findings_with_conditions)} condition-based controls"
            )
            
        except Exception as e:
            self.log_result("Access Control Excellence Validation", False, f"Error: {str(e)}")
    
    def validate_persona_management(self) -> None:
        """Validate persona-based role management"""
        logger.info("Validating persona-based role management...")
        
        try:
            # Test human interactive role classification
            human_role_data = self.create_test_role_data('human_role', persona_type='human')
            human_analysis = self.run_persona_analysis(human_role_data)
            
            persona_classification = human_analysis.get('persona_classification', {})
            detected_persona = persona_classification.get('primary_persona', 'UNKNOWN')
            
            self.log_result(
                "Human Role Persona Detection",
                detected_persona == 'HUMAN_INTERACTIVE',
                f"Detected persona: {detected_persona}"
            )
            
            # Test service role classification
            service_role_data = self.create_test_role_data('service_role', persona_type='service')
            service_analysis = self.run_persona_analysis(service_role_data)
            
            service_persona = service_analysis.get('persona_classification', {}).get('primary_persona', 'UNKNOWN')
            
            self.log_result(
                "Service Role Persona Detection",
                service_persona == 'SERVICE_EXECUTION',
                f"Detected persona: {service_persona}"
            )
            
            # Test cross-account role classification
            cross_account_data = self.create_test_role_data('cross_account_role', persona_type='cross_account')
            cross_account_analysis = self.run_persona_analysis(cross_account_data)
            
            cross_account_persona = cross_account_analysis.get('persona_classification', {}).get('primary_persona', 'UNKNOWN')
            
            self.log_result(
                "Cross-Account Role Persona Detection",
                cross_account_persona == 'CROSS_ACCOUNT_ACCESS',
                f"Detected persona: {cross_account_persona}"
            )
            
            # Test persona security validation
            security_validation = human_analysis.get('security_validation', {})
            has_security_validation = 'compliant' in security_validation
            
            self.log_result(
                "Persona Security Validation",
                has_security_validation,
                f"Provides persona security validation: {has_security_validation}"
            )
            
        except Exception as e:
            self.log_result("Persona Management Validation", False, f"Error: {str(e)}")
    
    def validate_fedramp_compliance(self) -> None:
        """Validate FedRAMP High baseline compliance"""
        logger.info("Validating FedRAMP High compliance...")
        
        try:
            # Test NIST control mapping
            test_role_data = self.create_test_role_data('compliance_test_role')
            compliance_analysis = self.run_compliance_analysis(test_role_data)
            
            control_mappings = compliance_analysis.get('control_mappings', [])
            has_nist_controls = any(
                mapping.get('control_id', '').startswith(('AC-', 'AU-', 'CA-', 'SI-'))
                for mapping in control_mappings
            )
            
            self.log_result(
                "NIST Control Mapping",
                has_nist_controls,
                f"Maps to {len(control_mappings)} NIST controls"
            )
            
            # Test baseline compliance assessment
            baseline_compliance = compliance_analysis.get('baseline_compliance', {})
            has_baseline_assessment = 'meets_baseline' in baseline_compliance
            
            self.log_result(
                "Baseline Compliance Assessment",
                has_baseline_assessment,
                f"Provides baseline assessment: {has_baseline_assessment}"
            )
            
            # Test compliance evidence generation
            audit_evidence = compliance_analysis.get('audit_evidence', {})
            has_audit_evidence = len(audit_evidence) > 0
            
            self.log_result(
                "Audit Evidence Generation",
                has_audit_evidence,
                f"Generates audit evidence: {has_audit_evidence}"
            )
            
            # Test FedRAMP-specific findings
            findings = compliance_analysis.get('findings', [])
            fedramp_findings = [
                f for f in findings 
                if f.get('fedramp_control') and f.get('fedramp_control').startswith(('AC-', 'AU-', 'CA-', 'SI-'))
            ]
            
            self.log_result(
                "FedRAMP-Specific Findings",
                len(fedramp_findings) > 0,
                f"Generated {len(fedramp_findings)} FedRAMP-specific findings"
            )
            
        except Exception as e:
            self.log_result("FedRAMP Compliance Validation", False, f"Error: {str(e)}")
    
    def validate_hallucination_prevention(self) -> None:
        """Validate AI hallucination prevention measures"""
        logger.info("Validating hallucination prevention...")
        
        try:
            # Test with minimal data to ensure no hallucinations
            minimal_role_data = {
                'type': 'role',
                'name': 'minimal-test-role',
                'created_date': '2024-01-01T00:00:00Z',
                'trust_policy': {},
                'attached_policies': [],
                'inline_policies': [],
                'access_advisor': {},
                'business_context': {}
            }
            
            minimal_analysis = self.run_test_analysis(minimal_role_data)
            
            # Should not hallucinate findings without evidence
            findings = minimal_analysis.get('findings', [])
            has_evidence = all(
                finding.get('evidence') and finding.get('evidence') != 'No specific evidence provided'
                for finding in findings
            )
            
            self.log_result(
                "Evidence-Based Findings Only",
                has_evidence or len(findings) == 0,
                f"All {len(findings)} findings have evidence"
            )
            
            # Test JSON structure validation
            required_fields = ['entity_id', 'security_posture', 'risk_level', 'findings']
            has_required_fields = all(field in minimal_analysis for field in required_fields)
            
            self.log_result(
                "Structured Output Validation",
                has_required_fields,
                f"Contains all required fields: {has_required_fields}"
            )
            
            # Test finding structure validation
            valid_findings = all(
                isinstance(finding, dict) and
                'finding_type' in finding and
                'severity' in finding and
                'title' in finding
                for finding in findings
            )
            
            self.log_result(
                "Finding Structure Validation",
                valid_findings or len(findings) == 0,
                f"All findings have valid structure"
            )
            
            # Test severity level validation
            valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            valid_severity_levels = all(
                finding.get('severity') in valid_severities
                for finding in findings
            )
            
            self.log_result(
                "Severity Level Validation",
                valid_severity_levels or len(findings) == 0,
                f"All severities are valid"
            )
            
        except Exception as e:
            self.log_result("Hallucination Prevention Validation", False, f"Error: {str(e)}")
    
    def test_security_scenarios(self) -> None:
        """Test real-world security scenarios"""
        logger.info("Testing real-world security scenarios...")
        
        try:
            # Scenario 1: Over-privileged service role
            overprivileged_data = self.create_test_role_data(
                'overprivileged-service-role',
                persona_type='service',
                has_wildcards=True,
                has_admin_access=True
            )
            
            overprivileged_analysis = self.run_test_analysis(overprivileged_data)
            detected_overpriv = overprivileged_analysis.get('risk_level') in ['HIGH', 'CRITICAL']
            
            self.log_result(
                "Over-privileged Service Role Detection",
                detected_overpriv,
                f"Risk level: {overprivileged_analysis.get('risk_level', 'UNKNOWN')}"
            )
            
            # Scenario 2: Stale human access role
            stale_human_data = self.create_test_role_data(
                'stale-human-role',
                persona_type='human',
                unused_days=180,
                missing_mfa=True
            )
            
            stale_analysis = self.run_test_analysis(stale_human_data)
            stale_findings = stale_analysis.get('findings', [])
            
            detected_stale_issues = any(
                'unused' in finding.get('title', '').lower() or
                'mfa' in finding.get('title', '').lower()
                for finding in stale_findings
            )
            
            self.log_result(
                "Stale Human Access Detection",
                detected_stale_issues,
                f"Detected stale access issues: {detected_stale_issues}"
            )
            
            # Scenario 3: Insecure cross-account role
            insecure_cross_account_data = self.create_test_role_data(
                'insecure-cross-account-role',
                persona_type='cross_account',
                missing_external_id=True,
                has_admin_access=True
            )
            
            cross_account_analysis = self.run_test_analysis(insecure_cross_account_data)
            cross_account_findings = cross_account_analysis.get('findings', [])
            
            detected_cross_account_risks = any(
                'cross' in finding.get('title', '').lower() or
                'external' in finding.get('title', '').lower()
                for finding in cross_account_findings
            )
            
            self.log_result(
                "Insecure Cross-Account Role Detection",
                detected_cross_account_risks,
                f"Detected cross-account risks: {detected_cross_account_risks}"
            )
            
        except Exception as e:
            self.log_result("Security Scenarios Testing", False, f"Error: {str(e)}")
    
    def create_test_role_data(self, role_name: str, **kwargs) -> Dict:
        """Create test role data for validation"""
        base_data = {
            'type': 'role',
            'name': role_name,
            'path': '/',
            'created_date': '2024-01-01T00:00:00Z',
            'max_session_duration': 3600,
            'description': f'Test role for validation: {role_name}',
            'tags': [],
            'trust_policy': {},
            'attached_policies': [],
            'inline_policies': [],
            'access_advisor': {
                'services_accessed': 0,
                'total_services': 10,
                'last_activity': None
            },
            'business_context': {
                'environment': 'test',
                'application': 'validation',
                'owner': 'security-team',
                'criticality': 'medium'
            },
            'risk_indicators': {
                'high_privilege_policies': 0,
                'wildcard_policies': 0,
                'unused_duration_days': 0,
                'missing_mfa': False,
                'cross_account_trust': False,
                'admin_access': False
            }
        }
        
        # Apply test scenario modifications
        if kwargs.get('persona_type') == 'human':
            base_data['trust_policy'] = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'AWS': f'arn:aws-us-gov:iam::{self.account_id}:root'},
                    'Action': 'sts:AssumeRole'
                }]
            }
            if kwargs.get('missing_mfa', False):
                base_data['risk_indicators']['missing_mfa'] = True
        
        elif kwargs.get('persona_type') == 'service':
            base_data['trust_policy'] = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'lambda.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            }
        
        elif kwargs.get('persona_type') == 'cross_account':
            external_account = '123456789012'  # Fake external account
            base_data['trust_policy'] = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'AWS': f'arn:aws-us-gov:iam::{external_account}:root'},
                    'Action': 'sts:AssumeRole'
                }]
            }
            base_data['risk_indicators']['cross_account_trust'] = True
            
            if not kwargs.get('missing_external_id', False):
                base_data['trust_policy']['Statement'][0]['Condition'] = {
                    'StringEquals': {'sts:ExternalId': 'test-external-id'}
                }
        
        if kwargs.get('has_wildcards', False):
            base_data['attached_policies'].append({
                'name': 'WildcardPolicy',
                'arn': f'arn:aws-us-gov:iam::{self.account_id}:policy/WildcardPolicy',
                'type': 'managed',
                'document': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }]
                },
                'is_aws_managed': False
            })
            base_data['risk_indicators']['wildcard_policies'] = 1
        
        if kwargs.get('has_admin_access', False):
            base_data['attached_policies'].append({
                'name': 'AdministratorAccess',
                'arn': 'arn:aws-us-gov:iam::aws:policy/AdministratorAccess',
                'type': 'managed',
                'is_aws_managed': True
            })
            base_data['risk_indicators']['admin_access'] = True
        
        if kwargs.get('has_iam_passrole', False):
            base_data['attached_policies'].append({
                'name': 'PassRolePolicy',
                'arn': f'arn:aws-us-gov:iam::{self.account_id}:policy/PassRolePolicy',
                'type': 'managed',
                'document': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': 'iam:PassRole',
                        'Resource': '*'
                    }]
                },
                'is_aws_managed': False
            })
            base_data['risk_indicators']['high_privilege_policies'] = 1
        
        if kwargs.get('unused_days', 0) > 0:
            from datetime import datetime, timezone, timedelta
            last_activity = datetime.now(timezone.utc) - timedelta(days=kwargs['unused_days'])
            base_data['access_advisor']['last_activity'] = last_activity.isoformat()
            base_data['risk_indicators']['unused_duration_days'] = kwargs['unused_days']
        
        return base_data
    
    def run_test_analysis(self, role_data: Dict) -> Dict:
        """Run test analysis using the deployed solution"""
        try:
            # Get the analyzer function name
            stack_outputs = self.cf.describe_stacks(StackName=self.stack_name)['Stacks'][0]['Outputs']
            analyzer_arn = None
            
            for output in stack_outputs:
                if output['OutputKey'] == 'BedrockAnalyzerFunctionArn':
                    analyzer_arn = output['OutputValue']
                    break
            
            if not analyzer_arn:
                raise ValueError("Bedrock analyzer function ARN not found in stack outputs")
            
            function_name = analyzer_arn.split(':')[-1]
            
            # Prepare test payload
            test_payload = {
                'source': 'validation_test',
                'entities': [{
                    'entity_data': role_data,
                    'entity_id': f"{role_data['type']}:{role_data['name']}",
                    'analysis_timestamp': datetime.now(timezone.utc).isoformat()
                }]
            }
            
            # Invoke the analyzer function
            response = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps(test_payload)
            )
            
            if response['StatusCode'] != 200:
                raise ValueError(f"Lambda invocation failed with status {response['StatusCode']}")
            
            result = json.loads(response['Payload'].read())
            
            if 'errorMessage' in result:
                raise ValueError(f"Lambda execution error: {result['errorMessage']}")
            
            # Extract analysis results
            analysis_results = result.get('analysis_results', [])
            if analysis_results:
                return analysis_results[0]  # Return first result
            else:
                return {'error': 'No analysis results returned'}
            
        except Exception as e:
            logger.error(f"Test analysis failed: {e}")
            return {'error': str(e), 'analysis_failed': True}
    
    def run_persona_analysis(self, role_data: Dict) -> Dict:
        """Run persona analysis test"""
        # For now, use the same test analysis method
        # In a full implementation, this would call the persona-specific analysis
        return self.run_test_analysis(role_data)
    
    def run_compliance_analysis(self, role_data: Dict) -> Dict:
        """Run compliance analysis test"""
        # For now, use the same test analysis method
        # In a full implementation, this would call the compliance-specific analysis
        return self.run_test_analysis(role_data)
    
    def generate_validation_summary(self) -> bool:
        """Generate validation summary and return overall success"""
        total_tests = len(self.validation_results)
        passed_tests = len([r for r in self.validation_results if r['passed']])
        failed_tests = total_tests - passed_tests
        
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        print(f"\n{'='*60}")
        print(f"SECURITY-FOCUSED VALIDATION SUMMARY")
        print(f"{'='*60}")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"{'='*60}")
        
        if failed_tests > 0:
            print(f"\nFAILED TESTS:")
            for result in self.validation_results:
                if not result['passed']:
                    print(f"❌ {result['test']}: {result['details']}")
        
        print(f"\nPASSED TESTS:")
        for result in self.validation_results:
            if result['passed']:
                print(f"✅ {result['test']}: {result['details']}")
        
        # Security objectives assessment
        print(f"\n{'='*60}")
        print(f"SECURITY OBJECTIVES ASSESSMENT")
        print(f"{'='*60}")
        
        objectives = {
            'Proactive Security': [r for r in self.validation_results if 'Proactive' in r['test']],
            'Access Control Excellence': [r for r in self.validation_results if 'Access Control' in r['test'] or 'Wildcard' in r['test'] or 'Privilege' in r['test']],
            'Persona Management': [r for r in self.validation_results if 'Persona' in r['test']],
            'FedRAMP Compliance': [r for r in self.validation_results if 'FedRAMP' in r['test'] or 'NIST' in r['test'] or 'Baseline' in r['test']],
            'Hallucination Prevention': [r for r in self.validation_results if 'Evidence' in r['test'] or 'Structure' in r['test'] or 'Validation' in r['test']]
        }
        
        for objective, tests in objectives.items():
            if tests:
                obj_passed = len([t for t in tests if t['passed']])
                obj_total = len(tests)
                obj_rate = (obj_passed / obj_total) * 100 if obj_total > 0 else 0
                status = "✅ ACHIEVED" if obj_rate >= 80 else "❌ NEEDS WORK"
                print(f"{status} {objective}: {obj_passed}/{obj_total} ({obj_rate:.1f}%)")
        
        # Overall assessment
        overall_success = success_rate >= 80
        print(f"\n{'='*60}")
        if overall_success:
            print(f"🎯 OVERALL ASSESSMENT: SECURITY OBJECTIVES MET")
            print(f"The AI IAM Reviewer solution successfully meets the security objectives")
            print(f"for proactive security, access control, and FedRAMP High compliance.")
        else:
            print(f"⚠️  OVERALL ASSESSMENT: SECURITY OBJECTIVES NEED IMPROVEMENT")
            print(f"The solution requires additional work to meet all security objectives.")
            print(f"Focus on failed tests and improve prompt engineering and validation.")
        
        return overall_success

def main():
    parser = argparse.ArgumentParser(
        description='Validate AI IAM Reviewer security objectives'
    )
    parser.add_argument(
        '--stack-name',
        required=True,
        help='CloudFormation stack name'
    )
    parser.add_argument(
        '--region',
        default='us-gov-west-1',
        help='AWS region (default: us-gov-west-1)'
    )
    
    args = parser.parse_args()
    
    validator = SecurityFocusValidator(args.stack_name, args.region)
    success = validator.validate_security_objectives()
    
    exit(0 if success else 1)

if __name__ == '__main__':
    main()