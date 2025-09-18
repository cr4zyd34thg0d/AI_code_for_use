#!/usr/bin/env python3
"""
AI-Powered IAM Report Generator
FedRAMP High Environment

This Lambda function generates executive-ready reports from AI analysis results,
including compliance summaries, risk assessments, and actionable recommendations.

Features:
- Executive dashboard generation
- Compliance framework reporting
- Trend analysis and metrics
- Natural language summaries
- Multi-format output (JSON, HTML, PDF-ready)
"""

import os
import json
import boto3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class AIIAMReportGenerator:
    """Generates comprehensive reports from AI IAM analysis results"""
    
    def __init__(self):
        # Initialize AWS clients
        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.sts = boto3.client('sts')
        
        # Environment configuration
        self.reports_bucket = os.environ.get('REPORTS_BUCKET')
        self.cache_table_name = os.environ.get('CACHE_TABLE')
        self.compliance_framework = os.environ.get('COMPLIANCE_FRAMEWORK', 'NIST-800-53')
        
        # Initialize DynamoDB table
        if self.cache_table_name:
            self.cache_table = self.dynamodb.Table(self.cache_table_name)
        
        # Get account context
        caller_identity = self.sts.get_caller_identity()
        self.account_id = caller_identity['Account']
        self.region = os.environ.get('AWS_REGION', 'us-gov-west-1')
    
    def generate_executive_summary(self, analysis_results: List[Dict]) -> Dict:
        """Generate executive summary from analysis results"""
        
        # Calculate key metrics
        total_entities = len(analysis_results)
        successful_analyses = len([r for r in analysis_results if not r.get('analysis_failed')])
        
        # Risk distribution
        risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        compliance_counts = {'COMPLIANT': 0, 'NON_COMPLIANT': 0, 'PARTIALLY_COMPLIANT': 0}
        
        total_findings = 0
        critical_findings = 0
        high_findings = 0
        
        entity_types = {'role': 0, 'user': 0}
        unused_entities = 0
        overprivileged_entities = 0
        
        for result in analysis_results:
            if result.get('analysis_failed'):
                continue
            
            # Risk level
            risk_level = result.get('risk_level', 'UNKNOWN')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
            
            # Compliance status
            compliance_status = result.get('compliance_status', {})
            if compliance_status.get('compliant') is True:
                compliance_counts['COMPLIANT'] += 1
            elif compliance_status.get('compliant') is False:
                compliance_counts['NON_COMPLIANT'] += 1
            else:
                compliance_counts['PARTIALLY_COMPLIANT'] += 1
            
            # Findings
            findings = result.get('security_findings', [])
            total_findings += len(findings)
            critical_findings += len([f for f in findings if f.get('severity') == 'CRITICAL'])
            high_findings += len([f for f in findings if f.get('severity') == 'HIGH'])
            
            # Entity analysis
            metadata = result.get('metadata', {})
            entity_id = metadata.get('entity_id', '')
            
            if entity_id.startswith('role:'):
                entity_types['role'] += 1
            elif entity_id.startswith('user:'):
                entity_types['user'] += 1
            
            # Usage assessment
            usage_assessment = result.get('usage_assessment', {})
            if usage_assessment.get('utilization_score', 10) <= 3:
                unused_entities += 1
            if usage_assessment.get('overprovisioned', False):
                overprivileged_entities += 1
        
        # Calculate percentages
        compliance_percentage = (compliance_counts['COMPLIANT'] / max(successful_analyses, 1)) * 100
        high_risk_percentage = ((risk_counts['HIGH'] + risk_counts['CRITICAL']) / max(successful_analyses, 1)) * 100
        
        # Generate key insights
        insights = []
        
        if critical_findings > 0:
            insights.append(f"{critical_findings} critical security findings require immediate attention")
        
        if compliance_percentage < 80:
            insights.append(f"Compliance rate of {compliance_percentage:.1f}% is below recommended 80% threshold")
        
        if unused_entities > 0:
            insights.append(f"{unused_entities} entities appear unused and may be candidates for removal")
        
        if overprivileged_entities > 0:
            insights.append(f"{overprivileged_entities} entities have excessive permissions beyond their usage patterns")
        
        if high_risk_percentage > 20:
            insights.append(f"{high_risk_percentage:.1f}% of entities are high or critical risk")
        
        return {
            'analysis_date': datetime.now(timezone.utc).isoformat(),
            'account_id': self.account_id,
            'compliance_framework': self.compliance_framework,
            'summary_metrics': {
                'total_entities_analyzed': total_entities,
                'successful_analyses': successful_analyses,
                'analysis_success_rate': (successful_analyses / max(total_entities, 1)) * 100,
                'compliance_percentage': compliance_percentage,
                'high_risk_percentage': high_risk_percentage
            },
            'risk_distribution': risk_counts,
            'compliance_distribution': compliance_counts,
            'entity_breakdown': entity_types,
            'security_metrics': {
                'total_findings': total_findings,
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'unused_entities': unused_entities,
                'overprivileged_entities': overprivileged_entities
            },
            'key_insights': insights,
            'recommendations': self._generate_executive_recommendations(
                risk_counts, compliance_counts, critical_findings, unused_entities
            )
        }
    
    def _generate_executive_recommendations(self, risk_counts: Dict, compliance_counts: Dict, 
                                         critical_findings: int, unused_entities: int) -> List[str]:
        """Generate executive-level recommendations"""
        recommendations = []
        
        if critical_findings > 0:
            recommendations.append(
                f"Immediate Action Required: Address {critical_findings} critical security findings "
                "within 24-48 hours to maintain security posture"
            )
        
        if risk_counts['HIGH'] > 0:
            recommendations.append(
                f"High Priority: Review and remediate {risk_counts['HIGH']} high-risk entities "
                "within the next week"
            )
        
        if unused_entities > 0:
            recommendations.append(
                f"Cost Optimization: Consider removing or archiving {unused_entities} unused entities "
                "to reduce attack surface and management overhead"
            )
        
        if compliance_counts['NON_COMPLIANT'] > 0:
            recommendations.append(
                f"Compliance Gap: {compliance_counts['NON_COMPLIANT']} entities are non-compliant "
                f"with {self.compliance_framework} requirements and need remediation"
            )
        
        # General recommendations
        recommendations.extend([
            "Implement regular IAM access reviews as part of quarterly compliance processes",
            "Consider implementing automated policy validation in CI/CD pipelines",
            "Establish role-based access control (RBAC) patterns for consistent permissions",
            "Enable AWS CloudTrail and Access Analyzer for continuous monitoring"
        ])
        
        return recommendations
    
    def generate_compliance_report(self, analysis_results: List[Dict]) -> Dict:
        """Generate detailed compliance report"""
        
        control_mappings = {}
        violations = []
        evidence_items = []
        
        for result in analysis_results:
            if result.get('analysis_failed'):
                continue
            
            compliance_mapping = result.get('compliance_mapping', {})
            control_mappings_list = compliance_mapping.get('control_mappings', [])
            
            for mapping in control_mappings_list:
                control_id = mapping.get('control_id', 'UNKNOWN')
                
                if control_id not in control_mappings:
                    control_mappings[control_id] = {
                        'control_id': control_id,
                        'control_title': mapping.get('control_title', ''),
                        'total_entities': 0,
                        'compliant_entities': 0,
                        'non_compliant_entities': 0,
                        'partially_compliant_entities': 0,
                        'violations': [],
                        'evidence': []
                    }
                
                control_mappings[control_id]['total_entities'] += 1
                
                status = mapping.get('compliance_status', 'UNKNOWN')
                if status == 'COMPLIANT':
                    control_mappings[control_id]['compliant_entities'] += 1
                elif status == 'NON_COMPLIANT':
                    control_mappings[control_id]['non_compliant_entities'] += 1
                    violations.extend(mapping.get('gaps', []))
                else:
                    control_mappings[control_id]['partially_compliant_entities'] += 1
                
                control_mappings[control_id]['violations'].extend(mapping.get('gaps', []))
                control_mappings[control_id]['evidence'].append(mapping.get('evidence', ''))
        
        # Calculate overall compliance score
        total_controls = len(control_mappings)
        compliant_controls = len([c for c in control_mappings.values() 
                                if c['compliant_entities'] > c['non_compliant_entities']])
        
        compliance_score = (compliant_controls / max(total_controls, 1)) * 100
        
        return {
            'compliance_framework': self.compliance_framework,
            'assessment_date': datetime.now(timezone.utc).isoformat(),
            'overall_compliance_score': compliance_score,
            'total_controls_assessed': total_controls,
            'compliant_controls': compliant_controls,
            'control_details': list(control_mappings.values()),
            'critical_violations': list(set(violations)),  # Deduplicate
            'remediation_priorities': self._prioritize_remediation(control_mappings),
            'audit_evidence_summary': {
                'total_evidence_items': len(evidence_items),
                'documentation_gaps': self._identify_documentation_gaps(control_mappings),
                'technical_controls_status': self._assess_technical_controls(control_mappings)
            }
        }
    
    def _prioritize_remediation(self, control_mappings: Dict) -> List[Dict]:
        """Prioritize remediation actions based on control criticality"""
        priorities = []
        
        # Define critical controls for FedRAMP High
        critical_controls = {
            'AC-2': 'Account Management',
            'AC-6': 'Least Privilege',
            'AU-6': 'Audit Review',
            'CA-7': 'Continuous Monitoring',
            'SI-4': 'Information System Monitoring'
        }
        
        for control_id, control_data in control_mappings.items():
            if control_data['non_compliant_entities'] > 0:
                priority_level = 'HIGH' if control_id in critical_controls else 'MEDIUM'
                
                priorities.append({
                    'control_id': control_id,
                    'control_title': control_data['control_title'],
                    'priority': priority_level,
                    'non_compliant_entities': control_data['non_compliant_entities'],
                    'violations': control_data['violations'][:5],  # Top 5 violations
                    'estimated_effort': self._estimate_remediation_effort(control_data)
                })
        
        # Sort by priority and impact
        priorities.sort(key=lambda x: (
            0 if x['priority'] == 'HIGH' else 1,
            -x['non_compliant_entities']
        ))
        
        return priorities
    
    def _estimate_remediation_effort(self, control_data: Dict) -> str:
        """Estimate remediation effort for control"""
        non_compliant = control_data['non_compliant_entities']
        
        if non_compliant <= 5:
            return 'LOW (1-2 days)'
        elif non_compliant <= 20:
            return 'MEDIUM (1-2 weeks)'
        else:
            return 'HIGH (2-4 weeks)'
    
    def _identify_documentation_gaps(self, control_mappings: Dict) -> List[str]:
        """Identify documentation gaps for compliance"""
        gaps = []
        
        for control_id, control_data in control_mappings.items():
            if not any(control_data['evidence']):
                gaps.append(f"Missing documentation for {control_id}: {control_data['control_title']}")
        
        return gaps
    
    def _assess_technical_controls(self, control_mappings: Dict) -> Dict:
        """Assess technical control implementation status"""
        return {
            'implemented': len([c for c in control_mappings.values() if c['compliant_entities'] > 0]),
            'partially_implemented': len([c for c in control_mappings.values() if c['partially_compliant_entities'] > 0]),
            'not_implemented': len([c for c in control_mappings.values() if c['compliant_entities'] == 0])
        }
    
    def generate_trend_analysis(self, current_results: List[Dict]) -> Dict:
        """Generate trend analysis comparing with historical data"""
        try:
            # Query historical data from DynamoDB cache
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            
            # This is a simplified implementation - in practice, you'd query historical analysis results
            historical_data = self._get_historical_analysis_data(thirty_days_ago)
            
            current_summary = self.generate_executive_summary(current_results)
            
            trends = {
                'analysis_period': {
                    'start_date': thirty_days_ago.isoformat(),
                    'end_date': datetime.now(timezone.utc).isoformat()
                },
                'current_metrics': current_summary['summary_metrics'],
                'trends': {
                    'compliance_trend': self._calculate_compliance_trend(historical_data, current_summary),
                    'risk_trend': self._calculate_risk_trend(historical_data, current_summary),
                    'findings_trend': self._calculate_findings_trend(historical_data, current_summary)
                },
                'improvement_areas': self._identify_improvement_areas(historical_data, current_summary),
                'regression_areas': self._identify_regression_areas(historical_data, current_summary)
            }
            
            return trends
            
        except Exception as e:
            logger.warning(f"Failed to generate trend analysis: {e}")
            return {
                'error': 'Trend analysis unavailable',
                'message': 'Insufficient historical data or analysis error'
            }
    
    def _get_historical_analysis_data(self, since_date: datetime) -> List[Dict]:
        """Retrieve historical analysis data from cache"""
        # Simplified implementation - would query DynamoDB for historical results
        return []
    
    def _calculate_compliance_trend(self, historical_data: List[Dict], current_summary: Dict) -> Dict:
        """Calculate compliance trend over time"""
        return {
            'direction': 'stable',  # 'improving', 'declining', 'stable'
            'change_percentage': 0.0,
            'description': 'Insufficient historical data for trend analysis'
        }
    
    def _calculate_risk_trend(self, historical_data: List[Dict], current_summary: Dict) -> Dict:
        """Calculate risk trend over time"""
        return {
            'direction': 'stable',
            'change_percentage': 0.0,
            'description': 'Insufficient historical data for trend analysis'
        }
    
    def _calculate_findings_trend(self, historical_data: List[Dict], current_summary: Dict) -> Dict:
        """Calculate security findings trend over time"""
        return {
            'direction': 'stable',
            'change_percentage': 0.0,
            'description': 'Insufficient historical data for trend analysis'
        }
    
    def _identify_improvement_areas(self, historical_data: List[Dict], current_summary: Dict) -> List[str]:
        """Identify areas of improvement"""
        return ['Trend analysis requires more historical data']
    
    def _identify_regression_areas(self, historical_data: List[Dict], current_summary: Dict) -> List[str]:
        """Identify areas of regression"""
        return []
    
    def generate_html_report(self, executive_summary: Dict, compliance_report: Dict, 
                           trend_analysis: Dict) -> str:
        """Generate HTML report for executive viewing"""
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>AI-Powered IAM Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #1f2937; color: white; padding: 20px; text-align: center; }}
        .summary {{ background-color: #f3f4f6; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: white; border-radius: 5px; text-align: center; }}
        .critical {{ color: #dc2626; font-weight: bold; }}
        .high {{ color: #ea580c; font-weight: bold; }}
        .medium {{ color: #d97706; }}
        .low {{ color: #16a34a; }}
        .compliant {{ color: #16a34a; }}
        .non-compliant {{ color: #dc2626; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .recommendation {{ background-color: #fef3c7; padding: 10px; margin: 10px 0; border-left: 4px solid #f59e0b; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AI-Powered IAM Security Analysis Report</h1>
        <p>Account: {account_id} | Framework: {compliance_framework} | Date: {analysis_date}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="metric">
            <h3>{total_entities}</h3>
            <p>Total Entities</p>
        </div>
        <div class="metric">
            <h3 class="{compliance_class}">{compliance_percentage:.1f}%</h3>
            <p>Compliance Rate</p>
        </div>
        <div class="metric">
            <h3 class="{risk_class}">{high_risk_percentage:.1f}%</h3>
            <p>High Risk Entities</p>
        </div>
        <div class="metric">
            <h3 class="critical">{critical_findings}</h3>
            <p>Critical Findings</p>
        </div>
    </div>
    
    <div>
        <h2>Key Insights</h2>
        <ul>
        {insights_html}
        </ul>
    </div>
    
    <div>
        <h2>Risk Distribution</h2>
        <table>
            <tr><th>Risk Level</th><th>Count</th><th>Percentage</th></tr>
            {risk_table_rows}
        </table>
    </div>
    
    <div>
        <h2>Compliance Status</h2>
        <table>
            <tr><th>Status</th><th>Count</th><th>Percentage</th></tr>
            {compliance_table_rows}
        </table>
    </div>
    
    <div>
        <h2>Executive Recommendations</h2>
        {recommendations_html}
    </div>
    
    <div>
        <h2>Compliance Framework Details</h2>
        <p><strong>Framework:</strong> {compliance_framework}</p>
        <p><strong>Overall Score:</strong> <span class="{compliance_score_class}">{compliance_score:.1f}%</span></p>
        <p><strong>Controls Assessed:</strong> {total_controls}</p>
        <p><strong>Compliant Controls:</strong> {compliant_controls}</p>
    </div>
    
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666;">
        <p>This report was generated by AI-powered analysis using Amazon Bedrock. 
        For technical details and raw analysis data, please refer to the detailed JSON reports.</p>
    </div>
</body>
</html>
        """
        
        # Prepare template variables
        summary_metrics = executive_summary['summary_metrics']
        risk_distribution = executive_summary['risk_distribution']
        compliance_distribution = executive_summary['compliance_distribution']
        
        # Generate insights HTML
        insights_html = ''.join([f'<li>{insight}</li>' for insight in executive_summary['key_insights']])
        
        # Generate recommendations HTML
        recommendations_html = ''.join([
            f'<div class="recommendation">{rec}</div>' 
            for rec in executive_summary['recommendations']
        ])
        
        # Generate risk table rows
        total_entities = sum(risk_distribution.values())
        risk_table_rows = ''.join([
            f'<tr><td class="{level.lower()}">{level}</td><td>{count}</td><td>{(count/max(total_entities,1)*100):.1f}%</td></tr>'
            for level, count in risk_distribution.items()
        ])
        
        # Generate compliance table rows
        total_compliance = sum(compliance_distribution.values())
        compliance_table_rows = ''.join([
            f'<tr><td class="{status.lower().replace("_", "-")}">{status.replace("_", " ")}</td><td>{count}</td><td>{(count/max(total_compliance,1)*100):.1f}%</td></tr>'
            for status, count in compliance_distribution.items()
        ])
        
        # Determine CSS classes based on values
        compliance_class = 'compliant' if summary_metrics['compliance_percentage'] >= 80 else 'non-compliant'
        risk_class = 'critical' if summary_metrics['high_risk_percentage'] > 20 else 'medium'
        compliance_score_class = 'compliant' if compliance_report['overall_compliance_score'] >= 80 else 'non-compliant'
        
        return html_template.format(
            account_id=executive_summary['account_id'],
            compliance_framework=executive_summary['compliance_framework'],
            analysis_date=executive_summary['analysis_date'][:10],
            total_entities=summary_metrics['total_entities_analyzed'],
            compliance_percentage=summary_metrics['compliance_percentage'],
            high_risk_percentage=summary_metrics['high_risk_percentage'],
            critical_findings=executive_summary['security_metrics']['critical_findings'],
            compliance_class=compliance_class,
            risk_class=risk_class,
            insights_html=insights_html,
            risk_table_rows=risk_table_rows,
            compliance_table_rows=compliance_table_rows,
            recommendations_html=recommendations_html,
            compliance_score=compliance_report['overall_compliance_score'],
            total_controls=compliance_report['total_controls_assessed'],
            compliant_controls=compliance_report['compliant_controls'],
            compliance_score_class=compliance_score_class
        )
    
    def save_reports(self, executive_summary: Dict, compliance_report: Dict, 
                    trend_analysis: Dict, analysis_results: List[Dict]) -> Dict:
        """Save all reports to S3 in multiple formats"""
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        report_keys = {}
        
        try:
            # Save executive summary (JSON)
            exec_key = f"reports/executive/{timestamp}-executive-summary.json"
            self.s3.put_object(
                Bucket=self.reports_bucket,
                Key=exec_key,
                Body=json.dumps(executive_summary, default=str, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            report_keys['executive_summary'] = exec_key
            
            # Save compliance report (JSON)
            comp_key = f"reports/compliance/{timestamp}-compliance-report.json"
            self.s3.put_object(
                Bucket=self.reports_bucket,
                Key=comp_key,
                Body=json.dumps(compliance_report, default=str, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            report_keys['compliance_report'] = comp_key
            
            # Save trend analysis (JSON)
            trend_key = f"reports/trends/{timestamp}-trend-analysis.json"
            self.s3.put_object(
                Bucket=self.reports_bucket,
                Key=trend_key,
                Body=json.dumps(trend_analysis, default=str, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            report_keys['trend_analysis'] = trend_key
            
            # Save HTML report
            html_content = self.generate_html_report(executive_summary, compliance_report, trend_analysis)
            html_key = f"reports/html/{timestamp}-executive-report.html"
            self.s3.put_object(
                Bucket=self.reports_bucket,
                Key=html_key,
                Body=html_content,
                ContentType='text/html',
                ServerSideEncryption='AES256'
            )
            report_keys['html_report'] = html_key
            
            # Save detailed analysis results
            detailed_key = f"reports/detailed/{timestamp}-detailed-analysis.json"
            detailed_report = {
                'metadata': {
                    'report_timestamp': timestamp,
                    'account_id': self.account_id,
                    'compliance_framework': self.compliance_framework,
                    'total_entities': len(analysis_results)
                },
                'executive_summary': executive_summary,
                'compliance_report': compliance_report,
                'trend_analysis': trend_analysis,
                'detailed_results': analysis_results
            }
            
            self.s3.put_object(
                Bucket=self.reports_bucket,
                Key=detailed_key,
                Body=json.dumps(detailed_report, default=str, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            report_keys['detailed_report'] = detailed_key
            
            logger.info(f"Saved all reports to S3: {list(report_keys.keys())}")
            return report_keys
            
        except Exception as e:
            logger.error(f"Failed to save reports: {e}")
            raise

def lambda_handler(event, context):
    """Main Lambda handler for report generation"""
    
    logger.info(f"Starting report generation with event: {json.dumps(event, default=str)}")
    
    try:
        generator = AIIAMReportGenerator()
        
        # Get analysis results from S3 (triggered by S3 event)
        if 'Records' in event:
            # S3 event trigger
            s3_event = event['Records'][0]['s3']
            bucket = s3_event['bucket']['name']
            key = s3_event['object']['key']
            
            # Load analysis results
            response = generator.s3.get_object(Bucket=bucket, Key=key)
            analysis_data = json.loads(response['Body'].read())
            analysis_results = analysis_data.get('results', [])
            
        else:
            # Direct invocation with results
            analysis_results = event.get('analysis_results', [])
        
        if not analysis_results:
            logger.warning("No analysis results provided for report generation")
            return {
                'status': 'warning',
                'message': 'No analysis results to process',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        logger.info(f"Generating reports for {len(analysis_results)} analysis results")
        
        # Generate reports
        executive_summary = generator.generate_executive_summary(analysis_results)
        compliance_report = generator.generate_compliance_report(analysis_results)
        trend_analysis = generator.generate_trend_analysis(analysis_results)
        
        # Save reports to S3
        report_keys = generator.save_reports(
            executive_summary, compliance_report, trend_analysis, analysis_results
        )
        
        result = {
            'status': 'success',
            'reports_generated': len(report_keys),
            'report_keys': report_keys,
            'summary': {
                'total_entities': len(analysis_results),
                'compliance_score': compliance_report['overall_compliance_score'],
                'critical_findings': executive_summary['security_metrics']['critical_findings'],
                'high_risk_entities': executive_summary['risk_distribution']['HIGH'] + executive_summary['risk_distribution']['CRITICAL']
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Report generation completed: {json.dumps(result, default=str)}")
        return result
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        
        error_result = {
            'status': 'error',
            'error_message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return error_result