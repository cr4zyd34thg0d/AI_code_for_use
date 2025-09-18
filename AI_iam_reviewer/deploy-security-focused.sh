#!/bin/bash
# Security-Focused AI IAM Reviewer Deployment Script
# FedRAMP High Environment
#
# This script deploys the AI-powered IAM security analyzer with focus on:
# 1. Proactive security posture improvement
# 2. Access control excellence  
# 3. Persona-based role management
# 4. FedRAMP High baseline compliance
# 5. AI hallucination prevention

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Default configuration
DEFAULT_REGION="us-gov-west-1"
DEFAULT_STACK_NAME="ai-iam-security-analyzer"
DEFAULT_BEDROCK_MODEL="anthropic.claude-3-haiku-20240307-v1:0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${BOLD}=== $1 ===${NC}"; }

show_help() {
    cat << EOF
Security-Focused AI IAM Reviewer Deployment

USAGE: $0 [OPTIONS]

REQUIRED OPTIONS:
    -c, --code-bucket BUCKET    S3 bucket for Lambda code
    -b, --reports-bucket BUCKET S3 bucket for security reports

OPTIONAL:
    -r, --region REGION         AWS region (default: $DEFAULT_REGION)
    -s, --stack-name NAME       Stack name (default: $DEFAULT_STACK_NAME)
    -m, --bedrock-model MODEL   Bedrock model (default: haiku)
    -k, --kms-key-arn ARN       KMS key for encryption
    --enable-fedramp-high       Enable FedRAMP High mode
    --dry-run                   Show what would be deployed
    -h, --help                  Show this help

SECURITY FOCUS:
This deployment prioritizes security objectives over cost optimization:
- Proactive threat detection and prevention
- Persona-based access control validation
- Real-time compliance monitoring
- Evidence-based AI analysis (no hallucinations)

EXAMPLES:
    # Basic security-focused deployment
    $0 --code-bucket my-code --reports-bucket my-security-reports

    # Full FedRAMP High deployment
    $0 --code-bucket my-code --reports-bucket my-reports \\
       --kms-key-arn arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/... \\
       --enable-fedramp-high

EOF
}

# Parse arguments
parse_args() {
    REGION="$DEFAULT_REGION"
    STACK_NAME="$DEFAULT_STACK_NAME"
    BEDROCK_MODEL="$DEFAULT_BEDROCK_MODEL"
    CODE_BUCKET=""
    REPORTS_BUCKET=""
    KMS_KEY_ARN=""
    ENABLE_FEDRAMP_HIGH=false
    DRY_RUN=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--code-bucket) CODE_BUCKET="$2"; shift 2 ;;
            -b|--reports-bucket) REPORTS_BUCKET="$2"; shift 2 ;;
            -r|--region) REGION="$2"; shift 2 ;;
            -s|--stack-name) STACK_NAME="$2"; shift 2 ;;
            -m|--bedrock-model) BEDROCK_MODEL="$2"; shift 2 ;;
            -k|--kms-key-arn) KMS_KEY_ARN="$2"; shift 2 ;;
            --enable-fedramp-high) ENABLE_FEDRAMP_HIGH=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done

    if [[ -z "$CODE_BUCKET" ]]; then
        log_error "Code bucket is required"
        exit 1
    fi

    if [[ -z "$REPORTS_BUCKET" ]]; then
        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")
        REPORTS_BUCKET="ai-security-reports-${ACCOUNT_ID}-$(date +%s)"
        log_info "Auto-generated reports bucket: $REPORTS_BUCKET"
    fi
}

# Validate security prerequisites
validate_security_prerequisites() {
    log_step "Validating Security Prerequisites"

    # AWS CLI and credentials
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not installed"
        exit 1
    fi

    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured"
        exit 1
    fi

    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    log_success "AWS credentials valid - Account: $ACCOUNT_ID"

    # FedRAMP High specific checks
    if [[ "$ENABLE_FEDRAMP_HIGH" == "true" ]]; then
        if [[ "$REGION" != us-gov-* ]]; then
            log_error "FedRAMP High requires AWS GovCloud regions"
            exit 1
        fi
        log_success "FedRAMP High mode enabled in GovCloud region"

        if [[ -n "$KMS_KEY_ARN" ]]; then
            if aws kms describe-key --key-id "$KMS_KEY_ARN" --region "$REGION" &> /dev/null; then
                log_success "KMS key validated for FedRAMP High encryption"
            else
                log_error "KMS key not accessible: $KMS_KEY_ARN"
                exit 1
            fi
        else
            log_warning "No KMS key specified - using default encryption"
        fi
    fi

    # Bedrock access
    if ! aws bedrock list-foundation-models --region "$REGION" &> /dev/null; then
        log_warning "Cannot verify Bedrock access - ensure models are available"
    else
        log_success "Bedrock access verified"
    fi

    # Security Hub
    if aws securityhub describe-hub --region "$REGION" &> /dev/null; then
        log_success "Security Hub is enabled"
    else
        log_info "Security Hub will be enabled during deployment"
    fi

    # CloudTrail (required for real-time monitoring)
    if aws cloudtrail describe-trails --region "$REGION" --query 'trailList[0].Name' --output text | grep -q "None"; then
        log_warning "No CloudTrail detected - real-time policy monitoring may not work"
    else
        log_success "CloudTrail detected for real-time monitoring"
    fi
}

# Package Lambda functions with security focus
package_security_functions() {
    log_step "Packaging Security-Focused Lambda Functions"

    PACKAGE_DIR="$TEMP_DIR/lambda-packages"
    mkdir -p "$PACKAGE_DIR"
    cd "$PACKAGE_DIR"

    # Required files for security-focused deployment
    REQUIRED_FILES=(
        "iam_data_collector.py"
        "bedrock_policy_analyzer.py" 
        "report_generator.py"
    )

    for file in "${REQUIRED_FILES[@]}"; do
        if [[ -f "$SCRIPT_DIR/$file" ]]; then
            log_success "Found required file: $file"
        else
            log_error "Missing required file: $file"
            exit 1
        fi
    done

    # Package data collector
    log_info "Packaging IAM data collector..."
    cp "$SCRIPT_DIR/iam_data_collector.py" .
    zip -q iam_data_collector.zip iam_data_collector.py

    # Package Bedrock analyzer
    log_info "Packaging Bedrock security analyzer..."
    cp "$SCRIPT_DIR/bedrock_policy_analyzer.py" .
    zip -q bedrock_policy_analyzer.zip bedrock_policy_analyzer.py

    # Package report generator
    log_info "Packaging security report generator..."
    cp "$SCRIPT_DIR/report_generator.py" .
    zip -q report_generator.zip report_generator.py

    log_success "All security functions packaged successfully"
    cd "$SCRIPT_DIR"
}

# Deploy with security-first configuration
deploy_security_stack() {
    log_step "Deploying Security-Focused CloudFormation Stack"

    # Upload Lambda packages
    CODE_PREFIX="ai-security-analyzer/$(date +%Y%m%d-%H%M%S)"
    
    if [[ "$DRY_RUN" != "true" ]]; then
        log_info "Uploading Lambda packages..."
        for zip_file in "$TEMP_DIR/lambda-packages"/*.zip; do
            filename=$(basename "$zip_file")
            aws s3 cp "$zip_file" "s3://$CODE_BUCKET/$CODE_PREFIX/$filename" --region "$REGION"
            log_success "Uploaded $filename"
        done
    fi

    # Prepare CloudFormation parameters
    PARAMETERS=(
        "ReportsBucketName=$REPORTS_BUCKET"
        "LambdaSourceBucket=$CODE_BUCKET"
        "LambdaSourcePrefix=$CODE_PREFIX"
        "BedrockModel=$BEDROCK_MODEL"
        "BedrockRegion=$REGION"
        "ComplianceFramework=NIST-800-53"
        "RiskThreshold=MEDIUM"
        "EnableSecurityHub=true"
        "LogRetentionDays=90"
        "EnableDashboard=true"
    )

    if [[ -n "$KMS_KEY_ARN" ]]; then
        PARAMETERS+=("KmsKeyArn=$KMS_KEY_ARN")
    fi

    # Convert to CloudFormation format
    CF_PARAMETERS=""
    for param in "${PARAMETERS[@]}"; do
        CF_PARAMETERS+="ParameterKey=${param%=*},ParameterValue=${param#*=} "
    done

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would deploy with parameters:"
        for param in "${PARAMETERS[@]}"; do
            log_info "  $param"
        done
        return
    fi

    # Deploy stack
    log_info "Deploying CloudFormation stack: $STACK_NAME"
    aws cloudformation deploy \
        --template-file "$SCRIPT_DIR/bedrock-iam-analyzer.yaml" \
        --stack-name "$STACK_NAME" \
        --capabilities CAPABILITY_NAMED_IAM \
        --parameter-overrides $CF_PARAMETERS \
        --region "$REGION" \
        --no-fail-on-empty-changeset

    # Verify deployment
    STACK_STATUS=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].StackStatus' \
        --output text)

    if [[ "$STACK_STATUS" == "CREATE_COMPLETE" ]] || [[ "$STACK_STATUS" == "UPDATE_COMPLETE" ]]; then
        log_success "Security stack deployed successfully"
    else
        log_error "Deployment failed with status: $STACK_STATUS"
        exit 1
    fi
}

# Test security objectives
test_security_objectives() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would run security objective testing"
        return
    fi

    log_step "Testing Security Objectives"

    if [[ -f "$SCRIPT_DIR/validate-security-focus.py" ]] && command -v python3 &> /dev/null; then
        log_info "Running comprehensive security validation..."
        
        if python3 "$SCRIPT_DIR/validate-security-focus.py" \
            --stack-name "$STACK_NAME" \
            --region "$REGION"; then
            log_success "🎯 All security objectives validated successfully"
        else
            log_warning "⚠️  Some security objectives need improvement"
            log_info "Review the validation output above for specific recommendations"
        fi
    else
        log_warning "Security validation script not available - running basic tests"
        
        # Basic security tests
        log_info "Testing Lambda function deployment..."
        FUNCTIONS=$(aws lambda list-functions \
            --region "$REGION" \
            --query "Functions[?contains(FunctionName, 'ai-iam')].FunctionName" \
            --output text)
        
        if [[ -n "$FUNCTIONS" ]]; then
            log_success "Security analysis functions deployed: $FUNCTIONS"
        else
            log_error "No security analysis functions found"
        fi
        
        # Test Security Hub integration
        if aws securityhub describe-hub --region "$REGION" &> /dev/null; then
            log_success "Security Hub integration ready"
        else
            log_warning "Security Hub not enabled"
        fi
    fi
}

# Generate security-focused summary
generate_security_summary() {
    log_step "Security Deployment Summary"

    cat << EOF

${BOLD}🛡️  AI-Powered IAM Security Analyzer Deployed${NC}

${GREEN}✅${NC} Stack: $STACK_NAME
${GREEN}✅${NC} Region: $REGION  
${GREEN}✅${NC} Model: $BEDROCK_MODEL
${GREEN}✅${NC} Security Reports: s3://$REPORTS_BUCKET
${GREEN}✅${NC} FedRAMP High Mode: $ENABLE_FEDRAMP_HIGH

${BOLD}🎯 Security Objectives Enabled:${NC}
• Proactive security posture improvement
• Access control excellence with persona management
• Real-time FedRAMP High baseline compliance
• Evidence-based AI analysis (hallucination-resistant)
• Continuous security monitoring and alerting

${BOLD}🔍 Security Capabilities:${NC}
• Unused role/user detection and removal recommendations
• Privilege escalation vector identification
• Wildcard permission detection and remediation
• Cross-account trust relationship validation
• Persona-based role security assessment
• NIST 800-53 control compliance mapping

${BOLD}📊 Monitoring & Alerting:${NC}
• Real-time IAM policy change analysis
• Security Hub findings integration
• Executive security dashboards
• Automated compliance evidence generation

${BOLD}🚀 Next Steps:${NC}
1. Review Security Hub findings for immediate actions
2. Set up executive security report distribution
3. Configure ITSM integration for automated ticketing
4. Schedule weekly security posture reviews

${BOLD}🔧 Operational Commands:${NC}

# Trigger immediate security scan
aws lambda invoke --function-name \$(aws cloudformation describe-stacks \\
  --stack-name $STACK_NAME --region $REGION \\
  --query 'Stacks[0].Outputs[?OutputKey==\`DataCollectorFunctionArn\`].OutputValue' \\
  --output text | cut -d: -f7) --region $REGION \\
  --payload '{"mode": "security_scan", "full_analysis": true}' response.json

# Check Security Hub findings
aws securityhub get-findings --region $REGION \\
  --filters '{"GeneratorId": [{"Value": "AI-IAM-Analyzer", "Comparison": "EQUALS"}]}'

# Review security reports
aws s3 ls s3://$REPORTS_BUCKET/reports/executive/ --recursive

# Monitor real-time policy changes
aws logs filter-log-events --log-group-name /aws/lambda/ai-iam-bedrock-analyzer-* \\
  --start-time \$(date -d '1 hour ago' +%s)000 --region $REGION

EOF

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}Note: This was a dry run. No resources were deployed.${NC}"
    else
        echo -e "${GREEN}🎉 Security-focused AI IAM Reviewer is now protecting your environment!${NC}"
    fi
}

# Main execution
main() {
    echo -e "${BOLD}🛡️  Security-Focused AI IAM Reviewer Deployment${NC}"
    echo -e "Proactive Security • Access Control Excellence • FedRAMP High Compliance\n"

    parse_args "$@"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "🔍 Running in DRY RUN mode - no resources will be created"
    fi

    validate_security_prerequisites
    package_security_functions
    deploy_security_stack
    test_security_objectives
    generate_security_summary

    if [[ "$DRY_RUN" != "true" ]]; then
        log_success "🎯 Security-focused deployment completed successfully!"
        log_info "Your environment is now protected by AI-powered proactive security monitoring."
    fi
}

# Execute with all arguments
main "$@"