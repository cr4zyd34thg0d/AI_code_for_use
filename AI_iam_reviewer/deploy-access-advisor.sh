#!/bin/bash
# Deploy IAM Access Advisor Component Only
# Lightweight deployment for testing scheduled IAM role analysis

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Script configuration
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
Deploy IAM Access Advisor Component

USAGE: $0 [OPTIONS]

OPTIONS:
    -r, --region REGION         AWS region (will prompt if not provided)
    -s, --stack-name NAME       CloudFormation stack name (default: iam-access-advisor)
    -b, --bucket-name BUCKET    S3 bucket for reports (will prompt if not provided)
    -u, --unused-days DAYS      Days threshold for unused roles (default: 90)
    --schedule EXPRESSION       EventBridge schedule (default: rate(7 days))
    --enable-security-hub       Enable Security Hub integration
    --kms-key-arn ARN          Optional KMS key for encryption
    --dry-run                   Show what would be deployed
    -h, --help                  Show this help

EXAMPLES:
    # Interactive deployment (will prompt for required values)
    $0

    # Specify all parameters
    $0 --region us-east-1 --bucket-name my-iam-reports --enable-security-hub

    # Test in different region with custom schedule
    $0 --region eu-west-1 --bucket-name eu-iam-reports --schedule "rate(3 days)"

EOF
}

# Parse arguments with interactive prompts
parse_args() {
    REGION=""
    STACK_NAME="iam-access-advisor"
    BUCKET_NAME=""
    UNUSED_DAYS="90"
    SCHEDULE_EXPRESSION="rate(7 days)"
    ENABLE_SECURITY_HUB=false
    KMS_KEY_ARN=""
    DRY_RUN=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region) REGION="$2"; shift 2 ;;
            -s|--stack-name) STACK_NAME="$2"; shift 2 ;;
            -b|--bucket-name) BUCKET_NAME="$2"; shift 2 ;;
            -u|--unused-days) UNUSED_DAYS="$2"; shift 2 ;;
            --schedule) SCHEDULE_EXPRESSION="$2"; shift 2 ;;
            --enable-security-hub) ENABLE_SECURITY_HUB=true; shift ;;
            --kms-key-arn) KMS_KEY_ARN="$2"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done

    # Interactive prompts for missing required parameters
    if [[ -z "$REGION" ]]; then
        echo -e "${BOLD}Available AWS Regions:${NC}"
        echo "  us-east-1      (N. Virginia)"
        echo "  us-west-2      (Oregon)"
        echo "  eu-west-1      (Ireland)"
        echo "  us-gov-west-1  (GovCloud West)"
        echo "  us-gov-east-1  (GovCloud East)"
        echo ""
        read -p "Enter AWS region: " REGION
        
        if [[ -z "$REGION" ]]; then
            log_error "Region is required"
            exit 1
        fi
    fi

    if [[ -z "$BUCKET_NAME" ]]; then
        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")
        DEFAULT_BUCKET="iam-access-advisor-${ACCOUNT_ID}-$(date +%s)"
        
        echo -e "${BOLD}S3 Bucket for Reports:${NC}"
        echo "This bucket will store CSV reports of IAM role usage analysis."
        echo ""
        read -p "Enter S3 bucket name (or press Enter for: $DEFAULT_BUCKET): " BUCKET_INPUT
        
        BUCKET_NAME="${BUCKET_INPUT:-$DEFAULT_BUCKET}"
    fi

    # Ask about Security Hub if not specified
    if [[ "$ENABLE_SECURITY_HUB" == "false" ]]; then
        echo -e "${BOLD}Security Hub Integration:${NC}"
        echo "Security Hub will receive findings about unused IAM roles."
        echo ""
        read -p "Enable Security Hub integration? (y/N): " SECURITY_HUB_INPUT
        
        if [[ "$SECURITY_HUB_INPUT" =~ ^[Yy]$ ]]; then
            ENABLE_SECURITY_HUB=true
        fi
    fi

    log_info "Configuration:"
    log_info "  Region: $REGION"
    log_info "  Stack: $STACK_NAME"
    log_info "  Bucket: $BUCKET_NAME"
    log_info "  Unused threshold: $UNUSED_DAYS days"
    log_info "  Schedule: $SCHEDULE_EXPRESSION"
    log_info "  Security Hub: $ENABLE_SECURITY_HUB"
    
    if [[ -n "$KMS_KEY_ARN" ]]; then
        log_info "  KMS Key: $KMS_KEY_ARN"
    fi
}

# Validate prerequisites
validate_prerequisites() {
    log_step "Validating Prerequisites"

    # AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed"
        exit 1
    fi

    # AWS credentials
    if ! aws sts get-caller-identity --region "$REGION" &> /dev/null; then
        log_error "AWS credentials not configured or invalid for region $REGION"
        exit 1
    fi

    ACCOUNT_ID=$(aws sts get-caller-identity --region "$REGION" --query Account --output text)
    log_success "AWS credentials valid - Account: $ACCOUNT_ID, Region: $REGION"

    # Check if Security Hub is available in region
    if [[ "$ENABLE_SECURITY_HUB" == "true" ]]; then
        if aws securityhub describe-hub --region "$REGION" &> /dev/null; then
            log_success "Security Hub is already enabled"
        else
            log_info "Security Hub will be enabled during deployment"
        fi
    fi

    # Validate KMS key if provided
    if [[ -n "$KMS_KEY_ARN" ]]; then
        if aws kms describe-key --key-id "$KMS_KEY_ARN" --region "$REGION" &> /dev/null; then
            log_success "KMS key is valid and accessible"
        else
            log_error "KMS key $KMS_KEY_ARN is not accessible"
            exit 1
        fi
    fi
}

# Create CloudFormation template
create_template() {
    log_step "Creating CloudFormation Template"

    cat > "$TEMP_DIR/access-advisor-template.yaml" << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: >
  IAM Access Advisor Component - Scheduled analysis of IAM role usage using 
  free Access Advisor API. Generates CSV reports and Security Hub findings.

Parameters:
  ReportsBucketName:
    Type: String
    Description: S3 bucket name for CSV reports (will be created)
    
  UnusedDays:
    Type: Number
    Default: 90
    MinValue: 1
    Description: Number of days without access to flag a role as unused
    
  OutputPrefix:
    Type: String
    Default: iam/usage/
    Description: S3 key prefix for CSV outputs
    
  ScheduleExpression:
    Type: String
    Default: rate(7 days)
    Description: EventBridge schedule for the analysis
    
  EnableSecurityHub:
    Type: String
    Default: "false"
    AllowedValues: ["true", "false"]
    Description: Enable Security Hub integration
    
  LogRetentionDays:
    Type: Number
    Default: 90
    AllowedValues: [1,3,5,7,14,30,60,90,120,150,180,365,400,545,731,1096,1827,2192,2557,2922,3288,3653]
    Description: CloudWatch Logs retention (days)
    
  KmsKeyArn:
    Type: String
    Default: ""
    Description: Optional CMK ARN for S3 encryption

Conditions:
  UseKmsEncryption: !Not [!Equals [!Ref KmsKeyArn, ""]]
  EnableSecurityHubIntegration: !Equals [!Ref EnableSecurityHub, "true"]

Resources:
  # S3 Bucket for Reports
  ReportsBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref ReportsBucketName
      VersioningConfiguration:
        Status: Enabled
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - !If
            - UseKmsEncryption
            - ServerSideEncryptionByDefault:
                SSEAlgorithm: aws:kms
                KMSMasterKeyID: !Ref KmsKeyArn
            - ServerSideEncryptionByDefault:
                SSEAlgorithm: AES256

  # S3 Bucket Policy
  ReportsBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref ReportsBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: EnforceTLS
            Effect: Deny
            Principal: "*"
            Action: s3:*
            Resource:
              - !Sub arn:${AWS::Partition}:s3:::${ReportsBucket}
              - !Sub arn:${AWS::Partition}:s3:::${ReportsBucket}/*
            Condition:
              Bool:
                aws:SecureTransport: false

  # IAM Role for Lambda
  AccessAdvisorRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub iam-access-advisor-${AWS::StackName}
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - !Sub arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: AccessAdvisorPermissions
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - iam:ListRoles
                  - iam:GenerateServiceLastAccessedDetails
                  - iam:GetServiceLastAccessedDetails
                  - sts:GetCallerIdentity
                Resource: "*"
              - Effect: Allow
                Action: s3:PutObject
                Resource: !Sub arn:${AWS::Partition}:s3:::${ReportsBucket}/*
              - !If
                - EnableSecurityHubIntegration
                - Effect: Allow
                  Action: securityhub:BatchImportFindings
                  Resource: "*"
                - !Ref AWS::NoValue

  # CloudWatch Log Group
  AccessAdvisorLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/iam-access-advisor-${AWS::StackName}
      RetentionInDays: !Ref LogRetentionDays

  # Lambda Function
  AccessAdvisorFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub iam-access-advisor-${AWS::StackName}
      Runtime: python3.11
      Handler: scheduled_access_advisor.lambda_handler
      Role: !GetAtt AccessAdvisorRole.Arn
      Timeout: 900
      MemorySize: 512
      Code:
        ZipFile: |
          # Placeholder - will be replaced with actual code
          def lambda_handler(event, context):
              return {"statusCode": 200, "body": "Placeholder"}
      Environment:
        Variables:
          OUTPUT_BUCKET: !Ref ReportsBucketName
          OUTPUT_PREFIX: !Ref OutputPrefix
          UNUSED_DAYS: !Ref UnusedDays
          ENABLE_SECURITY_HUB: !Ref EnableSecurityHub

  # EventBridge Rule
  ScheduledRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub iam-access-advisor-schedule-${AWS::StackName}
      ScheduleExpression: !Ref ScheduleExpression
      State: ENABLED
      Targets:
        - Arn: !GetAtt AccessAdvisorFunction.Arn
          Id: AccessAdvisorTarget

  # Lambda Permission for EventBridge
  AccessAdvisorEventPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref AccessAdvisorFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt ScheduledRule.Arn

  # Security Hub (Optional)
  SecurityHub:
    Type: AWS::SecurityHub::Hub
    Condition: EnableSecurityHubIntegration
    Properties: {}

Outputs:
  ReportsBucket:
    Description: S3 bucket for IAM usage reports
    Value: !Ref ReportsBucketName
    Export:
      Name: !Sub ${AWS::StackName}-ReportsBucket
      
  AccessAdvisorFunctionArn:
    Description: ARN of the Access Advisor Lambda function
    Value: !GetAtt AccessAdvisorFunction.Arn
    Export:
      Name: !Sub ${AWS::StackName}-FunctionArn
      
  ScheduleExpression:
    Description: EventBridge schedule expression
    Value: !Ref ScheduleExpression
EOF

    log_success "CloudFormation template created"
}

# Deploy the stack
deploy_stack() {
    log_step "Deploying Access Advisor Stack"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would deploy with parameters:"
        log_info "  ReportsBucketName=$BUCKET_NAME"
        log_info "  UnusedDays=$UNUSED_DAYS"
        log_info "  ScheduleExpression=$SCHEDULE_EXPRESSION"
        log_info "  EnableSecurityHub=$ENABLE_SECURITY_HUB"
        return
    fi

    # Prepare parameters
    PARAMETERS=(
        "ReportsBucketName=$BUCKET_NAME"
        "UnusedDays=$UNUSED_DAYS"
        "OutputPrefix=iam/usage/"
        "ScheduleExpression=$SCHEDULE_EXPRESSION"
        "EnableSecurityHub=$ENABLE_SECURITY_HUB"
        "LogRetentionDays=90"
    )

    if [[ -n "$KMS_KEY_ARN" ]]; then
        PARAMETERS+=("KmsKeyArn=$KMS_KEY_ARN")
    fi

    # Convert to CloudFormation format
    CF_PARAMETERS=""
    for param in "${PARAMETERS[@]}"; do
        CF_PARAMETERS+="ParameterKey=${param%=*},ParameterValue=${param#*=} "
    done

    # Deploy stack
    log_info "Deploying CloudFormation stack: $STACK_NAME"
    
    aws cloudformation deploy \
        --template-file "$TEMP_DIR/access-advisor-template.yaml" \
        --stack-name "$STACK_NAME" \
        --capabilities CAPABILITY_NAMED_IAM \
        --parameter-overrides $CF_PARAMETERS \
        --region "$REGION" \
        --no-fail-on-empty-changeset

    # Check deployment status
    STACK_STATUS=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].StackStatus' \
        --output text)

    if [[ "$STACK_STATUS" == "CREATE_COMPLETE" ]] || [[ "$STACK_STATUS" == "UPDATE_COMPLETE" ]]; then
        log_success "Stack deployed successfully"
    else
        log_error "Deployment failed with status: $STACK_STATUS"
        exit 1
    fi
}

# Update Lambda function code
update_lambda_code() {
    log_step "Updating Lambda Function Code"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would update Lambda function code"
        return
    fi

    # Check if the Python file exists
    if [[ ! -f "$SCRIPT_DIR/scheduled_access_advisor.py" ]]; then
        log_error "scheduled_access_advisor.py not found in $SCRIPT_DIR"
        exit 1
    fi

    # Create ZIP file
    cd "$SCRIPT_DIR"
    zip -q "$TEMP_DIR/function.zip" scheduled_access_advisor.py
    
    # Update function code
    FUNCTION_NAME="iam-access-advisor-${STACK_NAME}"
    
    log_info "Updating Lambda function code..."
    aws lambda update-function-code \
        --function-name "$FUNCTION_NAME" \
        --zip-file "fileb://$TEMP_DIR/function.zip" \
        --region "$REGION" > /dev/null

    log_success "Lambda function code updated"
}

# Test the deployment
test_deployment() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would test deployment"
        return
    fi

    log_step "Testing Deployment"

    FUNCTION_NAME="iam-access-advisor-${STACK_NAME}"
    
    log_info "Testing Lambda function..."
    
    # Invoke function with test payload
    RESULT=$(aws lambda invoke \
        --function-name "$FUNCTION_NAME" \
        --region "$REGION" \
        --payload '{"test": true}' \
        "$TEMP_DIR/test-response.json" \
        --query 'StatusCode' \
        --output text)

    if [[ "$RESULT" == "200" ]]; then
        RESPONSE=$(cat "$TEMP_DIR/test-response.json")
        log_success "Function executed successfully"
        log_info "Response: $RESPONSE"
        
        # Check for CSV report
        sleep 5
        log_info "Checking for CSV reports in S3..."
        
        REPORTS=$(aws s3 ls "s3://$BUCKET_NAME/iam/usage/" --region "$REGION" 2>/dev/null || true)
        if [[ -n "$REPORTS" ]]; then
            log_success "CSV reports found:"
            echo "$REPORTS"
        else
            log_info "No CSV reports yet (this is normal for the first run)"
        fi
    else
        log_error "Function test failed with status: $RESULT"
        cat "$TEMP_DIR/test-response.json"
    fi
}

# Generate summary
generate_summary() {
    log_step "Deployment Summary"

    cat << EOF

${BOLD}🎯 IAM Access Advisor Component Deployed${NC}

${GREEN}✅${NC} Stack: $STACK_NAME
${GREEN}✅${NC} Region: $REGION
${GREEN}✅${NC} Reports Bucket: s3://$BUCKET_NAME
${GREEN}✅${NC} Schedule: $SCHEDULE_EXPRESSION
${GREEN}✅${NC} Unused Threshold: $UNUSED_DAYS days
${GREEN}✅${NC} Security Hub: $ENABLE_SECURITY_HUB

${BOLD}📊 What This Component Does:${NC}
• Analyzes IAM roles weekly using free Access Advisor API
• Generates CSV reports of role usage patterns
• Identifies unused roles (no activity for $UNUSED_DAYS+ days)
• Creates Security Hub findings for compliance tracking

${BOLD}🔧 Operational Commands:${NC}

# Manual function execution
aws lambda invoke --function-name iam-access-advisor-$STACK_NAME \\
  --region $REGION --payload '{}' response.json

# Check latest reports
aws s3 ls s3://$BUCKET_NAME/iam/usage/ --recursive --region $REGION

# View Security Hub findings (if enabled)
aws securityhub get-findings --region $REGION \\
  --filters '{"GeneratorId": [{"Value": "AccessAdvisorSweep", "Comparison": "EQUALS"}]}'

# Monitor function logs
aws logs tail /aws/lambda/iam-access-advisor-$STACK_NAME --follow --region $REGION

${BOLD}💰 Cost Estimate:${NC}
• Lambda: ~\$0.50/month (weekly execution)
• S3: ~\$0.10/month (CSV storage)
• CloudWatch Logs: ~\$0.25/month
• Total: ~\$0.85/month

${BOLD}🔄 Next Steps:${NC}
1. Monitor the first few executions to ensure proper operation
2. Review CSV reports for unused role identification
3. Consider deploying the Policy Guardrail component for real-time monitoring
4. Set up alerts for critical Security Hub findings

EOF

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}Note: This was a dry run. No resources were deployed.${NC}"
    fi
}

# Main execution
main() {
    echo -e "${BOLD}🔍 IAM Access Advisor Component Deployment${NC}"
    echo -e "Scheduled IAM role usage analysis with cost-effective monitoring\n"

    parse_args "$@"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "🔍 Running in DRY RUN mode - no resources will be created"
    fi

    validate_prerequisites
    create_template
    deploy_stack
    update_lambda_code
    test_deployment
    generate_summary

    if [[ "$DRY_RUN" != "true" ]]; then
        log_success "🎉 Access Advisor component deployed successfully!"
    fi
}

# Execute with all arguments
main "$@"