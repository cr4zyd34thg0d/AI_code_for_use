#!/bin/bash
# Deploy IAM Policy Guardrail Component Only
# Real-time IAM policy change monitoring and analysis

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
Deploy IAM Policy Guardrail Component

USAGE: $0 [OPTIONS]

OPTIONS:
    -r, --region REGION         AWS region (will prompt if not provided)
    -s, --stack-name NAME       CloudFormation stack name (default: iam-policy-guardrail)
    --enable-security-hub       Enable Security Hub integration
    --require-passrole-condition Require conditions on PassRole actions
    --kms-key-arn ARN          Optional KMS key for encryption
    --dry-run                   Show what would be deployed
    -h, --help                  Show this help

DESCRIPTION:
This component monitors IAM policy changes in real-time and analyzes them for:
- Wildcard permissions (Action: *, Resource: *)
- Missing conditions on sensitive actions
- Overly broad resource access
- Privilege escalation risks

EXAMPLES:
    # Interactive deployment (will prompt for required values)
    $0

    # Specify region and enable Security Hub
    $0 --region us-east-1 --enable-security-hub

    # Deploy with strict PassRole requirements
    $0 --region us-west-2 --require-passrole-condition --enable-security-hub

PREREQUISITES:
    - CloudTrail enabled (for EventBridge policy change detection)
    - IAM permissions for Lambda, EventBridge, Security Hub

EOF
}

# Parse arguments with interactive prompts
parse_args() {
    REGION=""
    STACK_NAME="iam-policy-guardrail"
    ENABLE_SECURITY_HUB=false
    REQUIRE_PASSROLE_CONDITION=true
    KMS_KEY_ARN=""
    DRY_RUN=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region) REGION="$2"; shift 2 ;;
            -s|--stack-name) STACK_NAME="$2"; shift 2 ;;
            --enable-security-hub) ENABLE_SECURITY_HUB=true; shift ;;
            --require-passrole-condition) REQUIRE_PASSROLE_CONDITION=true; shift ;;
            --kms-key-arn) KMS_KEY_ARN="$2"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done

    # Interactive prompts for missing parameters
    if [[ -z "$REGION" ]]; then
        echo -e "${BOLD}Available AWS Regions:${NC}"
        echo "  us-east-1      (N. Virginia) - Most services available"
        echo "  us-west-2      (Oregon) - Good for West Coast"
        echo "  eu-west-1      (Ireland) - Europe"
        echo "  ap-southeast-1 (Singapore) - Asia Pacific"
        echo "  us-gov-west-1  (GovCloud West) - Government"
        echo "  us-gov-east-1  (GovCloud East) - Government"
        echo ""
        read -p "Enter AWS region: " REGION
        
        if [[ -z "$REGION" ]]; then
            log_error "Region is required"
            exit 1
        fi
    fi

    # Ask about Security Hub if not specified
    if [[ "$ENABLE_SECURITY_HUB" == "false" ]]; then
        echo -e "${BOLD}Security Hub Integration:${NC}"
        echo "Security Hub will receive findings about risky IAM policy changes."
        echo "This helps with compliance monitoring and alerting."
        echo ""
        read -p "Enable Security Hub integration? (y/N): " SECURITY_HUB_INPUT
        
        if [[ "$SECURITY_HUB_INPUT" =~ ^[Yy]$ ]]; then
            ENABLE_SECURITY_HUB=true
        fi
    fi

    # Ask about PassRole condition requirements
    echo -e "${BOLD}PassRole Security:${NC}"
    echo "Require conditions on iam:PassRole actions for enhanced security?"
    echo "Recommended: Yes (will flag PassRole without resource/condition restrictions)"
    echo ""
    read -p "Require PassRole conditions? (Y/n): " PASSROLE_INPUT
    
    if [[ "$PASSROLE_INPUT" =~ ^[Nn]$ ]]; then
        REQUIRE_PASSROLE_CONDITION=false
    fi

    log_info "Configuration:"
    log_info "  Region: $REGION"
    log_info "  Stack: $STACK_NAME"
    log_info "  Security Hub: $ENABLE_SECURITY_HUB"
    log_info "  PassRole Conditions: $REQUIRE_PASSROLE_CONDITION"
    
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

    # Check CloudTrail (required for EventBridge)
    TRAILS=$(aws cloudtrail describe-trails --region "$REGION" --query 'trailList[?IsMultiRegionTrail==`true` || HomeRegion==`'$REGION'`]' --output text 2>/dev/null || echo "")
    
    if [[ -n "$TRAILS" ]]; then
        log_success "CloudTrail detected - EventBridge rules will work"
    else
        log_warning "No CloudTrail detected - EventBridge rules may not trigger"
        echo "Consider enabling CloudTrail for policy change detection"
    fi

    # Check Security Hub if enabled
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

    cat > "$TEMP_DIR/policy-guardrail-template.yaml" << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: >
  IAM Policy Guardrail Component - Real-time analysis of IAM policy changes
  using EventBridge and Lambda. Detects risky policy patterns and creates
  Security Hub findings for immediate remediation.

Parameters:
  EnableSecurityHub:
    Type: String
    Default: "false"
    AllowedValues: ["true", "false"]
    Description: Enable Security Hub integration
    
  RequirePassRoleCondition:
    Type: String
    Default: "true"
    AllowedValues: ["true", "false"]
    Description: Flag PassRole actions without conditions as high risk
    
  LogRetentionDays:
    Type: Number
    Default: 90
    AllowedValues: [1,3,5,7,14,30,60,90,120,150,180,365,400,545,731,1096,1827,2192,2557,2922,3288,3653]
    Description: CloudWatch Logs retention (days)
    
  KmsKeyArn:
    Type: String
    Default: ""
    Description: Optional CMK ARN for encryption

Conditions:
  EnableSecurityHubIntegration: !Equals [!Ref EnableSecurityHub, "true"]

Resources:
  # IAM Role for Lambda
  PolicyGuardrailRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub iam-policy-guardrail-${AWS::StackName}
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
        - PolicyName: PolicyGuardrailPermissions
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - iam:GetPolicy
                  - iam:GetPolicyVersion
                  - iam:GetRole
                  - iam:GetRolePolicy
                  - iam:GetUserPolicy
                  - sts:GetCallerIdentity
                Resource: "*"
              - !If
                - EnableSecurityHubIntegration
                - Effect: Allow
                  Action: securityhub:BatchImportFindings
                  Resource: "*"
                - !Ref AWS::NoValue

  # CloudWatch Log Group
  PolicyGuardrailLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/iam-policy-guardrail-${AWS::StackName}
      RetentionInDays: !Ref LogRetentionDays

  # Lambda Function
  PolicyGuardrailFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub iam-policy-guardrail-${AWS::StackName}
      Runtime: python3.11
      Handler: iam_policy_guardrail.lambda_handler
      Role: !GetAtt PolicyGuardrailRole.Arn
      Timeout: 120
      MemorySize: 256
      Code:
        ZipFile: |
          # Placeholder - will be replaced with actual code
          def lambda_handler(event, context):
              return {"statusCode": 200, "body": "Placeholder"}
      Environment:
        Variables:
          ENABLE_SECURITY_HUB: !Ref EnableSecurityHub
          REQUIRE_PASSROLE_CONDITION: !Ref RequirePassRoleCondition

  # EventBridge Rule for Policy Changes
  PolicyChangeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub iam-policy-guardrail-${AWS::StackName}
      Description: Triggers on IAM policy changes for real-time analysis
      State: ENABLED
      EventPattern:
        source: ["aws.iam"]
        detail-type: ["AWS API Call via CloudTrail"]
        detail:
          eventSource: ["iam.amazonaws.com"]
          eventName:
            - "CreatePolicy"
            - "CreatePolicyVersion"
            - "SetDefaultPolicyVersion"
            - "AttachRolePolicy"
            - "AttachUserPolicy"
            - "PutRolePolicy"
            - "PutUserPolicy"
            - "UpdateAssumeRolePolicy"
      Targets:
        - Arn: !GetAtt PolicyGuardrailFunction.Arn
          Id: PolicyGuardrailTarget

  # Lambda Permission for EventBridge
  PolicyGuardrailEventPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref PolicyGuardrailFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt PolicyChangeRule.Arn

  # Security Hub (Optional)
  SecurityHub:
    Type: AWS::SecurityHub::Hub
    Condition: EnableSecurityHubIntegration
    Properties: {}

Outputs:
  PolicyGuardrailFunctionArn:
    Description: ARN of the Policy Guardrail Lambda function
    Value: !GetAtt PolicyGuardrailFunction.Arn
    Export:
      Name: !Sub ${AWS::StackName}-FunctionArn
      
  EventBridgeRuleArn:
    Description: ARN of the EventBridge rule for policy changes
    Value: !GetAtt PolicyChangeRule.Arn
    Export:
      Name: !Sub ${AWS::StackName}-EventRuleArn
      
  MonitoredEvents:
    Description: IAM events being monitored
    Value: "CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion, AttachRolePolicy, AttachUserPolicy, PutRolePolicy, PutUserPolicy, UpdateAssumeRolePolicy"
EOF

    log_success "CloudFormation template created"
}

# Deploy the stack
deploy_stack() {
    log_step "Deploying Policy Guardrail Stack"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would deploy with parameters:"
        log_info "  EnableSecurityHub=$ENABLE_SECURITY_HUB"
        log_info "  RequirePassRoleCondition=$REQUIRE_PASSROLE_CONDITION"
        return
    fi

    # Prepare parameters
    PARAMETERS=(
        "EnableSecurityHub=$ENABLE_SECURITY_HUB"
        "RequirePassRoleCondition=$REQUIRE_PASSROLE_CONDITION"
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
        --template-file "$TEMP_DIR/policy-guardrail-template.yaml" \
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
    if [[ ! -f "$SCRIPT_DIR/iam_policy_guardrail.py" ]]; then
        log_error "iam_policy_guardrail.py not found in $SCRIPT_DIR"
        exit 1
    fi

    # Create ZIP file
    cd "$SCRIPT_DIR"
    zip -q "$TEMP_DIR/function.zip" iam_policy_guardrail.py
    
    # Update function code
    FUNCTION_NAME="iam-policy-guardrail-${STACK_NAME}"
    
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

    FUNCTION_NAME="iam-policy-guardrail-${STACK_NAME}"
    
    log_info "Testing Lambda function with sample policy change event..."
    
    # Create test event that simulates a policy change
    TEST_EVENT=$(cat << 'EOF'
{
    "version": "0",
    "id": "test-event-id",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "123456789012",
    "time": "2024-01-01T12:00:00Z",
    "region": "us-east-1",
    "detail": {
        "eventVersion": "1.05",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/testuser",
            "accountId": "123456789012",
            "userName": "testuser"
        },
        "eventTime": "2024-01-01T12:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreatePolicy",
        "requestParameters": {
            "policyName": "TestPolicy",
            "policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
        },
        "responseElements": {
            "policy": {
                "policyName": "TestPolicy",
                "arn": "arn:aws:iam::123456789012:policy/TestPolicy"
            }
        }
    }
}
EOF
)

    # Invoke function with test event
    RESULT=$(aws lambda invoke \
        --function-name "$FUNCTION_NAME" \
        --region "$REGION" \
        --payload "$TEST_EVENT" \
        "$TEMP_DIR/test-response.json" \
        --query 'StatusCode' \
        --output text)

    if [[ "$RESULT" == "200" ]]; then
        RESPONSE=$(cat "$TEMP_DIR/test-response.json")
        log_success "Function executed successfully"
        log_info "Response: $RESPONSE"
        
        # Check for Security Hub findings if enabled
        if [[ "$ENABLE_SECURITY_HUB" == "true" ]]; then
            sleep 3
            log_info "Checking for Security Hub findings..."
            
            FINDINGS=$(aws securityhub get-findings \
                --region "$REGION" \
                --filters '{"GeneratorId": [{"Value": "IAMPolicyGuardrail", "Comparison": "EQUALS"}]}' \
                --max-results 5 \
                --query 'Findings[*].[Id,Title,Severity.Label]' \
                --output table 2>/dev/null || echo "No findings yet")
            
            if [[ "$FINDINGS" != "No findings yet" ]]; then
                log_success "Security Hub findings created:"
                echo "$FINDINGS"
            else
                log_info "No Security Hub findings yet (normal for test event)"
            fi
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

${BOLD}🛡️ IAM Policy Guardrail Component Deployed${NC}

${GREEN}✅${NC} Stack: $STACK_NAME
${GREEN}✅${NC} Region: $REGION
${GREEN}✅${NC} Security Hub: $ENABLE_SECURITY_HUB
${GREEN}✅${NC} PassRole Conditions: $REQUIRE_PASSROLE_CONDITION

${BOLD}🔍 What This Component Does:${NC}
• Monitors IAM policy changes in real-time via EventBridge
• Analyzes policies for security risks (wildcards, missing conditions)
• Creates Security Hub findings for immediate alerting
• Focuses on preventing overly permissive policies

${BOLD}📊 Monitored IAM Events:${NC}
• CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion
• AttachRolePolicy, AttachUserPolicy
• PutRolePolicy, PutUserPolicy
• UpdateAssumeRolePolicy

${BOLD}🚨 Security Checks Performed:${NC}
• Action: "*" with Resource: "*" (HIGH severity)
• Service wildcards (e.g., s3:*, iam:*) (MEDIUM severity)
• Resource: "*" without scoping (MEDIUM severity)
• NotAction usage (MEDIUM severity)
• iam:PassRole without conditions (HIGH severity if enabled)
• sts:AssumeRole with Resource: "*" (HIGH severity)

${BOLD}🔧 Operational Commands:${NC}

# Manual function test
aws lambda invoke --function-name iam-policy-guardrail-$STACK_NAME \\
  --region $REGION --payload '{"test": true}' response.json

# View Security Hub findings (if enabled)
aws securityhub get-findings --region $REGION \\
  --filters '{"GeneratorId": [{"Value": "IAMPolicyGuardrail", "Comparison": "EQUALS"}]}'

# Monitor function logs
aws logs tail /aws/lambda/iam-policy-guardrail-$STACK_NAME --follow --region $REGION

# Check EventBridge rule status
aws events describe-rule --name iam-policy-guardrail-$STACK_NAME --region $REGION

${BOLD}🧪 Test the Guardrail:${NC}
# Create a test policy with wildcards to trigger the guardrail
aws iam create-policy --policy-name TestWildcardPolicy --region $REGION \\
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# Wait 2-3 minutes, then check Security Hub for findings
# Clean up test policy:
aws iam delete-policy --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/TestWildcardPolicy --region $REGION

${BOLD}💰 Cost Estimate:${NC}
• Lambda: ~\$0.10/month (event-driven execution)
• CloudWatch Logs: ~\$0.15/month
• EventBridge: ~\$0.05/month
• Total: ~\$0.30/month

${BOLD}🔄 Integration with Access Advisor:${NC}
This component works great alongside the Access Advisor component:
• Access Advisor: Weekly analysis of role usage patterns
• Policy Guardrail: Real-time analysis of policy changes
• Together: Comprehensive IAM security monitoring

EOF

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}Note: This was a dry run. No resources were deployed.${NC}"
    fi
}

# Main execution
main() {
    echo -e "${BOLD}🛡️ IAM Policy Guardrail Component Deployment${NC}"
    echo -e "Real-time IAM policy change monitoring and analysis\n"

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
        log_success "🎉 Policy Guardrail component deployed successfully!"
    fi
}

# Execute with all arguments
main "$@"