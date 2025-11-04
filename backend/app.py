import os
import json
import traceback
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import boto3
import logging
from uuid import uuid4

# Load environment variables
load_dotenv()

# ✅ Production-ready Flask app initialization
def create_app():
    app = Flask(__name__)
    
    # ✅ Environment-based configuration (minimal change)
    flask_env = os.getenv('FLASK_ENV', 'production')
    
    if flask_env == 'production':
        app.config.update(
            DEBUG=False,
            SECRET_KEY=os.getenv("FLASK_SECRET_KEY", str(uuid4()))
        )
        # ✅ Production logging (less verbose)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        # ✅ Secure CORS for production
        CORS(app, origins=os.getenv('ALLOWED_ORIGINS', '*').split(','))
    else:
        app.config.update(
            DEBUG=True,
            SECRET_KEY=os.getenv("FLASK_SECRET_KEY", str(uuid4()))
        )
        # ✅ Keep your original logging for development
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        CORS(app)
    
    return app

# ✅ Create app instance
app = create_app()

# ✅ ADDED: Global error handler to prevent HTML responses
@app.errorhandler(Exception)
def handle_error(e):
    """Global error handler to return JSON instead of HTML"""
    logging.error(f"Unhandled error: {e}")
    return jsonify({
        'success': False,
        'error': str(e),
        'timestamp': datetime.utcnow().isoformat()
    }), 500

# ✅ ALL YOUR ORIGINAL LOGIC REMAINS EXACTLY THE SAME
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
LAMBDA_FUNCTION_NAME = os.getenv("LAMBDA_FUNCTION_NAME", "L1ActivityAutomation")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID") or "amazon.nova-pro-v1:0"
DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "L1-Account-Groups")

try:
    bedrock_client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    lambda_client = boto3.client("lambda", region_name=AWS_REGION)
    sts_client = boto3.client("sts", region_name=AWS_REGION)
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    logging.info(f"AWS clients initialized successfully in region: {AWS_REGION}")
except Exception as e:
    logging.error(f"Failed to initialize AWS clients: {e}")
    raise

FIXED_ROLE_NAME = "L1TargetCrossAccountRole"

def get_discovery_regions():
    """Get regions dynamically from environment or account context"""
    env_regions = os.getenv("DISCOVERY_REGIONS")
    if env_regions:
        return env_regions.split(",")
    
    try:
        ec2 = boto3.client('ec2')
        regions_response = ec2.describe_regions(AllRegions=False)
        return [region['RegionName'] for region in regions_response['Regions']]
    except Exception as e:
        logging.warning(f"Could not discover regions dynamically: {e}")
        return ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1', 'ap-northeast-1', 'ap-southeast-1', 'ca-central-1']

DISCOVERY_REGIONS = get_discovery_regions()

def assume_role(account_id: str, role_name: str, session_name: str = "L1BotSession"):
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    logging.info(f"Assuming role: {role_arn}")
    try:
        response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        logging.info(f"Successfully assumed role for account {account_id}")
        return response["Credentials"]
    except Exception as e:
        logging.error(f"Failed to assume role {role_arn}: {e}")
        raise

def check_cloudwatch_intent(user_input: str, available_actions: list = None) -> bool:
    """Dynamic CloudWatch intent detection"""
    try:
        if not available_actions:
            available_actions = ["install CloudWatch agents", "configure monitoring", "check instance status"]
        
        action_list = ", ".join(available_actions)
        
        messages = [
            {
                "role": "user",
                "content": [
                    {
                        "text": f"User input: '{user_input}'. Available actions: {action_list}. "
                               f"Does user want CloudWatch/monitoring functionality? Reply YES or NO only."
                    }
                ],
            }
        ]
        
        payload = {
            "messages": messages,
            "inferenceConfig": {
                "max_new_tokens": 5,
                "temperature": 0,
                "top_p": 1,
                "top_k": 1,
            },
        }
        
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        
        resp_stream = response.get("body")
        if hasattr(resp_stream, "read"):
            resp_str = resp_stream.read().decode()
        else:
            resp_str = str(resp_stream)
            
        resp_json = json.loads(resp_str)
        content = resp_json.get("output", {}).get("message", {}).get("content", [])
        intent_text = content[0].get("text", "").strip().upper() if content else ""
        
        logging.info(f"CloudWatch intent classification: '{user_input}' -> {intent_text}")
        return "YES" in intent_text
        
    except Exception as e:
        logging.error(f"Error in CloudWatch intent detection: {e}")
        return False

def check_alarm_intent(user_input: str, available_actions: list = None) -> bool:
    """Dynamic alarm configuration intent detection"""
    try:
        if not available_actions:
            available_actions = ["configure CloudWatch alarms", "set up alerts", "create monitoring thresholds"]
        
        action_list = ", ".join(available_actions)
        
        messages = [
            {
                "role": "user",
                "content": [
                    {
                        "text": f"User input: '{user_input}'. Available alarm actions: {action_list}. "
                               f"Does user want alarm/alert configuration? Reply YES or NO only."
                    }
                ],
            }
        ]
        
        payload = {
            "messages": messages,
            "inferenceConfig": {
                "max_new_tokens": 5,
                "temperature": 0,
                "top_p": 0.1,
            },
        }
        
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        
        resp_stream = response.get("body")
        if hasattr(resp_stream, "read"):
            resp_str = resp_stream.read().decode()
        else:
            resp_str = str(resp_stream)
            
        resp_json = json.loads(resp_str)
        content = resp_json.get("output", {}).get("message", {}).get("content", [])
        intent_text = content[0].get("text", "").strip().upper() if content else ""
        
        logging.info(f"Alarm intent classification: '{user_input}' -> {intent_text}")
        return any(word in intent_text for word in ["YES", "TRUE", "ALARM", "MONITOR"])
        
    except Exception as e:
        logging.error(f"Error in alarm intent detection: {e}")
        return False

def check_instance_type_change_intent(user_input: str, available_actions: list = None) -> bool:
    """Dynamic instance type change intent detection"""
    try:
        if not available_actions:
            available_actions = ["change instance type", "resize instance", "upgrade instance", "modify instance type"]
        
        action_list = ", ".join(available_actions)
        
        messages = [
            {
                "role": "user",
                "content": [
                    {
                        "text": f"User input: '{user_input}'. Available actions: {action_list}. "
                               f"Does user want to change/resize/upgrade instance type? Reply YES or NO only."
                    }
                ],
            }
        ]
        
        payload = {
            "messages": messages,
            "inferenceConfig": {
                "max_new_tokens": 5,
                "temperature": 0,
                "top_p": 0.1,
            },
        }
        
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        
        resp_stream = response.get("body")
        if hasattr(resp_stream, "read"):
            resp_str = resp_stream.read().decode()
        else:
            resp_str = str(resp_stream)
            
        resp_json = json.loads(resp_str)
        content = resp_json.get("output", {}).get("message", {}).get("content", [])
        intent_text = content[0].get("text", "").strip().upper() if content else ""
        
        logging.info(f"Instance type change intent classification: '{user_input}' -> {intent_text}")
        return any(word in intent_text for word in ["YES", "TRUE", "CHANGE", "RESIZE", "UPGRADE"])
        
    except Exception as e:
        logging.error(f"Error in instance type change intent detection: {e}")
        return False

# *** NEW: GP2 to GP3 Volume Intent Detection ***
def check_volume_conversion_intent(user_input: str, available_actions: list = None) -> bool:
    """Dynamic GP2 to GP3 volume conversion intent detection"""
    try:
        if not available_actions:
            available_actions = ["convert GP2 to GP3 volumes", "upgrade storage volumes", "optimize EBS volumes", "migrate volumes"]
        
        action_list = ", ".join(available_actions)
        
        messages = [
            {
                "role": "user",
                "content": [
                    {
                        "text": f"User input: '{user_input}'. Available actions: {action_list}. "
                               f"Does user want to convert/upgrade/migrate GP2 volumes to GP3? Reply YES or NO only."
                    }
                ],
            }
        ]
        
        payload = {
            "messages": messages,
            "inferenceConfig": {
                "max_new_tokens": 5,
                "temperature": 0,
                "top_p": 0.1,
            },
        }
        
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        
        resp_stream = response.get("body")
        if hasattr(resp_stream, "read"):
            resp_str = resp_stream.read().decode()
        else:
            resp_str = str(resp_stream)
            
        resp_json = json.loads(resp_str)
        content = resp_json.get("output", {}).get("message", {}).get("content", [])
        intent_text = content[0].get("text", "").strip().upper() if content else ""
        
        logging.info(f"Volume conversion intent classification: '{user_input}' -> {intent_text}")
        return any(word in intent_text for word in ["YES", "TRUE", "CONVERT", "UPGRADE", "MIGRATE", "GP2", "GP3"])
        
    except Exception as e:
        logging.error(f"Error in volume conversion intent detection: {e}")
        return False

def get_account_groups():
    logging.info("=== GETTING ACCOUNT GROUPS FROM DYNAMODB ===")
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        logging.info(f"Scanning table: {DYNAMODB_TABLE_NAME} in region: {AWS_REGION}")
        response = table.scan()
        logging.info(f"DynamoDB scan response: {response}")
        items = response.get('Items', [])
        logging.info(f"Found {len(items)} items in DynamoDB")
        
        standardized_items = []
        for item in items:
            logging.info(f"Processing DynamoDB item: {item}")
            group_name = item.get('GroupName') or item.get('Groupname') or 'Unknown Group'
            account_id = item.get('AccountID')
            if account_id:
                standardized_item = {
                    'GroupName': group_name,
                    'AccountID': account_id,
                    'AccountName': item.get('AccountName', group_name),
                    'Environment': item.get('Environment', 'Unknown'),
                    'Owner': item.get('Owner', 'Unknown'),
                    'Description': item.get('Description', 'No description'),
                    'ConfiguredInstances': item.get('ConfiguredInstances', 0),
                    'UnConfiguredInstances': item.get('UnConfiguredInstances', 0),
                    'TotalInstances': item.get('TotalInstances', 0),
                    'LastUpdated': item.get('LastUpdated', datetime.utcnow().isoformat())
                }
                standardized_items.append(standardized_item)
                logging.info(f"Standardized item: {standardized_item}")
            else:
                logging.warning(f"Skipping item without AccountID: {item}")
        
        logging.info(f"Returning {len(standardized_items)} standardized account groups")
        return standardized_items
    except Exception as e:
        logging.error(f"Error getting account groups from DynamoDB: {e}")
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return []

def create_cross_account_cloudwatch_client(account_id, region):
    """Create CloudWatch client with assumed role credentials"""
    try:
        credentials = assume_role(account_id, FIXED_ROLE_NAME)
        return boto3.client('cloudwatch',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except Exception as e:
        logging.error(f"Failed to create CloudWatch client for account {account_id}: {e}")
        raise

def check_cloudwatch_alarms_status(cloudwatch_client, instance_id, instance_name=None):
    """Enhanced: Comprehensive real-time alarm detection WITH INSTANCE NAMES"""
    try:
        # Create display name with BOTH name and ID
        if instance_name and instance_name != "No Name":
            display_identifier = f"{instance_name} ({instance_id})"
        else:
            display_identifier = instance_id
            
        logging.info(f"🔍 Checking alarms for: {display_identifier}")
        
        # Get all alarms using paginator for complete results
        paginator = cloudwatch_client.get_paginator('describe_alarms')
        instance_alarms = []
        
        for page in paginator.paginate():
            for alarm in page.get('MetricAlarms', []):
                alarm_name = alarm['AlarmName']
                
                # Method 1: Check if alarm name contains instance ID
                if instance_id in alarm_name:
                    instance_alarms.append({
                        'name': alarm_name,
                        'state': alarm.get('StateValue', 'UNKNOWN'),
                        'reason': alarm.get('StateReason', ''),
                        'updated': alarm.get('StateUpdatedTimestamp', '').isoformat() if alarm.get('StateUpdatedTimestamp') else 'Unknown'
                    })
                    logging.info(f"✅ Found alarm (name match): {alarm_name} - State: {alarm.get('StateValue')}")
                    continue
                
                # Method 2: Check if alarm name contains instance name (if provided)
                if (instance_name and instance_name != "No Name" and 
                    instance_name.replace(' ', '-') in alarm_name):
                    instance_alarms.append({
                        'name': alarm_name,
                        'state': alarm.get('StateValue', 'UNKNOWN'),
                        'reason': alarm.get('StateReason', ''),
                        'updated': alarm.get('StateUpdatedTimestamp', '').isoformat() if alarm.get('StateUpdatedTimestamp') else 'Unknown'
                    })
                    logging.info(f"✅ Found alarm (instance name match): {alarm_name} - State: {alarm.get('StateValue')}")
                    continue
                
                # Method 3: Check dimensions for exact match
                for dimension in alarm.get('Dimensions', []):
                    if (dimension.get('Name') == 'InstanceId' and 
                        dimension.get('Value') == instance_id):
                        instance_alarms.append({
                            'name': alarm_name,
                            'state': alarm.get('StateValue', 'UNKNOWN'),
                            'reason': alarm.get('StateReason', ''),
                            'updated': alarm.get('StateUpdatedTimestamp', '').isoformat() if alarm.get('StateUpdatedTimestamp') else 'Unknown'
                        })
                        logging.info(f"✅ Found alarm (dimension match): {alarm_name} - State: {alarm.get('StateValue')}")
                        break
        
        # Log all found alarms with BOTH name and ID
        logging.info(f"📊 Total alarms found for {display_identifier}: {len(instance_alarms)}")
        for alarm in instance_alarms:
            logging.info(f"   - {alarm['name']} [{alarm['state']}] - Updated: {alarm['updated']}")
        
        # Check for expected alarm types
        expected_types = ['cpu', 'memory', 'disk', 'statuscheck']
        found_types = set()
        
        for alarm in instance_alarms:
            alarm_name_lower = alarm['name'].lower()
            for alarm_type in expected_types:
                if alarm_type in alarm_name_lower:
                    found_types.add(alarm_type)
                    logging.info(f"📈 Found alarm type '{alarm_type}' in {alarm['name']}")
                    break
        
        logging.info(f"📋 Alarm types detected for {display_identifier}: {list(found_types)}")
        
        # Consider configured if we have at least 3 different alarm types
        is_configured = len(found_types) >= 3
        
        logging.info(f"🎯 Final alarm status for {display_identifier}: {is_configured} ({len(instance_alarms)} alarms, {len(found_types)} types)")
        
        return is_configured
        
    except Exception as e:
        display_name = display_identifier if 'display_identifier' in locals() else instance_id
        logging.error(f"❌ Error checking alarm status for {display_name}: {e}")
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return False

def check_cloudwatch_agent_status(instance_id, region, credentials):
    """Dynamic CloudWatch agent status checking"""
    now = datetime.utcnow()
    start = now - timedelta(minutes=30)
    
    status_config = {
        'configured_symbols': ['✅', '🟢', '✓'],
        'unconfigured_symbols': ['❌', '🔴', '✗'],
        'paused_symbols': ['⏸️', '🟡', '⏹️']
    }
    
    configured_symbol = status_config['configured_symbols'][0]
    unconfigured_symbol = status_config['unconfigured_symbols'][0]
    
    cloudwatch = boto3.client('cloudwatch', 
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    namespaces_to_check = ['CWAgent', 'Windows System']
    
    for namespace in namespaces_to_check:
        try:
            response = cloudwatch.list_metrics(
                Namespace=namespace,
                Dimensions=[
                    {
                        'Name': 'InstanceId',
                        'Value': instance_id
                    }
                ]
            )
            
            metrics = response.get('Metrics', [])
            logging.info(f"Found {len(metrics)} metrics for instance {instance_id} in {namespace} namespace")
            
            if metrics:
                # ✅ FIXED: If metrics exist, agent is configured!
                metric_name = metrics[0]['MetricName']
                
                # Determine display text based on namespace and metric
                if namespace == 'CWAgent':
                    display_text = f'{configured_symbol} Configured (CWAgent - {metric_name.lower()})'
                else:
                    display_text = f'{configured_symbol} Configured ({namespace} - {metric_name})'
                
                logging.info(f"✅ Found {len(metrics)} CWAgent metrics for {instance_id}")
                
                return {
                    'configured': True,
                    'display': display_text,
                    'status': 'running',
                    'action_needed': False,
                    'details': {
                        'namespace': namespace,
                        'metricsFound': len(metrics),
                        'sampleMetric': metric_name
                    }
                }
        
        except Exception as e:
            logging.warning(f"Error listing {namespace} metrics for {instance_id}: {e}")
    
    return {
        'configured': False,
        'display': f'{unconfigured_symbol} Not Configured (no metrics in {region})',
        'status': 'not_reporting',
        'action_needed': True,
        'suggestions': ['Install CloudWatch agent', 'Check IAM permissions', 'Verify instance connectivity']
    }


def discover_instances_in_account(account_id, credentials):
    logging.info(f"Discovering instances in account: {account_id}")
    instances = []
    
    # Create CloudWatch clients for each region (alarms are region-specific)
    cloudwatch_clients = {}
    
    for region in DISCOVERY_REGIONS:
        try:
            logging.info(f"Scanning region: {region}")
            ec2 = boto3.client('ec2',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            # Create CloudWatch client for this specific region
            try:
                cloudwatch_clients[region] = boto3.client('cloudwatch',
                    region_name=region,
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
                logging.info(f"✅ Created CloudWatch client for region: {region}")
            except Exception as e:
                logging.warning(f"❌ Could not create CloudWatch client for {region}: {e}")
                cloudwatch_clients[region] = None
            
            response = ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'terminated':
                        continue
                    
                    instance_id = instance['InstanceId']
                    instance_state = instance['State']['Name']
                    
                    instance_name = "No Name"
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                instance_name = tag['Value']
                                break
                    
                    logging.info(f"Processing instance {instance_id} ({instance_name}) in {region} with state {instance_state}")

                    if instance_state == 'running':
                        # Check CloudWatch agent status
                        cw_status = check_cloudwatch_agent_status(instance_id, region, credentials)
                        
                        # Check for alarms - NOW PASS BOTH instance_id AND instance_name
                        alarms_configured = False
                        if cw_status['configured'] and cloudwatch_clients.get(region):
                            logging.info(f"🔍 Checking alarms for {instance_id} ({instance_name}) - agent configured")
                            # PASS BOTH instance_id AND instance_name
                            alarms_configured = check_cloudwatch_alarms_status(
                                cloudwatch_clients[region], instance_id, instance_name
                            )
                            logging.info(f"🎯 Alarm result for {instance_name} ({instance_id}): {alarms_configured}")
                        else:
                            if not cw_status['configured']:
                                logging.info(f"⏭️ Skipping alarm check for {instance_name} ({instance_id}) - agent not configured")
                            else:
                                logging.info(f"⏭️ Skipping alarm check for {instance_name} ({instance_id}) - no CloudWatch client")
                            
                    else:
                        cw_status = {
                            'configured': False,
                            'display': f'⏸️ Instance {instance_state.title()}',
                            'status': instance_state,
                            'action_needed': False
                        }
                        alarms_configured = False  # No alarms for non-running instances

                    instances.append({
                        'InstanceId': instance_id,
                        'InstanceName': instance_name,
                        'State': instance_state,
                        'Region': region,
                        'Platform': instance.get('Platform', 'linux'),
                        'InstanceType': instance['InstanceType'],
                        'LaunchTime': instance['LaunchTime'].isoformat(),
                        'CloudWatchConfigured': cw_status['configured'],
                        'CloudWatchDisplay': cw_status['display'],
                        'CloudWatchStatus': cw_status['status'],
                        'ActionNeeded': cw_status['action_needed'],
                        'AlarmsConfigured': alarms_configured  # Real-time alarm status
                    })

        except Exception as e:
            logging.error(f"Error discovering instances in {region}: {e}")
            continue
    
    # Log final instance summary with instance names
    total_instances = len(instances)
    running_instances = len([i for i in instances if i['State'] == 'running'])
    agent_configured = len([i for i in instances if i['CloudWatchConfigured']])
    alarms_configured = len([i for i in instances if i['AlarmsConfigured']])
    
    logging.info(f"📊 Instance discovery summary for account {account_id}:")
    logging.info(f"   Total: {total_instances}, Running: {running_instances}")
    logging.info(f"   Agent Configured: {agent_configured}, Alarms Configured: {alarms_configured}")
    
    # Log instances with names for better visibility
    for instance in instances[:5]:  # Log first 5 instances as sample
        name_display = f"{instance['InstanceName']} ({instance['InstanceId']})" if instance['InstanceName'] != "No Name" else instance['InstanceId']
        logging.info(f"   📋 {name_display} - Agent: {instance['CloudWatchConfigured']}, Alarms: {instance['AlarmsConfigured']}")
    
    return instances

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route("/")
def home():
    return jsonify({
        "message": "L1 Agentic CloudWatch Bot API is running.", 
        "region": AWS_REGION,
        "version": "2.8.0",  # ✅ UPDATED: Version with complete universal volume conversion
        "features": [
            "CloudWatch Agent Deployment", 
            "Real-time Alarm Detection with Instance Names", 
            "Instance Type Changes with Async Processing",
            "Universal Volume Type Conversion (All Types)",  # ✅ UPDATED
            "Volume Discovery and Status",   
            "Multi-Account Discovery",
            "Force Refresh Support"
        ],
        "environment": os.getenv('FLASK_ENV', 'production')
    })

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "L1 Agentic CloudWatch Bot",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.8.0",  # ✅ UPDATED: Version with complete universal volume conversion
        "aws_region": AWS_REGION,
        "dynamodb_table": DYNAMODB_TABLE_NAME,
        "lambda_function": LAMBDA_FUNCTION_NAME,
        "environment": os.getenv('FLASK_ENV', 'production'),
        "features": {
            "cloudwatch_agent_deployment": True,
            "alarm_configuration": True,
            "real_time_alarm_detection": True,
            "instance_name_support": True,
            "instance_type_change": True,
            "universal_volume_conversion": True,  # ✅ UPDATED
            "volume_discovery": True,
            "volume_status_monitoring": True,
            "multi_account_discovery": True,
            "dynamic_intent_detection": True,
            "alarm_status_detection": True,
            "force_refresh_support": True,
            "async_operations": True
        },
        "discovery_regions": len(DISCOVERY_REGIONS)
    })

@app.route("/api/test-dynamodb", methods=['GET'])
def test_dynamodb():
    logging.info("=== TESTING DYNAMODB CONNECTION ===")
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        response = table.scan()
        logging.info(f"DynamoDB test successful: {response}")
        return jsonify({
            'status': 'success',
            'table': DYNAMODB_TABLE_NAME,
            'region': AWS_REGION,
            'itemCount': len(response.get('Items', [])),
            'items': response.get('Items', [])
        })
    except Exception as e:
        logging.error(f"DynamoDB test failed: {e}")
        return jsonify({
            'status': 'error',
            'table': DYNAMODB_TABLE_NAME,
            'region': AWS_REGION,
            'error': str(e)
        }), 500

@app.route("/api/discover-accounts", methods=['GET'])
def discover_accounts():
    logging.info("=== DISCOVER ACCOUNTS ENDPOINT CALLED ===")
    try:
        account_groups = get_account_groups()
        logging.info(f"Retrieved {len(account_groups)} account groups")
        if not account_groups:
            logging.warning("No account groups found in DynamoDB")
            return jsonify({
                'accountGroups': [],
                'totalAccounts': 0,
                'message': 'No account groups configured in DynamoDB'
            })
        return jsonify({
            'accountGroups': account_groups,
            'totalAccounts': len(account_groups)
        })
    except Exception as e:
        logging.error(f"Error in discover_accounts: {e}")
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

# ✅ FIXED: Enhanced discover_instances endpoint with cache-busting
@app.route("/api/discover-instances/<account_id>", methods=['GET'])
def discover_instances(account_id):
    logging.info(f"=== DISCOVER INSTANCES FOR ACCOUNT: {account_id} ===")
    
    # ✅ FIXED: Check for force refresh parameter
    force_refresh = request.args.get('force_refresh', 'false').lower() == 'true'
    
    if force_refresh:
        logging.info(f"🔄 Force refresh requested for account {account_id}")
        # Clear any cached data here if you have caching
    
    try:
        credentials = assume_role(account_id, FIXED_ROLE_NAME)
        instances = discover_instances_in_account(account_id, credentials)
        
        total_instances = len(instances)
        running_instances = len([i for i in instances if i['State'] == 'running'])
        configured_instances = len([i for i in instances if i['CloudWatchConfigured']])
        alarms_configured_instances = len([i for i in instances if i['AlarmsConfigured']])
        unconfigured_count = len([i for i in instances if i['ActionNeeded'] and i['State'] == 'running'])
        
        # Enhanced logging for debugging with instance names
        logging.info(f"📈 Final summary for account {account_id}:")
        logging.info(f"   Total: {total_instances}, Running: {running_instances}")
        logging.info(f"   Agent Configured: {configured_instances}, Alarms Configured: {alarms_configured_instances}")
        logging.info(f"   Needs Configuration: {unconfigured_count}")
        
        return jsonify({
            'instances': instances,
            'summary': {
                'totalInstances': total_instances,
                'runningInstances': running_instances,
                'configuredInstances': configured_instances,
                'alarmsConfiguredInstances': alarms_configured_instances,
                'unconfiguredInstances': unconfigured_count
            },
            'accountId': account_id,
            'discoveredAt': datetime.utcnow().isoformat(),
            'forceRefresh': force_refresh  # ✅ Include refresh status
        })
    except Exception as e:
        logging.error(f"Error discovering instances in account {account_id}: {e}")
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/deploy-cloudwatch-agent", methods=['POST'])
def deploy_cloudwatch_agent():
    logging.info("=== DEPLOY CLOUDWATCH AGENT ENDPOINT CALLED ===")
    try:
        data = request.get_json()
        logging.info(f"🔍 RAW REQUEST JSON: {data}")
        
        instance_id = data.get('instanceId')
        account_id = data.get('accountId')
        region = data.get('region')
        
        logging.info(f"🔍 PARSED PARAMETERS:")
        logging.info(f"   - instance_id: '{instance_id}' (type: {type(instance_id)})")
        logging.info(f"   - account_id: '{account_id}' (type: {type(account_id)})")
        logging.info(f"   - region: '{region}' (type: {type(region)})")
        
        if not instance_id:
            logging.error("❌ MISSING INSTANCE ID")
            return jsonify({'error': 'Missing instanceId parameter'}), 400
        if not account_id:
            logging.error("❌ MISSING ACCOUNT ID")
            return jsonify({'error': 'Missing accountId parameter'}), 400
        if not region:
            logging.error("❌ MISSING REGION")
            return jsonify({'error': 'Missing region parameter'}), 400
        
        logging.info(f"✅ ALL PARAMETERS VALID - Deploy request: instance={instance_id}, account={account_id}, region={region}")
        
        lambda_payload = {
            'action': 'deploy_agent',
            'instance_id': instance_id,
            'account_id': account_id,
            'region': region,
            'role_name': FIXED_ROLE_NAME
        }
        
        logging.info(f"🚀 Invoking Lambda with payload: {lambda_payload}")
        
        lambda_response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType='RequestResponse',
            Payload=json.dumps(lambda_payload)
        )
        
        payload_response = lambda_response['Payload'].read()
        lambda_result = json.loads(payload_response)
        
        logging.info(f"📥 Lambda response: {lambda_result}")
        
        status_code = lambda_result.get('statusCode', 200)
        body = json.loads(lambda_result.get('body', '{}'))
        
        if status_code == 200:
            return jsonify({
                'success': True,
                'message': body.get('message', f'CloudWatch agent deployment initiated on {instance_id}'),
                'commandId': body.get('commandId'),
                'details': body
            })
        else:
            return jsonify({
                'success': False,
                'error': body.get('error', 'Deployment failed')
            }), status_code
            
    except Exception as e:
        logging.error(f"💥 Error deploying CloudWatch agent: {e}")
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/configure-alarms", methods=['POST'])
def configure_alarms():
    logging.info("=== CONFIGURE ALARMS ENDPOINT CALLED ===")
    try:
        data = request.get_json()
        logging.info(f"Alarm configuration request: {data}")
        
        instance_id = data.get('instanceId')
        account_id = data.get('accountId')
        region = data.get('region')
        platform = data.get('platform', 'linux')
        instance_name = data.get('instanceName', f'Instance-{instance_id}')  # Accept instance name from frontend
        alarm_config = data.get('alarmConfig', {})
        
        if not all([instance_id, account_id, region]):
            missing_params = []
            if not instance_id: missing_params.append('instanceId')
            if not account_id: missing_params.append('accountId')
            if not region: missing_params.append('region')
            return jsonify({'error': f'Missing required parameters: {", ".join(missing_params)}'}), 400
        
        # Enhanced logging with instance names
        display_name = f"{instance_name} ({instance_id})" if instance_name != f'Instance-{instance_id}' else instance_id
        logging.info(f"Creating alarms for {display_name} in account {account_id}")
        
        lambda_payload = {
            'action': 'create_alarms',
            'instance_id': instance_id,
            'instance_name': instance_name,  # Pass instance name to Lambda
            'account_id': account_id,
            'region': region,
            'platform': platform,
            'alarm_config': alarm_config,
            'role_name': FIXED_ROLE_NAME
        }
        
        logging.info(f"Invoking Lambda with alarm payload for {display_name}: {lambda_payload}")
        
        lambda_response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType='RequestResponse',
            Payload=json.dumps(lambda_payload)
        )
        
        payload_response = lambda_response['Payload'].read()
        lambda_result = json.loads(payload_response)
        
        logging.info(f"Lambda alarm response for {display_name}: {lambda_result}")
        
        status_code = lambda_result.get('statusCode', 200)
        body = json.loads(lambda_result.get('body', '{}'))
        
        if status_code == 200:
            return jsonify({
                'success': True,
                'message': f"Alarms configured successfully for {display_name}",
                'instanceName': instance_name,
                'instanceId': instance_id,
                'alarmDetails': body.get('alarmDetails'),
                'details': body
            })
        elif status_code == 207:  # Partial success
            return jsonify({
                'success': False,
                'message': body.get('message'),
                'instanceName': instance_name,
                'instanceId': instance_id,
                'alarmDetails': body.get('alarmDetails'),
                'partialSuccess': True
            }), 207
        else:
            return jsonify({
                'success': False,
                'error': body.get('error', 'Alarm configuration failed'),
                'instanceName': instance_name,
                'instanceId': instance_id
            }), status_code
            
    except Exception as e:
        logging.error(f"Error configuring alarms: {e}")
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ✅ FIXED: Async instance type change endpoint
@app.route("/api/change-instance-type", methods=['POST'])
def change_instance_type():
    logging.info("=== CHANGE INSTANCE TYPE ENDPOINT CALLED ===")
    try:
        data = request.get_json()
        logging.info(f"Instance type change request: {data}")
        
        instance_id = data.get('instanceId')
        account_id = data.get('accountId')
        region = data.get('region')
        new_instance_type = data.get('newInstanceType')
        instance_name = data.get('instanceName', f'Instance-{instance_id}')
        
        # Validate required parameters
        if not all([instance_id, account_id, region, new_instance_type]):
            missing_params = []
            if not instance_id: missing_params.append('instanceId')
            if not account_id: missing_params.append('accountId')
            if not region: missing_params.append('region')
            if not new_instance_type: missing_params.append('newInstanceType')
            return jsonify({'success': False, 'error': f'Missing required parameters: {", ".join(missing_params)}'}), 400
        
        # Enhanced logging with instance names
        display_name = f"{instance_name} ({instance_id})" if instance_name != f'Instance-{instance_id}' else instance_id
        logging.info(f"Starting instance type change for {display_name} to {new_instance_type}")
        
        lambda_payload = {
            'action': 'change_instance_type',
            'instance_id': instance_id,
            'account_id': account_id,
            'region': region,
            'new_instance_type': new_instance_type,
            'role_name': FIXED_ROLE_NAME
        }
        
        logging.info(f"Invoking Lambda with instance type change payload for {display_name}: {lambda_payload}")
        
        # ✅ FIXED: Make it ASYNC to avoid timeout
        lambda_response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType='Event',  # ✅ ASYNC - Don't wait for response!
            Payload=json.dumps(lambda_payload)
        )
        
        # ✅ FIXED: Return immediately with success message
        return jsonify({
            'success': True,
            'message': f"Instance type change initiated for {display_name}. This will take 5-10 minutes.",
            'instanceName': instance_name,
            'instanceId': instance_id,
            'newInstanceType': new_instance_type,
            'estimatedCompletion': '5-10 minutes',
            'status': 'initiated',
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error initiating instance type change: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# *** UPDATED: Volume Conversion Endpoints with NEW Lambda actions ***

@app.route("/api/find-gp2-volumes", methods=['POST'])
def find_gp2_volumes():
    """UPDATED: Find GP2 volumes using new Lambda action"""
    logging.info("=== FIND GP2 VOLUMES ENDPOINT CALLED ===")
    try:
        data = request.get_json()
        logging.info(f"GP2 volume discovery request: {data}")
        
        account_id = data.get('accountId')
        region = data.get('region')
        instance_id = data.get('instanceId')  # Optional
        volume_type_filter = 'gp2'  # Force GP2 filter for Lambda call

        
        # Validate required parameters
        if not account_id:
            return jsonify({'success': False, 'error': 'Missing accountId parameter'}), 400
        if not region:
            return jsonify({'success': False, 'error': 'Missing region parameter'}), 400
        
        discovery_scope = f"all {volume_type_filter.upper()} volumes in region"
        if instance_id:
            discovery_scope = f"{volume_type_filter.upper()} volumes for instance {instance_id}"
        
        logging.info(f"Finding {volume_type_filter.upper()} volumes in account {account_id} for: {discovery_scope}")
        
        # ✅ UPDATED: Use new Lambda action name
        lambda_payload = {
            'action': 'find_instance_volumes',  # ✅ CHANGED FROM 'find_gp2_volumes'
            'account_id': account_id,
            'region': region,
            'instance_id': instance_id if instance_id else None,
            'volume_type_filter': volume_type_filter,  # ✅ UPDATED: Universal filter
            'role_name': FIXED_ROLE_NAME
        }
        
        logging.info(f"Invoking Lambda with volume discovery payload: {lambda_payload}")
        
        lambda_response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType='RequestResponse',
            Payload=json.dumps(lambda_payload)
        )
        
        payload_response = lambda_response['Payload'].read()
        lambda_result = json.loads(payload_response)
        
        logging.info(f"Lambda volume discovery response: {lambda_result}")
        
        status_code = lambda_result.get('statusCode', 200)
        body = json.loads(lambda_result.get('body', '{}'))
        
        if status_code == 200:
            return jsonify({
                'success': True,
                'message': body.get('message'),
                'accountId': account_id,
                'region': region,
                'discoveryScope': discovery_scope,
                'summary': body.get('summary'),
                'volumes': body.get('volumes', []),
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': body.get('error', f'{volume_type_filter.upper()} volume discovery failed'),
                'accountId': account_id,
                'region': region
            }), status_code
            
    except Exception as e:
        logging.error(f"Error finding volumes: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/convert-volume-universal", methods=['POST'])
def convert_volume_universal():
    """Universal volume conversion endpoint - supports all volume types"""
    logging.info("=== UNIVERSAL VOLUME CONVERSION ENDPOINT CALLED ===")
    try:
        data = request.get_json()
        logging.info(f"Universal volume conversion request: {data}")

        account_id = data.get('accountId')
        region = data.get('region')
        volume_id = data.get('volumeId')
        new_volume_type = 'gp3'  # Force GP3 conversion only
        target_iops = data.get('targetIops')
        target_throughput = data.get('targetThroughput')

        # Validate required parameters
        if not all([account_id, region, volume_id, new_volume_type]):
            missing = []
            if not account_id: missing.append('accountId')
            if not region: missing.append('region')
            if not volume_id: missing.append('volumeId')
            if not new_volume_type: missing.append('newVolumeType')
            return jsonify({'success': False, 'error': f'Missing required parameters: {", ".join(missing)}'}), 400

        logging.info(f"Converting volume {volume_id} from any type to {new_volume_type} in account {account_id}")

        # Helper for safe integer casting
        def safe_cast_int(x):
            try:
                return int(x)
            except (TypeError, ValueError):
                return None

        lambda_payload = {
            'action': 'change_volume_type',
            'account_id': account_id,
            'region': region,
            'volume_id': volume_id,
            'new_volume_type': new_volume_type,
            'target_iops': safe_cast_int(target_iops),
            'target_throughput': safe_cast_int(target_throughput),
            'role_name': FIXED_ROLE_NAME
        }

        logging.info(f"Invoking Lambda with universal conversion payload: {lambda_payload}")

        lambda_response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType='RequestResponse',
            Payload=json.dumps(lambda_payload)
        )

        payload_response = lambda_response['Payload'].read()
        lambda_result = json.loads(payload_response)

        logging.info(f"Lambda universal conversion response: {lambda_result}")

        status_code = lambda_result.get('statusCode', 200)
        body = json.loads(lambda_result.get('body', '{}'))

        if status_code == 200:
            return jsonify({
                'success': True,
                'message': body.get('message'),
                'accountId': account_id,
                'region': region,
                'volumeDetails': body.get('volumeDetails'),
                'conversionDetails': body.get('details'),
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': body.get('error', 'Universal volume conversion failed'),
                'accountId': account_id,
                'region': region
            }), status_code

    except Exception as e:
        logging.error(f"Error in universal volume conversion: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/check-volume-conversion-status", methods=['POST'])
def check_volume_conversion_status():
    """Check status of volume conversions"""
    logging.info("=== CHECK VOLUME CONVERSION STATUS ENDPOINT CALLED ===")
    try:
        data = request.get_json()
        logging.info(f"Volume conversion status check request: {data}")
        
        account_id = data.get('accountId')
        region = data.get('region')
        volume_ids = data.get('volumeIds', [])  # Optional - specific volumes to check
        
        # Validate required parameters
        if not account_id:
            return jsonify({'success': False, 'error': 'Missing accountId parameter'}), 400
        if not region:
            return jsonify({'success': False, 'error': 'Missing region parameter'}), 400
        
        status_scope = "all recent volume modifications"
        if volume_ids:
            status_scope = f"specific volumes: {', '.join(volume_ids)}"
        
        logging.info(f"Checking volume conversion status in account {account_id} for: {status_scope}")
        
        lambda_payload = {
            'action': 'check_volume_conversion',
            'account_id': account_id,
            'region': region,
            'volume_ids': volume_ids if volume_ids else [],
            'role_name': FIXED_ROLE_NAME
        }
        
        logging.info(f"Invoking Lambda with volume status check payload: {lambda_payload}")
        
        lambda_response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType='RequestResponse',  # Synchronous for status check
            Payload=json.dumps(lambda_payload)
        )
        
        payload_response = lambda_response['Payload'].read()
        lambda_result = json.loads(payload_response)
        
        logging.info(f"Lambda volume status response: {lambda_result}")
        
        status_code = lambda_result.get('statusCode', 200)
        body = json.loads(lambda_result.get('body', '{}'))
        
        if status_code == 200:
            return jsonify({
                'success': True,
                'message': body.get('message'),
                'accountId': account_id,
                'region': region,
                'statusScope': status_scope,
                'modifications': body.get('modifications', []),
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': body.get('error', 'Volume status check failed'),
                'accountId': account_id,
                'region': region
            }), status_code
            
    except Exception as e:
        logging.error(f"Error checking volume conversion status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ✅ ADDED: Instance status check endpoint for polling
@app.route("/api/instance-status/<account_id>/<instance_id>", methods=['GET'])
def check_instance_status(account_id, instance_id):
    """Check specific instance status for polling"""
    try:
        credentials = assume_role(account_id, FIXED_ROLE_NAME)
        # Get instance details from specific region
        region = request.args.get('region', 'us-east-1')
        
        ec2 = boto3.client('ec2',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        
        return jsonify({
            'instanceId': instance_id,
            'state': instance['State']['Name'],
            'instanceType': instance['InstanceType'],
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error checking instance status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/converse", methods=["POST"])
def converse():
    logging.info("=== CONVERSE ENDPOINT CALLED ===")
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400
        
        user_input = data.get("message", "")
        session_id = data.get("session_id")
        
        logging.info(f"User input: '{user_input}', Session: {session_id}")
        
        if not session_id:
            return jsonify({"error": "Missing session_id"}), 400
        
        # Get system context dynamically
        try:
            account_groups = get_account_groups()
            total_accounts = len(account_groups)
        except Exception as e:
            logging.warning(f"Could not get account groups: {e}")
            total_accounts = 0
            account_groups = []
        
        # Check for different intents
        has_cloudwatch_intent = check_cloudwatch_intent(user_input)
        has_alarm_intent = check_alarm_intent(user_input)
        has_instance_type_change_intent = check_instance_type_change_intent(user_input)
        has_volume_conversion_intent = check_volume_conversion_intent(user_input)  # ✅ NEW
        
        # *** NEW: Volume conversion intent handling ***
        if has_volume_conversion_intent:
            return jsonify({
                "message": f"I'll help you convert volumes for cost savings and better performance! You have {total_accounts} accounts configured. "
                          f"I support converting between GP2, GP3, io1, io2, and magnetic volumes. "
                          f"GP2→GP3 can save up to 20% on storage costs while improving performance. "
                          f"Let me show you your instances so you can select volumes for conversion.",
                "action": "trigger_discovery",
                "intent": "volume_conversion",
                "context": {
                    "availableAccounts": total_accounts,
                    "nextStep": "volume_selection",
                    "benefits": "Up to 20% cost savings + improved performance",
                    "estimatedTime": "5-15 minutes per volume",
                    "supportedTypes": "GP2, GP3, io1, io2, magnetic"
                }
            })
        # Instance type change intent handling
        elif has_instance_type_change_intent:
            return jsonify({
                "message": f"I'll help you change instance types safely! You have {total_accounts} accounts configured. "
                          f"First, let me show you your instances so you can select which ones need type changes. "
                          f"⚠️ Note: This will cause 2-5 minutes downtime as instances must be stopped and restarted.",
                "action": "trigger_discovery",
                "intent": "instance_type_change",
                "context": {
                    "availableAccounts": total_accounts,
                    "nextStep": "instance_type_selection",
                    "warning": "Instance type changes require stop/start cycle"
                }
            })
        elif has_alarm_intent:
            return jsonify({
                "message": f"I'll help you configure CloudWatch alarms with instance names! You have {total_accounts} accounts configured. "
                          f"First, let me show you your instances so you can select which ones need alarm configuration.",
                "action": "trigger_discovery",
                "intent": "alarm_configuration",
                "context": {
                    "availableAccounts": total_accounts,
                    "nextStep": "alarm_setup"
                }
            })
        elif has_cloudwatch_intent:
            return jsonify({
                "message": f"I'll scan your {total_accounts} configured accounts for CloudWatch agent status...",
                "action": "trigger_discovery", 
                "intent": "cloudwatch_configuration",
                "context": {
                    "availableAccounts": total_accounts,
                    "nextStep": "agent_deployment"
                }
            })
        else:
            capabilities = [
                "discover instances across AWS accounts",
                "configure CloudWatch agents", 
                "set up monitoring alarms with instance names",
                "change instance types safely",
                "convert any EBS volume type (GP2↔GP3↔io1↔io2↔magnetic)",  # ✅ UPDATED
                "check monitoring status"
            ]
            
            return jsonify({
                "message": f"Hi! I can help you with: {', '.join(capabilities)}. "
                          f"You have {total_accounts} accounts configured. "
                          f"Try: 'configure cloudwatch', 'set up alarms', 'change instance type', or 'convert volumes'",
                "capabilities": capabilities,
                "accountCount": total_accounts,
                "suggestions": [
                    "configure cloudwatch agent",
                    "set up monitoring alarms", 
                    "change instance type",
                    "convert volumes between types",  # ✅ UPDATED
                    "show my instances"
                ]
            })
            
    except Exception as e:
        logging.error(f"Error in converse: {e}")
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({
            "error": str(e),
            "message": "CloudWatch Agent Assistant ready. Say 'configure cloudwatch' to begin."
        }), 500

if __name__ == "__main__":
    import sys
    
    # Get port from environment or default to 5000
    port = int(os.getenv('PORT', 5000))
    flask_env = os.getenv('FLASK_ENV', 'development')
    
    print("🚀 L1 Agentic CloudWatch Bot Starting...")
    print("="*50)
    print(f"📍 Environment: {flask_env}")
    print(f"🌐 AWS Region: {AWS_REGION}")
    print(f"📊 DynamoDB Table: {DYNAMODB_TABLE_NAME}")
    print(f"⚡ Lambda Function: {LAMBDA_FUNCTION_NAME}")
    print(f"🗺️  Discovery Regions: {len(DISCOVERY_REGIONS)} regions")
    print(f"🔌 Port: {port}")
    print("="*50)
    
    # ✅ PRODUCTION INSTRUCTIONS ONLY
    print("✅ To run in production:")
    print("1. Use: gunicorn --bind 0.0.0.0:5000 wsgi:app")
    print("2. Or deploy with systemd service")
    print("3. Never use app.run() in production!")
