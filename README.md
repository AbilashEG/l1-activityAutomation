🌟 What is This Project?
The L1 Activity Automation is a cutting-edge agentic AI ChatBot that revolutionizes AWS CloudWatch management across multiple enterprise accounts. Instead of manual configuration, simply tell the bot what you need, and it autonomously handles:

Instance Discovery across all AWS accounts

CloudWatch Agent Deployment (Windows & Linux)

Intelligent Alarm Configuration

Real-time Status Monitoring

Cross-account Infrastructure Management

This is true agentic AI - the system understands intent, makes decisions, and takes autonomous actions in complex AWS environments.

🚀 Key Features
🤖 Agentic AI Capabilities
Natural Language Interface: "configure cloudwatch for my instances"

Intent Recognition: Powered by AWS Bedrock (Claude 3 Sonnet)

Autonomous Action: Takes real infrastructure actions based on conversation

Context Awareness: Remembers account configurations and instance states

☁️ AWS Integration
Multi-Account Support: Works across enterprise AWS environments

Cross-Account Roles: Secure IAM-based account access

Platform Agnostic: Handles Windows and Linux instances intelligently

Real-time Monitoring: Live status updates and health checks

🔧 Enterprise Features
Production CI/CD: Automated deployment with GitHub Actions

Scalable Architecture: React frontend, Flask backend, AWS services

Error Recovery: Intelligent failure handling and retries

Security: No hardcoded credentials, IAM role-based access

🏗️ Architecture
![L1 BOT -19 09 2025](https://github.com/user-attachments/assets/7d3ae169-702f-43ed-bb8e-abde79abd112)


    F --> I[Account Groups]
Technology Stack:

AI Engine: AWS Bedrock (Claude 3 Sonnet)

Backend: Python Flask with cross-account IAM

Frontend: React with conversational UI

Infrastructure: Lambda, DynamoDB, EC2, CloudWatch

DevOps: GitHub Actions, PM2, Nginx, Gunicorn

⚡ Quick Start
Prerequisites
AWS Account with appropriate permissions

Python 3.9+, Node.js 18+

EC2 instance for deployment

1. Clone Repository
bash
git clone https://github.com/AWS-daml/l1-activity-automation.git
cd l1-activity-automation
2. Environment Setup
bash
# Backend setup
cd backend
pip3 install -r requirements.txt --user
cp .env.example .env  # Configure your AWS credentials

# Frontend setup
cd ../frontend
npm install
npm run build
3. Configure AWS Resources
bash
# Deploy Lambda function (L1ActivityAutomation)
# Setup DynamoDB table (L1-Account-Groups)
# Configure cross-account IAM roles
# Setup AWS Bedrock access
4. Run Application
bash
# Backend
cd backend
gunicorn --bind 0.0.0.0:5000 wsgi:app

# Frontend served via Nginx
sudo cp -r frontend/build/* /var/www/html/
🎯 Usage Examples
Basic Conversation
text
User: "Hello"
Bot: "Hi! I can help you configure CloudWatch across your AWS accounts..."

User: "configure cloudwatch"
Bot: "I'll scan your 3 configured accounts for CloudWatch agent status..."
     → Automatically discovers instances across all accounts
     → Shows real-time agent and alarm status
Agent Deployment
text
User: "install cloudwatch agent on i-1234567890"
Bot: → Detects instance platform (Windows/Linux)
     → Deploys appropriate CloudWatch configuration
     → Sets up monitoring metrics
     → Configures alarms automatically
Monitoring Setup
text
User: "set up monitoring alarms"  
Bot: → Analyzes current instance configurations
     → Creates CPU, Memory, Disk, and Status alarms
     → Configures thresholds based on platform
     → Provides real-time setup feedback
📊 Demo
Agent Status Dashboard
✅ Linux Instances: CWAgent namespace metrics

✅ Windows Instances: Windows System namespace metrics

🔍 Real-time Detection: Live status across multiple regions

Intelligent Deployment
🤖 Platform Detection: Automatic Windows vs Linux identification

⚙️ Custom Configurations: OS-specific CloudWatch agent setup

📈 Automated Alarms: Smart threshold configuration

Multi-Account Management
🏢 Enterprise Scale: Handles multiple AWS accounts simultaneously

🔐 Secure Access: Cross-account IAM role assumption

🌍 Global Reach: Multi-region instance discovery

🔧 Configuration
Environment Variables
bash
# Backend (.env file)
AWS_REGION=us-east-1
LAMBDA_FUNCTION_NAME=L1ActivityAutomation
BEDROCK_MODEL_ID=amazon.nova-pro-v1:0
DYNAMODB_TABLE_NAME=L1-Account-Groups
FLASK_ENV=production
DynamoDB Schema
json
{
  "GroupName": "Production",
  "AccountID": "123456789012", 
  "AccountName": "Prod Environment",
  "Environment": "Production",
  "Owner": "DevOps Team"
}
Cross-Account IAM Role
json
{
  "RoleName": "L1TargetCrossAccountRole",
  "AssumeRolePolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::MAIN-ACCOUNT:root"},
      "Action": "sts:AssumeRole"
    }]
  }
}
🛠️ Development
Project Structure
text
l1-activity-automation/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── wsgi.py               # Gunicorn entry point
│   ├── requirements.txt      # Python dependencies
│   └── .env                  # Environment configuration
├── frontend/
│   ├── src/                  # React source code
│   ├── public/               # Static assets  
│   └── package.json          # Node dependencies
├── deployment/
│   └── deploy.sh             # Manual deployment script
├── .github/workflows/
│   └── deploy.yml            # CI/CD pipeline
└── lambda/
    └── l1_activity_automation.py  # Lambda function code
API Endpoints
GET /api/health - Service health check

GET /api/discover-accounts - List configured accounts

GET /api/discover-instances/<account_id> - Instance discovery

POST /api/deploy-cloudwatch-agent - Agent deployment

POST /api/configure-alarms - Alarm setup

POST /api/converse - AI conversation interface

Running Tests
bash
# Backend tests
cd backend
python -m pytest tests/

# Frontend tests
cd frontend  
npm test

# Integration tests
curl http://localhost:5000/api/health
🚀 Deployment
Manual Deployment
bash
chmod +x deployment/deploy.sh
./deployment/deploy.sh
CI/CD Pipeline
The repository includes a complete GitHub Actions workflow:

Automated Deployment on push to master

Health Checks and validation

Error Recovery and rollback capabilities

Production-Ready Gunicorn + Nginx setup

Infrastructure Requirements
EC2 Instance: t3.small or larger

Security Groups: HTTP (80), SSH (22)

IAM Roles: EC2 instance role with necessary permissions

AWS Services: Bedrock, Lambda, DynamoDB access

📈 Monitoring & Logging
Application Logs
bash
# Backend logs
pm2 logs l1-backend

# System logs  
sudo journalctl -u nginx -f

# CloudWatch metrics
aws cloudwatch list-metrics --namespace CWAgent
Health Monitoring
Application Health: /api/health endpoint

Service Status: PM2 process monitoring

Infrastructure: CloudWatch dashboard integration
