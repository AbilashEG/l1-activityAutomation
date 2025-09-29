#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  L1 Activity Automation Deployment     ${NC}"
echo -e "${BLUE}  Amazon Linux EC2 Production Setup     ${NC}"
echo -e "${BLUE}========================================${NC}"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_status "🚀 Starting L1 Activity Automation deployment on Amazon Linux..."

# Update system packages
print_status "📦 Updating system packages..."
sudo yum update -y

# Install Python 3 and pip
print_status "🐍 Installing Python 3 and pip..."
sudo yum install python3 python3-pip git -y

# Install Node.js 20
print_status "📦 Installing Node.js 20..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
    sudo yum install nodejs -y
else
    print_status "Node.js already installed: $(node --version)"
fi

# Install and configure nginx
print_status "🌐 Installing and configuring Nginx..."
sudo yum install nginx -y
sudo systemctl enable nginx
sudo systemctl start nginx

# Create web directory
print_status "📁 Creating web directories..."
sudo mkdir -p /var/www/html
sudo chown ec2-user:ec2-user /var/www/html

# Setup backend
print_status "🔧 Setting up Flask backend..."
cd /home/ec2-user/l1-activity-automation/backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    print_status "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment and install dependencies
print_status "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Creating from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
    else
        print_warning "Creating basic .env file - please update with your credentials"
        cat > .env << EOF
FLASK_ENV=production
FLASK_SECRET_KEY=your-secret-key-here
AWS_REGION=us-east-1
LAMBDA_FUNCTION_NAME=L1ActivityAutomation
BEDROCK_MODEL_ID=amazon.nova-pro-v1:0
DYNAMODB_TABLE_NAME=L1-Account-Groups
EOF
    fi
    print_warning "⚠️  Please update .env file with your production configuration"
fi

# Setup frontend
print_status "⚛️  Setting up React frontend..."
cd ../frontend

# Install Node.js dependencies
print_status "Installing Node.js dependencies..."
npm install

# Build React application
print_status "Building React application..."
npm run build

# Copy built files to web directory
print_status "Copying build files to web directory..."
sudo cp -r build/* /var/www/html/
sudo chown -R nginx:nginx /var/www/html/

# Setup systemd service
print_status "🔧 Configuring systemd service..."
sudo tee /etc/systemd/system/l1-automation.service > /dev/null << 'EOF'
[Unit]
Description=L1 Activity Automation CloudWatch Bot
After=network.target

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/l1-activity-automation/backend
Environment="PATH=/home/ec2-user/l1-activity-automation/backend/venv/bin"
Environment="FLASK_ENV=production"
ExecStart=/home/ec2-user/l1-activity-automation/backend/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 --timeout 300 --keep-alive 2 wsgi:app
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure nginx
print_status "🌐 Configuring Nginx..."
sudo tee /etc/nginx/nginx.conf > /dev/null << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 4096;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    server {
        listen       80 default_server;
        listen       [::]:80 default_server;
        server_name  _;
        root         /var/www/html;
        index        index.html index.htm;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;

        # Serve React frontend
        location / {
            try_files $uri $uri/ /index.html;
            
            # Cache static assets
            location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires 1y;
                add_header Cache-Control "public, immutable";
            }
        }

        # Proxy API requests to Flask backend
        location /api/ {
            proxy_pass http://127.0.0.1:5000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 300;
            proxy_connect_timeout 300;
            proxy_send_timeout 300;
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }

        error_page   404              /404.html;
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /usr/share/nginx/html;
        }
    }
}
EOF

# Test nginx configuration
print_status "🧪 Testing Nginx configuration..."
sudo nginx -t

# Reload systemd and start services
print_status "🔄 Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable l1-automation
sudo systemctl restart l1-automation
sudo systemctl restart nginx

# Wait a moment for services to start
sleep 3

# Check service status
print_status "📊 Checking service status..."
if sudo systemctl is-active --quiet l1-automation; then
    print_status "✅ L1 Automation service is running"
else
    print_error "❌ L1 Automation service failed to start"
    sudo systemctl status l1-automation --no-pager -l
fi

if sudo systemctl is-active --quiet nginx; then
    print_status "✅ Nginx service is running"
else
    print_error "❌ Nginx service failed to start"
    sudo systemctl status nginx --no-pager -l
fi

# Get public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "your-ec2-ip")

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Completed Successfully!    ${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}🌐 Your L1 Activity Automation Bot is running at:${NC}"
echo -e "${BLUE}   http://$PUBLIC_IP${NC}"
echo -e "${YELLOW}📝 Next steps:${NC}"
echo -e "${YELLOW}   1. Update .env file with your AWS credentials${NC}"
echo -e "${YELLOW}   2. Restart the service: sudo systemctl restart l1-automation${NC}"
echo -e "${YELLOW}   3. Check logs: sudo journalctl -u l1-automation -f${NC}"
echo -e "${GREEN}========================================${NC}"
