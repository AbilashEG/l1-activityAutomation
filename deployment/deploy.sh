#!/bin/bash
set -e

# Colors for clear output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  L1 Activity Automation Deployment     ${NC}"
echo -e "${BLUE}  Amazon Linux EC2 Production Setup     ${NC}"
echo -e "${BLUE}========================================${NC}"

print_status()   { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning()  { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error()    { echo -e "${RED}[ERROR]${NC} $1"; }

print_status "🚀 Starting L1 Activity Automation deployment..."

# Update system packages
print_status "📦 Updating system packages..."
sudo yum update -y

# Git, Python, pip
print_status "🐍 Installing Python 3, pip, and git..."
sudo yum install python3 python3-pip git -y

# Node.js 20
print_status "📦 Installing Node.js 20..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
    sudo yum install nodejs -y
else
    print_status "Node.js already installed: $(node --version)"
fi

# Nginx
print_status "🌐 Installing and configuring Nginx..."
sudo yum install nginx -y
sudo systemctl enable nginx
sudo systemctl start nginx

# Web directory
print_status "📁 Creating web directories..."
sudo mkdir -p /var/www/html
sudo chown ec2-user:ec2-user /var/www/html

# --- Deploy Flask Backend ---
print_status "🔧 Setting up Flask backend..."
cd /home/ec2-user/l1-activity-automation/backend

# Python venv
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Created Python virtual environment."
fi

print_status "Installing Python dependencies with pip..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# .env file
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Creating from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
    else
        cat > .env << EOF
FLASK_ENV=production
FLASK_SECRET_KEY=your-secret-key-here
AWS_REGION=us-east-1
LAMBDA_FUNCTION_NAME=L1ActivityAutomation
BEDROCK_MODEL_ID=amazon.nova-pro-v1:0
DYNAMODB_TABLE_NAME=L1-Account-Groups
EOF
    fi
    print_warning "⚠️  Please update .env with correct production credentials."
fi

# --- Deploy React Frontend ---
print_status "⚛️  Setting up React frontend..."
cd ../frontend
print_status "Cleaning previous node_modules and build..."
rm -rf node_modules package-lock.json build

print_status "Installing Node.js dependencies (npm install)..."
npm install

print_status "Building React application for production..."
npm run build

# Copy frontend build to web root
print_status "Copying build files to /var/www/html..."
sudo cp -r build/* /var/www/html/
sudo chown -R nginx:nginx /var/www/html/

# --- systemd for backend (gunicorn) ---
print_status "🔧 Configuring systemd service for Flask backend..."
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

# --- Nginx Proxy Setup ---
print_status "🌐 Configuring nginx reverse proxy..."
sudo tee /etc/nginx/nginx.conf > /dev/null << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events { worker_connections 1024; }

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

        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;

        location / {
            try_files $uri $uri/ /index.html;
            location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires 1y;
                add_header Cache-Control "public, immutable";
            }
        }
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
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
        error_page 404 /404.html;
        error_page 500 502 503 504 /50x.html;
        location = /50x.html { root /usr/share/nginx/html; }
    }
}
EOF

print_status "🧪 Testing Nginx config..."
sudo nginx -t

print_status "🔄 Reloading and starting systemd and Nginx..."
sudo systemctl daemon-reload
sudo systemctl enable l1-automation
sudo systemctl restart l1-automation
sudo systemctl restart nginx

sleep 3

print_status "📊 Checking backend and nginx status..."
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
