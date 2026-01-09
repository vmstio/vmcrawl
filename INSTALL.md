# vmcrawl Installation Guide

## Prerequisites

- Python 3.13+
- PostgreSQL database
- System user for running the service

## Installation Steps

### 1. Create System User

```bash
sudo useradd -r -s /bin/bash -d /opt/vmcrawl -m vmcrawl
```

### 2. Install Application

```bash
# Copy application files
git clone https://github.com/vmstio/vmcrawl.git /opt/vmcrawl
rm -fr /opt/vmcrawl
chown -R vmcrawl:vmcrawl /opt/vmcrawl
```

### 3. Set Up Virtual Environment

```bash
# Switch to vmcrawl user
sudo -u vmcrawl -i

# Create virtual environment
cd /opt/vmcrawl
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Exit vmcrawl user
exit
```

### 4. Configure Environment Variables

```bash
sudo -u vmcrawl vim /opt/vmcrawl/.env
```

Add your configuration (database credentials, API tokens, etc.)

### 5. Install Service Files

```bash
# Make the shell script executable
chmod +x /opt/vmcrawl/vmcrawl.sh

# Copy service file to systemd
cp /opt/vmcrawl/vmcrawl.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload
```

### 6. Enable and Start Service

```bash
# Enable service to start on boot
systemctl enable vmcrawl.service

# Start the service
systemctl start vmcrawl.service

# Check status
systemctl status vmcrawl.service
```

## Service Management

### View Logs

```bash
# Follow logs in real-time
journalctl -u vmcrawl.service -f

# View recent logs
journalctl -u vmcrawl.service -n 100

# View logs since boot
journalctl -u vmcrawl.service -b
```

### Control Service

```bash
# Stop service
systemctl stop vmcrawl.service

# Restart service
systemctl restart vmcrawl.service

# Disable service
systemctl disable vmcrawl.service
```

## Troubleshooting

### Service fails to start

1. Check logs: `journalctl -u vmcrawl.service -n 50`
2. Verify permissions: `ls -la /opt/vmcrawl`
3. Test script manually: `sudo -u vmcrawl /opt/vmcrawl/vmcrawl.sh`

### Permission errors

```bash
# Fix ownership
chown -R vmcrawl:vmcrawl /opt/vmcrawl

# Fix script permissions
chmod +x /opt/vmcrawl/vmcrawl.sh
```
