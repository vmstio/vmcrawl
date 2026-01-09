# vmcrawl Installation Guide

## Prerequisites

- Python 3.8+
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
sudo cp -r /path/to/vmcrawl /opt/vmcrawl/
sudo chown -R vmcrawl:vmcrawl /opt/vmcrawl
```

### 3. Set Up Virtual Environment

```bash
# Switch to vmcrawl user
sudo -u vmcrawl -i

# Create virtual environment
cd /opt/vmcrawl
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Exit vmcrawl user
exit
```

### 4. Configure Environment Variables

```bash
sudo -u vmcrawl nano /opt/vmcrawl/.env
```

Add your configuration (database credentials, API tokens, etc.)

### 5. Install Service Files

```bash
# Make the shell script executable
sudo chmod +x /opt/vmcrawl/vmcrawl.sh

# Copy service file to systemd
sudo cp /opt/vmcrawl/vmcrawl.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload
```

### 6. Enable and Start Service

```bash
# Enable service to start on boot
sudo systemctl enable vmcrawl.service

# Start the service
sudo systemctl start vmcrawl.service

# Check status
sudo systemctl status vmcrawl.service
```

## Service Management

### View Logs

```bash
# Follow logs in real-time
sudo journalctl -u vmcrawl.service -f

# View recent logs
sudo journalctl -u vmcrawl.service -n 100

# View logs since boot
sudo journalctl -u vmcrawl.service -b
```

### Control Service

```bash
# Stop service
sudo systemctl stop vmcrawl.service

# Restart service
sudo systemctl restart vmcrawl.service

# Disable service
sudo systemctl disable vmcrawl.service
```

## Troubleshooting

### Service fails to start

1. Check logs: `sudo journalctl -u vmcrawl.service -n 50`
2. Verify permissions: `ls -la /opt/vmcrawl`
3. Test script manually: `sudo -u vmcrawl /opt/vmcrawl/vmcrawl.sh`

### Database connection issues

1. Verify PostgreSQL is running: `sudo systemctl status postgresql`
2. Check database credentials in `/opt/vmcrawl/.env`
3. Test database connection as vmcrawl user

### Permission errors

```bash
# Fix ownership
sudo chown -R vmcrawl:vmcrawl /opt/vmcrawl

# Fix script permissions
sudo chmod +x /opt/vmcrawl/vmcrawl.sh
```
