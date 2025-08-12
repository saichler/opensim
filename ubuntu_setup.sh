#!/bin/bash

# Ubuntu Server Setup Script for Network Device Simulator
# This script installs all required dependencies and configures the system

set -e  # Exit on any error

echo "🚀 Setting up Network Device Simulator on Ubuntu Server..."
echo "========================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run this script as root (sudo ./ubuntu_setup.sh)"
    exit 1
fi

# Update package lists
echo "📦 Updating package lists..."
apt update

# Install essential packages
echo "📦 Installing essential packages..."
apt install -y \
    curl \
    wget \
    git \
    build-essential \
    iproute2 \
    iptables \
    net-tools \
    iputils-ping \
    snmp \
    snmp-mibs-downloader \
    openssh-client \
    jq \
    vim \
    htop

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "📦 Installing Go programming language..."
    GO_VERSION="1.21.5"
    cd /tmp
    wget -q "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    
    # Add Go to PATH for all users
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export GOPATH=$HOME/go' >> /etc/profile
    echo 'export PATH=$PATH:$GOPATH/bin' >> /etc/profile
    
    # Set for current session
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    
    echo "✅ Go ${GO_VERSION} installed successfully"
else
    echo "✅ Go is already installed: $(go version)"
fi

# Create TUN/TAP module loading
echo "🔧 Configuring TUN/TAP support..."
modprobe tun
echo "tun" >> /etc/modules

# Enable IP forwarding (useful for network simulation)
echo "🔧 Enabling IP forwarding..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
sysctl -p

# Configure system limits for high file descriptor usage
echo "🔧 Configuring system limits..."
cat >> /etc/security/limits.conf << EOF
# Network Device Simulator limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
root soft nproc 32768
root hard nproc 32768
EOF

# Configure systemd limits
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/limits.conf << EOF
[Manager]
DefaultLimitNOFILE=65536
DefaultLimitNPROC=32768
EOF

# Reload systemd configuration
systemctl daemon-reload

# Configure kernel parameters for networking
echo "🔧 Configuring kernel networking parameters..."
cat >> /etc/sysctl.conf << EOF

# Network Device Simulator kernel parameters
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 1024

# Allow binding to any IP (for device simulation)
net.ipv4.ip_nonlocal_bind = 1
net.ipv6.ip_nonlocal_bind = 1

# Increase maximum number of network interfaces
net.core.dev_weight = 64
EOF

# Apply sysctl changes
sysctl -p

# Install SNMP MIBs
echo "🔧 Installing SNMP MIBs..."
download-mibs

# Create simulator user (optional, for non-root operation where possible)
if ! id "simulator" &>/dev/null; then
    echo "👤 Creating simulator user..."
    useradd -r -s /bin/bash -d /opt/simulator simulator
    mkdir -p /opt/simulator
    chown simulator:simulator /opt/simulator
fi

# Set up firewall rules to allow simulator ports
echo "🔧 Configuring firewall for simulator..."
if command -v ufw &> /dev/null; then
    # Allow SSH (standard)
    ufw allow ssh
    
    # Allow simulator web UI
    ufw allow 8080/tcp
    
    # Allow SNMP range for simulators
    ufw allow 161:65535/udp
    
    # Allow SSH range for simulators  
    ufw allow 22:65535/tcp
    
    echo "✅ UFW firewall configured"
else
    echo "⚠️  UFW not installed, manual firewall configuration may be needed"
fi

# Create directories for simulator
echo "📁 Creating simulator directories..."
mkdir -p /opt/simulator/{logs,data,config}
chown -R simulator:simulator /opt/simulator

# Set up log rotation for simulator
cat > /etc/logrotate.d/simulator << EOF
/opt/simulator/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 simulator simulator
}
EOF

echo "🔧 Verifying installation..."

# Check Go installation
if command -v go &> /dev/null; then
    echo "✅ Go: $(go version)"
else
    echo "❌ Go installation failed"
    exit 1
fi

# Check TUN/TAP support
if [ -c /dev/net/tun ]; then
    echo "✅ TUN/TAP device available"
else
    echo "❌ TUN/TAP device not available"
    exit 1
fi

# Check required commands
for cmd in ip iptables ping snmpget ssh jq; do
    if command -v $cmd &> /dev/null; then
        echo "✅ $cmd: available"
    else
        echo "❌ $cmd: missing"
        exit 1
    fi
done

# Display system limits
echo "📊 Current system limits:"
echo "Max open files: $(ulimit -n)"
echo "Max processes: $(ulimit -u)"

echo ""
echo "🎉 Ubuntu Server setup completed successfully!"
echo "========================================================"
echo ""
echo "📋 Next steps:"
echo "1. Reboot the server to ensure all changes take effect:"
echo "   sudo reboot"
echo ""
echo "2. After reboot, clone and build the simulator:"
echo "   git clone <your-repo>"
echo "   cd opensim/go"
echo "   go build -o sim/sim ./sim"
echo ""
echo "3. Run the simulator with root privileges:"
echo "   sudo ./sim/sim"
echo ""
echo "⚠️  Important notes:"
echo "- The simulator requires root privileges for TUN interface creation"
echo "- Default ports: Web UI (8080), SNMP (161+), SSH (22+)"
echo "- Log files will be in /opt/simulator/logs/"
echo "- System limits have been increased for high device counts"
echo ""
echo "🔧 Troubleshooting:"
echo "- Check logs: journalctl -u <service-name>"
echo "- Verify limits: ulimit -n"
echo "- Test TUN: ls -la /dev/net/tun"
echo "- Check Go path: echo \$PATH"