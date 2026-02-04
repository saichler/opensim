#!/bin/bash

# Script to increase open file limits for Kubernetes on Ubuntu
# Run with sudo

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo"
    exit 1
fi

echo "=== Increasing file limits for Kubernetes ==="

# 1. System-wide limits
echo "Configuring /etc/security/limits.conf..."
cat >> /etc/security/limits.conf << 'EOF'

# Kubernetes file limits - added by script
* soft nofile 10000000
* hard nofile 10000000
root soft nofile 10000000
root hard nofile 10000000
EOF
echo "Done."

# 2. Systemd default limits
echo "Configuring /etc/systemd/system.conf..."
if grep -q "^DefaultLimitNOFILE=" /etc/systemd/system.conf; then
    sed -i 's/^DefaultLimitNOFILE=.*/DefaultLimitNOFILE=10000000/' /etc/systemd/system.conf
elif grep -q "^#DefaultLimitNOFILE=" /etc/systemd/system.conf; then
    sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=10000000/' /etc/systemd/system.conf
else
    echo "DefaultLimitNOFILE=10000000" >> /etc/systemd/system.conf
fi
echo "Done."

# 3. Containerd service limits
echo "Configuring containerd service limits..."
mkdir -p /etc/systemd/system/containerd.service.d
cat > /etc/systemd/system/containerd.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=10000000
EOF
echo "Done."

# 4. Kubelet service limits
echo "Configuring kubelet service limits..."
mkdir -p /etc/systemd/system/kubelet.service.d
cat > /etc/systemd/system/kubelet.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=10000000
EOF
echo "Done."

# 5. Kernel parameters
echo "Configuring kernel parameters in /etc/sysctl.conf..."
if ! grep -q "fs.file-max" /etc/sysctl.conf; then
    cat >> /etc/sysctl.conf << 'EOF'

# Kubernetes file limits - added by script
fs.file-max = 20000000
fs.nr_open = 10000000
EOF
fi
echo "Done."

# 6. Apply sysctl changes
echo "Applying sysctl changes..."
sysctl -p

# 7. Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# 8. Restart services if they exist
echo "Restarting services..."
if systemctl is-active --quiet containerd; then
    systemctl restart containerd
    echo "Restarted containerd."
fi

if systemctl is-active --quiet kubelet; then
    systemctl restart kubelet
    echo "Restarted kubelet."
fi

# 9. Verify
echo ""
echo "=== Verification ==="
echo "System file-max: $(cat /proc/sys/fs/file-max)"
echo "Current file usage: $(cat /proc/sys/fs/file-nr)"
echo ""
echo "=== Configuration complete ==="
echo "A reboot is recommended for all changes to take full effect."
echo "Run 'sudo reboot' when ready."
