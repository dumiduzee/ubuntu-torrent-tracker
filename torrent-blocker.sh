#!/bin/bash

# CrowdSec Torrent Blocker Installation Script
# This script installs and configures CrowdSec to detect and block BitTorrent traffic
#
# Created for Ubuntu/Debian-based systems
# Usage: sudo ./install-torrent-blocker.sh

# Text colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

echo -e "${BLUE}=== CrowdSec Torrent Blocker Installation Script ===${NC}"
echo -e "${YELLOW}This script will install and configure CrowdSec to detect and block BitTorrent traffic${NC}"
echo ""

# Step 1: Update system
echo -e "${GREEN}Step 1: Updating system...${NC}"
apt update && apt upgrade -y

# Step 2: Install NFTables (if not already installed)
echo -e "${GREEN}Step 2: Installing NFTables...${NC}"
apt install -y nftables
systemctl enable nftables
systemctl start nftables

# Step 3: Install CrowdSec
echo -e "${GREEN}Step 3: Installing CrowdSec...${NC}"
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec
systemctl enable crowdsec
systemctl start crowdsec

# Step 4: Install CrowdSec NFTables bouncer
echo -e "${GREEN}Step 4: Installing CrowdSec NFTables bouncer...${NC}"
apt install -y crowdsec-firewall-bouncer-nftables
systemctl enable crowdsec-firewall-bouncer-nftables
systemctl start crowdsec-firewall-bouncer-nftables

# Step 5: Creating directories for custom configurations
echo -e "${GREEN}Step 5: Creating custom configuration directories...${NC}"
mkdir -p /etc/crowdsec/scenarios/
mkdir -p /etc/crowdsec/profiles.d/
mkdir -p /etc/crowdsec/acquis.d/
mkdir -p /usr/local/bin/

# Step 6: Create custom BitTorrent detection scenario
echo -e "${GREEN}Step 6: Creating BitTorrent detection scenario...${NC}"
cat > /etc/crowdsec/scenarios/bittorrent-detection.yaml << 'EOF'
type: leaky
name: custom-bittorrent-detection
description: "Detect BitTorrent traffic"
filter: "evt.Meta.log_type == 'syslog' && evt.Line contains 'TORRENT'"
leakspeed: "10s"
capacity: 3
labels:
  service: bittorrent
  type: abuse
  remediation: true
groupby: "evt.Meta.source_ip"
blackhole: 10m
reprocess: false
EOF

# Step 7: Create custom profile for BitTorrent remediation
echo -e "${GREEN}Step 7: Creating BitTorrent remediation profile...${NC}"
cat > /etc/crowdsec/profiles.d/bittorrent.yaml << 'EOF'
name: bittorrent_remediation
filters:
 - Alert.GetScenario() == 'custom-bittorrent-detection'
decisions:
 - type: ban
   duration: 4h
on_success: break
EOF

# Step 8: Create custom acquisition file for kernel logs
echo -e "${GREEN}Step 8: Creating acquisition file for kernel logs...${NC}"
cat > /etc/crowdsec/acquis.d/kernel-logs.yaml << 'EOF'
filenames:
  - /var/log/kern.log
labels:
  type: syslog
---
source: journalctl
labels:
  type: syslog
EOF

# Step 9: Create NFTables configuration script for BitTorrent detection
echo -e "${GREEN}Step 9: Creating NFTables configuration script...${NC}"
cat > /usr/local/bin/torrent-detection.sh << 'EOF'
#!/bin/bash

# Create NFTables rules to log torrent traffic
nft flush ruleset
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; policy accept\; }
nft add chain inet filter forward { type filter hook forward priority 0 \; policy accept\; }
nft add chain inet filter output { type filter hook output priority 0 \; policy accept\; }

# Create a chain for torrent detection
nft add chain inet filter torrent_detect

# Jump to torrent detection chain
nft add rule inet filter forward jump torrent_detect
nft add rule inet filter output jump torrent_detect

# BitTorrent port rules
nft add rule inet filter torrent_detect tcp dport {6881-6889} log prefix \"TORRENT-PORT: \" limit rate 1/minute counter
nft add rule inet filter torrent_detect udp dport {6881-6889} log prefix \"TORRENT-PORT: \" limit rate 1/minute counter

# DHT port
nft add rule inet filter torrent_detect udp dport 6969 log prefix \"TORRENT-DHT: \" limit rate 1/minute counter

# Common tracker ports
nft add rule inet filter torrent_detect tcp dport 1337 log prefix \"TORRENT-TRACKER: \" limit rate 1/minute counter
nft add rule inet filter torrent_detect tcp dport 9090 log prefix \"TORRENT-TRACKER: \" limit rate 1/minute counter

# Additional suspected torrent ports
nft add rule inet filter torrent_detect tcp dport {2710, 7777, 4444, 4445, 4446, 4447, 4448} log prefix \"TORRENT-SUSPECT: \" limit rate 1/minute counter

# Save rules to make them persistent
nft list ruleset > /etc/nftables.conf
EOF

# Make the script executable
chmod +x /usr/local/bin/torrent-detection.sh

# Step 10: Configure NFTables script to run at boot
echo -e "${GREEN}Step 10: Setting NFTables script to run at boot...${NC}"
echo "@reboot root /usr/local/bin/torrent-detection.sh" >> /etc/crontab

# Step 11: Run NFTables script now
echo -e "${GREEN}Step 11: Running NFTables configuration script...${NC}"
/usr/local/bin/torrent-detection.sh

# Step 12: Register the scenario
echo -e "${GREEN}Step 12: Registering the BitTorrent detection scenario...${NC}"
cscli scenarios validate /etc/crowdsec/scenarios/bittorrent-detection.yaml

# Step 13: Restart CrowdSec services
echo -e "${GREEN}Step 13: Restarting CrowdSec services...${NC}"
systemctl restart crowdsec
systemctl restart crowdsec-firewall-bouncer-nftables

# Step 14: Create additional blocker for large port ranges
echo -e "${GREEN}Step 14: Creating advanced torrent blocking script...${NC}"
cat > /usr/local/bin/block-torrent-ranges.sh << 'EOF'
#!/bin/bash

# Block additional BitTorrent port ranges
nft add rule inet filter forward tcp dport 6000-7000 drop
nft add rule inet filter forward udp dport 6000-7000 drop

# Block outgoing BitTorrent port ranges
nft add rule inet filter output tcp dport 6881-6889 drop
nft add rule inet filter output udp dport 6881-6889 drop

# Block BitTorrent DHT
nft add rule inet filter output udp dport 6969 drop

# Save rules
nft list ruleset > /etc/nftables.conf
EOF

# Make the script executable
chmod +x /usr/local/bin/block-torrent-ranges.sh

# Add to crontab to run at boot
echo "@reboot root /usr/local/bin/block-torrent-ranges.sh" >> /etc/crontab

# Run the script now
/usr/local/bin/block-torrent-ranges.sh

# Step 15: Create monitoring script for torrent activity
echo -e "${GREEN}Step 15: Creating monitoring script...${NC}"
cat > /usr/local/bin/torrent-monitor.sh << 'EOF'
#!/bin/bash

# Log any ongoing decisions
echo "=== Current Ban Decisions ===" > /var/log/torrent-monitor.log
cscli decisions list >> /var/log/torrent-monitor.log

# Check for torrent-related strings in active connections
echo -e "\n=== Active Torrent Connections ===" >> /var/log/torrent-monitor.log
ss -tunapl | grep -E '6881|6969|1337|BitTorrent|torrent' >> /var/log/torrent-monitor.log 2>&1

# Log date
date >> /var/log/torrent-monitor.log
EOF

# Make the script executable
chmod +x /usr/local/bin/torrent-monitor.sh

# Add to crontab to run periodically
echo "*/30 * * * * root /usr/local/bin/torrent-monitor.sh" >> /etc/crontab

# Step 16: Enable automatic updates for CrowdSec
echo -e "${GREEN}Step 16: Setting up automatic updates for CrowdSec...${NC}"
cscli hub update

# Step 17: Create uninstall script for future reference
echo -e "${GREEN}Step 17: Creating uninstall script...${NC}"
cat > /usr/local/bin/uninstall-torrent-blocker.sh << 'EOF'
#!/bin/bash

# Remove crontab entries
sed -i '/torrent-detection.sh/d' /etc/crontab
sed -i '/block-torrent-ranges.sh/d' /etc/crontab
sed -i '/torrent-monitor.sh/d' /etc/crontab

# Stop and disable services
systemctl stop crowdsec-firewall-bouncer-nftables
systemctl disable crowdsec-firewall-bouncer-nftables
systemctl stop crowdsec
systemctl disable crowdsec

# Remove packages
apt remove -y crowdsec-firewall-bouncer-nftables
apt remove -y crowdsec

# Remove custom files
rm -f /etc/crowdsec/scenarios/bittorrent-detection.yaml
rm -f /etc/crowdsec/profiles.d/bittorrent.yaml
rm -f /etc/crowdsec/acquis.d/kernel-logs.yaml
rm -f /usr/local/bin/torrent-detection.sh
rm -f /usr/local/bin/block-torrent-ranges.sh
rm -f /usr/local/bin/torrent-monitor.sh
rm -f /usr/local/bin/uninstall-torrent-blocker.sh

echo "Torrent blocker uninstalled. You may need to manually reconfigure your firewall rules."
EOF

# Make the uninstall script executable
chmod +x /usr/local/bin/uninstall-torrent-blocker.sh

# Final step: Verify installation
echo -e "${GREEN}Final Step: Verifying installation...${NC}"
echo -e "${YELLOW}CrowdSec status:${NC}"
cscli status

echo ""
echo -e "${GREEN}===== Installation Complete! =====${NC}"
echo ""
echo -e "${YELLOW}Your system is now configured to detect and block BitTorrent traffic.${NC}"
echo -e "${YELLOW}The script has created the following:${NC}"
echo "- Custom BitTorrent detection scenario"
echo "- NFTables rules to log and block torrent traffic"
echo "- Automatic blocking of IPs engaged in torrent activities"
echo "- Monitoring script that runs every 30 minutes"
echo ""
echo -e "${YELLOW}To monitor BitTorrent blocking:${NC}"
echo "- Check CrowdSec decisions: sudo cscli decisions list"
echo "- View monitoring log: sudo cat /var/log/torrent-monitor.log"
echo "- View CrowdSec logs: sudo tail -f /var/log/crowdsec.log"
echo ""
echo -e "${YELLOW}To uninstall:${NC}"
echo "- Run: sudo /usr/local/bin/uninstall-torrent-blocker.sh"
echo ""

exit 0
