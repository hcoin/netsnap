# snapnet - Comprehensive Network Snapshot Tool

## Overview

`snapnet` is a unified command-line tool that captures a complete snapshot of your network configuration in a single JSON output. It combines all SnapNet modules into one comprehensive view.

## What It Captures

The tool captures five categories of network information:

1. **Devices** (`devices`) - Network interfaces
   - Interface configuration (MTU, MAC, state)
   - IP addresses (IPv4/IPv6)
   - WireGuard configuration and peers
   - Bridge configuration and STP
   - VLAN, veth, and other virtual interfaces
   - Carrier status and statistics

2. **Routes** (`routes`) - Routing tables
   - IPv4 and IPv6 routes
   - All routing tables (main, local, default, custom)
   - Gateway, metric, protocol information
   - Route attributes and flags

3. **Neighbors** (`neighbors`) - Neighbor cache
   - IPv4 ARP entries
   - IPv6 NDP (Neighbor Discovery Protocol)
   - Bridge FDB (Forwarding Database)
   - MAC addresses and states

4. **MDB** (`mdb`) - Multicast database
   - Bridge multicast forwarding entries
   - IGMP/MLD snooping information
   - Multicast group memberships

5. **Rules** (`rules`) - Policy routing rules
   - FIB rules for all families
   - Source/destination routing
   - Priority and table assignments
   - Rule actions and attributes

## Installation

### Option 1: From Package (Recommended)

```bash
# Install snapnet package
pip install snapnet

# The 'snapnet' command should now be in your PATH
which snapnet
```

### Option 2: Standalone Executable

```bash
# Copy to a directory in your PATH
sudo cp snapnet /usr/local/bin/
sudo chmod +x /usr/local/bin/snapnet

# Verify
snapnet --version
```

### Option 3: Direct Execution

```bash
# Make executable
chmod +x snapnet

# Run directly
sudo ./snapnet
```

## Usage

### Basic Usage

```bash
# Capture complete network snapshot (requires sudo)
sudo snapnet

# Output is compact JSON (one line)
```

### Show Help

```bash
snapnet --help
```

### Show Version

```bash
snapnet --version
```

### Pretty-Print Output

```bash
# Pretty-printed JSON for human readability
sudo snapnet --pretty

# Or pipe to jq
sudo snapnet | jq '.'
```

### Exclude Metadata

```bash
# Output without metadata section
sudo snapnet --no-metadata
```

### Save to File

```bash
# Save snapshot to file
sudo snapnet > network-snapshot.json

# Pretty-printed to file
sudo snapnet --pretty > network-snapshot-pretty.json

# With timestamp
sudo snapnet > network-snapshot-$(date +%Y%m%d-%H%M%S).json
```

## Output Structure

### JSON Format

```json
{
  "devices": {
    "eth0": {
      "index": 2,
      "name": "eth0",
      "type_name": "ETHER",
      "mtu": 1500,
      "addresses": [...],
      ...
    },
    "wlan0": {...},
    ...
  },
  "routes": [
    {
      "dst": "0.0.0.0/0",
      "gateway": "192.168.1.1",
      "dev": "eth0",
      "protocol": "boot",
      ...
    },
    ...
  ],
  "neighbors": [
    {
      "ifindex": 2,
      "ifname": "eth0",
      "family": "ipv4",
      "dst": "192.168.1.1",
      "lladdr": "00:11:22:33:44:55",
      "state_name": "REACHABLE",
      ...
    },
    ...
  ],
  "mdb": [
    {
      "ifindex": 3,
      "dev": "br0",
      "addr": "33:33:00:00:00:01",
      "state_name": "permanent",
      ...
    },
    ...
  ],
  "rules": [
    {
      "priority": 0,
      "family": "ipv4",
      "action": "to-table",
      "table": "local",
      ...
    },
    ...
  ],
  "_metadata": {
    "version": "2.1.0",
    "python_version": "3.12.3"
  }
}
```

### Metadata Section

The `_metadata` section includes:

- `version` - SnapNet version
- `python_version` - Python version used
- `errors` - Array of error messages (only present if errors occurred)

**Note:** Use `--no-metadata` to exclude this section.

## Examples

### Complete Snapshot

```bash
sudo snapnet --pretty
```

### Extract Specific Information with jq

```bash
# List all network interfaces
sudo snapnet | jq -r '.devices | keys[]'

# Get default gateway
sudo snapnet | jq -r '.routes[] | select(.dst == "0.0.0.0/0") | .gateway'

# List all IPv4 addresses
sudo snapnet | jq -r '.devices[] | .addresses[] | select(.family == "ipv4") | .address'

# Count neighbors by interface
sudo snapnet | jq '.neighbors | group_by(.ifname) | map({interface: .[0].ifname, count: length})'

# Get WireGuard interfaces
sudo snapnet | jq '.devices[] | select(.kind == "wireguard") | {name: .name, peers: .wireguard.peers}'

# List all bridge interfaces
sudo snapnet | jq -r '.devices[] | select(.kind == "bridge") | .name'
```

### Compare Snapshots

```bash
# Take baseline snapshot
sudo snapnet > baseline.json

# ... make network changes ...

# Take new snapshot
sudo snapnet > current.json

# Compare with diff
diff baseline.json current.json

# Or use jq for structured comparison
diff <(jq -S '.' baseline.json) <(jq -S '.' current.json)
```

### Monitor Network Changes

```bash
# Watch for changes every 5 seconds
watch -n 5 'sudo snapnet | jq ".devices.eth0.operstate_name, .neighbors | length"'

# Log snapshots every minute
while true; do
    sudo snapnet > snapshot-$(date +%Y%m%d-%H%M%S).json
    sleep 60
done
```

### Export for Analysis

```bash
# Export to pretty JSON for review
sudo snapnet --pretty > network-config.json

# Convert to YAML (if yq installed)
sudo snapnet | yq -P '.' > network-config.yaml

# Extract just routes
sudo snapnet | jq '.routes' > routes.json

# Extract just devices
sudo snapnet | jq '.devices' > devices.json
```

## Use Cases

### 1. Network Documentation

```bash
# Capture current network state
sudo snapnet --pretty > network-documentation-$(hostname)-$(date +%Y%m%d).json

# Include in system documentation repository
git add network-documentation-*.json
git commit -m "Network snapshot for $(hostname)"
```

### 2. Troubleshooting

```bash
# Capture state before issue
sudo snapnet > before-issue.json

# Reproduce issue or wait for it to occur

# Capture state after issue
sudo snapnet > after-issue.json

# Compare to find what changed
diff <(jq -S '.' before-issue.json) <(jq -S '.' after-issue.json)
```

### 3. Configuration Auditing

```bash
# Regular snapshots for audit trail
0 */6 * * * sudo snapnet > /var/log/network-snapshots/snapshot-$(date +\%Y\%m\%d-\%H\%M).json

# Keep last 30 days
find /var/log/network-snapshots/ -name "snapshot-*.json" -mtime +30 -delete
```

### 4. Deployment Verification

```bash
# After deployment
sudo snapnet > post-deployment.json

# Verify specific configuration
jq '.devices.eth0.mtu == 9000' post-deployment.json
jq '.routes[] | select(.dst == "10.0.0.0/8")' post-deployment.json
```

### 5. Backup and Restore Reference

```bash
# Capture current state
sudo snapnet --pretty > network-backup-$(date +%Y%m%d).json

# Use as reference for manual restoration if needed
# (Note: This is documentation, not automated restore)
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message and exit |
| `--version` | Show version and exit |
| `--pretty` | Pretty-print JSON output (indented, readable) |
| `--no-metadata` | Exclude `_metadata` section from output |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (see stderr for details) |
| 130 | Interrupted by user (Ctrl+C) |

## Error Handling

### Partial Success

If one module fails, the others continue. Errors are captured in the `_metadata.errors` array:

```json
{
  "devices": {...},
  "routes": [],
  "neighbors": [...],
  "mdb": [],
  "rules": [...],
  "_metadata": {
    "version": "2.1.0",
    "errors": [
      "mdb_info: Permission denied"
    ]
  }
}
```

### Common Issues

**Permission Denied:**
```bash
# Solution: Use sudo
sudo snapnet
```

**Module Import Errors:**
```bash
# Solution: Install snapnet package
pip install snapnet

# Or verify installation
pip show snapnet
```

**Python Version:**
```bash
# Check Python version (need 3.8+)
python3 --version

# Use correct Python version
python3.8 -m snapnet
```

## Requirements

- **Python:** 3.8 or higher
- **Permissions:** Root/sudo for complete information
- **Dependencies:** 
  - `cffi>=1.0.0`
  - `snapnet` package (contains all modules)

## Performance

**Typical execution time:** 50-200ms (depending on system complexity)

**Resource usage:**
- CPU: Minimal (single snapshot)
- Memory: ~10-50MB (depends on network size)
- Disk: ~10KB-1MB JSON (depends on configuration complexity)

## Output Size Examples

| Network Size | Approx. JSON Size | Devices | Routes | Neighbors |
|--------------|-------------------|---------|--------|-----------|
| Small (laptop) | 10-20 KB | 2-5 | 10-20 | 5-10 |
| Medium (server) | 50-100 KB | 10-20 | 50-100 | 20-50 |
| Large (router) | 200KB-1MB | 50+ | 500+ | 100+ |

## Integration Examples

### Monitoring System

```python
#!/usr/bin/env python3
import subprocess
import json
import time

while True:
    # Capture snapshot
    result = subprocess.run(['sudo', 'snapnet'], 
                          capture_output=True, text=True)
    
    if result.returncode == 0:
        snapshot = json.loads(result.stdout)
        
        # Extract metrics
        device_count = len(snapshot['devices'])
        route_count = len(snapshot['routes'])
        neighbor_count = len(snapshot['neighbors'])
        
        # Send to monitoring system
        print(f"Devices: {device_count}, Routes: {route_count}, Neighbors: {neighbor_count}")
    
    time.sleep(60)
```

### Ansible Playbook

```yaml
- name: Capture network snapshot
  hosts: all
  tasks:
    - name: Run snapnet
      command: snapnet
      become: yes
      register: network_snapshot
    
    - name: Save snapshot
      copy:
        content: "{{ network_snapshot.stdout }}"
        dest: "/var/log/network-snapshot-{{ ansible_date_time.iso8601 }}.json"
```

### systemd Service (Periodic Snapshots)

```ini
# /etc/systemd/system/snapnet-periodic.service
[Unit]
Description=Network Snapshot Capture
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/snapnet
StandardOutput=append:/var/log/network-snapshots/snapshot-%Y%m%d-%H%M%S.json
```

```ini
# /etc/systemd/system/snapnet-periodic.timer
[Unit]
Description=Run snapnet every 6 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
```

## Comparison with Individual Tools

### Running All Tools Separately

```bash
# Old way - run each tool
sudo snapnet-device -j > devices.json
sudo snapnet-route -j > routes.json
sudo snapnet-neighbor -j > neighbors.json
sudo snapnet-mdb -j > mdb.json
sudo snapnet-rule -j > rules.json

# Manually combine JSON files
# ... complicated jq or Python script ...
```

### Using snapnet (New Way)

```bash
# New way - single command
sudo snapnet > complete-snapshot.json
```

**Benefits:**
- ✅ Single command
- ✅ Consistent format
- ✅ Atomic snapshot (all at same time)
- ✅ Automatic error handling
- ✅ Built-in metadata

## Tips and Best Practices

### 1. Regular Snapshots

Create a cron job for regular captures:

```bash
# Add to crontab
0 */6 * * * /usr/local/bin/snapnet > /var/log/snapnet/$(date +\%Y\%m\%d-\%H\%M).json 2>&1
```

### 2. Compression for Storage

```bash
# Compress old snapshots
find /var/log/snapnet/ -name "*.json" -mtime +7 -exec gzip {} \;
```

### 3. Pre-Change Baseline

```bash
# Always capture before making changes
sudo snapnet > pre-change-$(date +%Y%m%d-%H%M%S).json
# ... make changes ...
sudo snapnet > post-change-$(date +%Y%m%d-%H%M%S).json
```

### 4. Git Tracking (for small networks)

```bash
# Track in git for history
sudo snapnet --pretty > network-config.json
git diff network-config.json
git add network-config.json
git commit -m "Network config update"
```

### 5. Anonymize for Sharing

```bash
# Remove sensitive info before sharing
sudo snapnet | jq 'del(.devices[].wireguard.private_key, .neighbors[].lladdr)' > shareable.json
```

## Troubleshooting

### Issue: Empty Output

**Problem:** `{}`

**Solution:**
```bash
# Check if running with sudo
sudo snapnet

# Check for errors
sudo snapnet 2>&1 | grep -i error
```

### Issue: Metadata Shows Errors

**Problem:**
```json
"_metadata": {
  "errors": ["device_info: CFFI error"]
}
```

**Solution:**
```bash
# Install CFFI
pip install cffi

# Install setuptools (Python 3.12+)
pip install setuptools
```

### Issue: Command Not Found

**Problem:** `bash: snapnet: command not found`

**Solution:**
```bash
# Add to PATH or use full path
/usr/local/bin/snapnet

# Or install package
pip install snapnet
which snapnet
```

## See Also

- `snapnet-device` - Device information only
- `snapnet-route` - Routing information only
- `snapnet-neighbor` - Neighbor information only
- `snapnet-mdb` - Multicast database only
- `snapnet-rule` - Policy routing rules only

## Support

For issues, questions, or contributions:
- Documentation: See individual tool man pages
- Source: SnapNet package repository
- Python version: Requires 3.8+

## License

MIT License - See LICENSE file in SnapNet package
