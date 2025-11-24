# NetMon - Quick Start Guide

## What is NetMon?

NetMon is a comprehensive Python package for monitoring Linux network subsystems using RTNetlink and Generic Netlink protocols. It provides powerful command-line tools for inspecting network interfaces, routing tables, neighbor tables (ARP/NDP), multicast databases, and routing rules.

## Installation

### From PyPI (Recommended)

Once published to PyPI:

```bash
pip install netmon
```

### From Source

```bash
# Clone or download the package
cd netmon

# Install
pip install .

# Or install in development mode
pip install -e .
```

## Basic Usage

All commands require root/sudo privileges:

```bash
# Network interfaces and addresses
sudo netmon-device

# Routing table
sudo netmon-route

# Neighbor table (ARP/NDP)
sudo netmon-neighbor

# Multicast database
sudo netmon-mdb

# Routing rules
sudo netmon-rule
```

## Command Examples

### Device Information

```bash
# Full interface information
sudo netmon-device

# Show only WireGuard interfaces
sudo netmon-device --wireguard

# Show detailed address information
sudo netmon-device --addresses

# Show summary of special interfaces
sudo netmon-device --summary
```

### Routing Information

```bash
# Full routing table
sudo netmon-route

# Human-readable summary
sudo netmon-route --summary

# IPv4 routes only
sudo netmon-route --ipv4

# Specific routing table
sudo netmon-route --table main
```

### Neighbor Information

```bash
# All neighbor entries
sudo netmon-neighbor

# Summary view
sudo netmon-neighbor --summary

# IPv4 ARP only
sudo netmon-neighbor --arp

# IPv6 NDP only
sudo netmon-neighbor --ndp

# Filter by interface
sudo netmon-neighbor --interface eth0
```

## Python API

Use NetMon programmatically:

```python
from netmon import device_info

# Get all interfaces (requires root)
with device_info.RTNetlinkQuery() as rtq:
    interfaces = rtq.get_interfaces()

# Process interface data
for if_name, if_info in interfaces.items():
    print(f"{if_name}: {if_info['operstate_name']}")
```

## Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux (kernel 2.6+)
- **Privileges**: Root/sudo access required
- **Dependencies**: cffi, setuptools

## Output Format

All tools output JSON by default, making it easy to integrate with other tools or scripts:

```bash
# Save to file
sudo netmon-device > interfaces.json

# Process with jq
sudo netmon-route | jq '.routes[] | select(.table == "main")'

# Pipe to other tools
sudo netmon-neighbor --summary
```

## Documentation

- Full README: See README.md
- PyPI Upload Guide: See PYPI_UPLOAD.md
- Contributing: See CONTRIBUTING.md
- Examples: Check the examples/ directory

## Support

- GitHub Issues: https://github.com/hcoin/netmon/issues
- Email: hcoin@quietfountain.com

## License

MIT License - See LICENSE file for details
