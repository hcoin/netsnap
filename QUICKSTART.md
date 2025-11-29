# NetSnap - Quick Start Guide

## What is NetSnap?

NetSnap is a comprehensive Python package for monitoring Linux network subsystems using RTNetlink and Generic Netlink protocols. It provides powerful command-line tools for inspecting network interfaces, routing tables, neighbor tables (ARP/NDP), multicast databases, and routing rules.

## Installation

### From PyPI (Recommended)

Once published to PyPI:

```bash
pip install netsnap
```

### From Source

```bash
# Clone or download the package
cd netsnap

# Install
pip install .

# Or install in development mode
pip install -e .
```

## Basic Usage

All commands require root/sudo privileges:

```bash
# Network interfaces and addresses
sudo netsnap-device

# Routing table
sudo netsnap-route

# Neighbor table (ARP/NDP)
sudo netsnap-neighbor

# Multicast database
sudo netsnap-mdb

# Routing rules
sudo netsnap-rule
```

## Command Examples

### Device Information

```bash
# Full interface information
sudo netsnap-device

# Show only WireGuard interfaces
sudo netsnap-device --wireguard

# Show detailed address information
sudo netsnap-device --addresses

# Show summary of special interfaces
sudo netsnap-device --summary
```

### Routing Information

```bash
# Full routing table
sudo netsnap-route

# Human-readable summary
sudo netsnap-route --summary

# IPv4 routes only
sudo netsnap-route --ipv4

# Specific routing table
sudo netsnap-route --table main
```

### Neighbor Information

```bash
# All neighbor entries
sudo netsnap-neighbor

# Summary view
sudo netsnap-neighbor --summary

# IPv4 ARP only
sudo netsnap-neighbor --arp

# IPv6 NDP only
sudo netsnap-neighbor --ndp

# Filter by interface
sudo netsnap-neighbor --interface eth0
```

## Python API

Use NetSnap programmatically:

```python
from netsnap import device_info

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
sudo netsnap-device > interfaces.json

# Process with jq
sudo netsnap-route | jq '.routes[] | select(.table == "main")'

# Pipe to other tools
sudo netsnap-neighbor --summary
```

## Documentation

- Full README: See README.md
- PyPI Upload Guide: See PYPI_UPLOAD.md
- Contributing: See CONTRIBUTING.md
- Examples: Check the examples/ directory

## Support

- GitHub Issues: https://github.com/hcoin/netsnap/issues
- Email: hcoin@quietfountain.com

## License

MIT License - See LICENSE file for details
