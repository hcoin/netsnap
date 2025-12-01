# NetSnap - Linux Network Monitoring Toolkit

A comprehensive package for pulling nearly all details of Linux networking into reliable and broadly usable form.  From configuration to statistics, NetSnap uses the fastest available api: RTNetlink and Generic Netlink. NetSnap can fuction in either standalone fashion generating JSON output, or provide Python 3.8+ objects.  NetSnap provides deep visibility into network interfaces, routing tables, neighbor tables, multicast databases, and routing rules through direct kernel communication via CFFI. More maintainable than alternatives as NetSnap avoids any hard-coded duplication of numeric constants.  This improves NetSnap's portability and maintainability across distros and kernel releases since the kernel running on each system is the 'single source of truth' for all symbolic definitions.

In use cases where network configuration changes happen every second or less, where snapshots are not enough as each change must be tracked in real time, or one-time-per-new-kernel CFFI recompile time is too expensive, consider alternatives such as pyroute2. 

## Features

- **Network Interfaces & Addresses** (`netsnap-device`)
  - Complete interface information (physical, virtual, bridge, VLAN, WireGuard, etc.)
  - IPv4 and IPv6 address details with scope and flags
  - Bridge port configuration and STP status
  - WireGuard interface details via Generic Netlink
  - DPLL (Digital Phase-Locked Loop) pin information
  - Interface statistics and capabilities
  - MTU, MAC addresses, and link states

- **Routing Tables** (`netsnap-route`)
  - IPv4 and IPv6 routing tables
  - Main, local, and custom routing tables
  - Gateway, destination, and source addresses
  - Route metrics, preferences, and protocols
  - Multipath routes (ECMP) support
  - Route types (UNICAST, LOCAL, BROADCAST, MULTICAST, etc.)

- **Neighbor Tables** (`netsnap-neighbor`)
  - IPv4 ARP cache entries
  - IPv6 Neighbor Discovery (NDP) cache
  - Bridge FDB (Forwarding Database) entries
  - Neighbor states (REACHABLE, STALE, DELAY, PROBE, FAILED, etc.)
  - Hardware addresses and interface mappings
  - Proxy entries and router flags

- **Multicast Database** (`netsnap-mdb`)
  - Bridge multicast forwarding database
  - Multicast group memberships
  - Port-specific multicast entries

- **Routing Rules** (`netsnap-rule`)
  - IP routing policy database (RPDB)
  - Rule priorities and actions
  - Source/destination selectors
  - Table routing decisions

## Installation

### From PyPI

```bash
pip install netsnap
```

### From Source

```bash
git clone https://github.com/hcoin/netsnap.git
cd netsnap
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/hcoin/netsnap.git
cd netsnap
pip install -e ".[dev]"
```

## Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux (kernel 2.6+)
- **Privileges**: Root/sudo access for network queries
- **Dependencies**:
  - cffi >= 1.0.0
  - setuptools >= 61.0

## Usage

To display all information, the commands require root privileges as they interact with kernel
netlink sockets.  However, partial information is returned when run with lesser privilege.  

### Show everything in JSON
```bash
sudo netsnap-snapnet
```


### Network Interfaces and Addresses

```bash
# Full JSON output of all interfaces and addresses
sudo netsnap-device

# Show extended interface details
sudo netsnap-device --extended

# Show detailed address information
sudo netsnap-device --addresses

# Show only WireGuard interfaces
sudo netsnap-device --wireguard

# Show summary of special interfaces
sudo netsnap-device --summary

```

### Routing Tables

```bash
# Full routing table in JSON
sudo netsnap-route

# Human-readable summary
sudo netsnap-route --summary

# IPv4 routes only
sudo netsnap-route --ipv4

# IPv6 routes only
sudo netsnap-route --ipv6

# Specific routing table
sudo netsnap-route --table main

# Disable unknown attribute collection
sudo netsnap-route --no-unknown-attrs
```

### Neighbor Tables

```bash
# Full neighbor table in JSON
sudo netsnap-neighbor

# Human-readable summary
sudo netsnap-neighbor --summary

# IPv4 ARP entries only
sudo netsnap-neighbor --arp

# IPv6 NDP entries only
sudo netsnap-neighbor --ndp

# Bridge FDB entries only
sudo netsnap-neighbor --bridge

# Filter by interface
sudo netsnap-neighbor --interface eth0
```

### Multicast Database

```bash
# Full multicast database in JSON
sudo netsnap-mdb

# Human-readable summary
sudo netsnap-mdb --summary

# Filter by interface
sudo netsnap-mdb --interface br0
```

### Routing Rules

```bash
# Full routing rules in JSON
sudo netsnap-rule

# Human-readable summary
sudo netsnap-rule --summary

# IPv4 rules only
sudo netsnap-rule --ipv4

# IPv6 rules only
sudo netsnap-rule --ipv6
```

## Python API

You can also use NetSnap programmatically in your Python code:

```python
from netsnap import device_info, route_info, neighbor_info

# Get all network interfaces
interfaces = device_info.get_interfaces()

# Get routing table
routes = route_info.get_routes()

# Get neighbor table
neighbors = neighbor_info.get_neighbors()
```

## Output Format

All tools output JSON by default for easy parsing and integration with other tools. The JSON structure includes:

- Metadata (timestamp, hostname, kernel version)
- Summary statistics
- Detailed entries with all available attributes
- Human-readable flags and enumerations

Example output structure:

```json
  "enp4s0": {
    "index": 2,
    "type": 1,
    "type_name": "ether",
    "mtu": 1500,
    "mac": "04:d4:c4:11:22:33",
    "operstate": 6,
    "operstate_name": "up",
    "flags": 69699,
    "flag_names": [
      "UP",
      "BROADCAST",
      "RUNNING",
      "MULTICAST",
      "LOWER_UP"
    ],
    "stats": {
      "rx_packets": 48184591,
      "tx_packets": 10588809,
      "rx_bytes": 31814972571,
      "tx_bytes": 1809544839,
      "rx_errors": 0,
      "tx_errors": 0,
       ...
      "is_64bit": true
    },
    "addresses": [
      {
        "family": "ipv4",
        "address": "10.12.119.1",
        "prefixlen": 20,
        "scope": 0,
        "scope_name": "universe",
        "flags": 0,
        "flag_names": [
          "NOPREFIXROUTE"
        ],
        "ipinterface": "10.12.119.1/20",
        "network": "10.12.112.0/20",
        "netmask": "255.255.240.0",
        "hostmask": "0.0.15.255",
        "is_secondary": false,
        "local": "10.12.119.1",
        "broadcast": "10.12.127.255",
        "label": "enp4s0",
        "cacheinfo": {
          "preferred_lft": 7660,
          "valid_lft": 7660,
          "created_tstamp": 1853,
          "updated_tstamp": 41251844,
          "preferred_lft_str": "7660s",
          "valid_lft_str": "7660s"
        },
        "extended_flags": 512,
        "readiness": "ready"
      },
      {
        "family": "ipv6",
        "address": "fc00:1002:c79::1",
        "prefixlen": 128,
        "scope": 0,
        "scope_name": "universe",
        "flags": 0,
        "flag_names": [
          "NOPREFIXROUTE"
        ],
        "ipinterface": "fc00:1002:c79::1/128",
        "network": "fc00:1002:c79::1/128",
        "netmask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "hostmask": "::",
        "is_temporary": false,
        "label": "",
        "cacheinfo": {
          "preferred_lft": 10482,
          "valid_lft": 10482,
          "created_tstamp": 2330,
          "updated_tstamp": 41534079,
          "preferred_lft_str": "10482s",
          "valid_lft_str": "10482s"
        },
        "extended_flags": 512,
        "readiness": "ready"
      },
      ...

```

## Technical Details

### Architecture

NetSnap uses CFFI (C Foreign Function Interface) to compile and execute C code that directly communicates with the Linux kernel via Netlink sockets. This approach provides:

- **Performance**: Direct system calls without subprocess overhead
- **Completeness**: Access to all kernel networking attributes
- **Type Safety**: C-level type checking and memory management
- **Portability**: Works across different Linux distributions

### Netlink Protocols

The package implements the following Netlink protocols:

- **RTNetlink (NETLINK_ROUTE)**: Routing, interfaces, addresses, neighbors
- **Generic Netlink**: WireGuard interface information
- **DPLL Netlink**: Hardware time synchronization

### Supported Kernel Features

- Interface types: physical, VLAN, bridge, bond, veth, WireGuard, tunnel, etc.
- Bridge STP, multicast snooping, netfilter integration
- IPv4 and IPv6 routing with ECMP support
- ARP, NDP, and bridge FDB
- Multicast group management
- Policy-based routing rules

## Security Considerations

- **Root Access**: All netsnap commands require root/sudo privileges to query kernel networking state
- **Read-Only**: NetSnap only reads network configuration; it never modifies kernel state
- **System Impact**: Minimal performance impact; queries complete in milliseconds

## Troubleshooting

### Permission Denied

```bash
# Error: Permission denied when opening netlink socket
# Solution: Run with sudo
sudo netsnap-device
```

### Python Version Error

```bash
# Error: Python 3.8 or higher is required
# Solution: Upgrade Python
python3 --version  # Check current version
```

### CFFI Compilation Error

```bash
# Error: cffi compilation failed
# Solution: Install development headers
sudo apt-get install python3-dev gcc  # Debian/Ubuntu
sudo yum install python3-devel gcc    # RHEL/CentOS
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest features.

### Development Setup

```bash
git clone https://github.com/hcoin/netsnap.git
cd netsnap
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black netsnap/

# Type checking
mypy netsnap/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on top of Linux kernel Netlink protocols
- Uses CFFI for efficient C integration
- Inspired by the need for comprehensive network monitoring on Linux systems

## Author

Harry Coin <hcoin@quietfountain.com>

## Version History

- **1.0.0** (2025-11-21): Initial release
  - Complete RTNetlink support for interfaces, addresses, routes, neighbors
  - Generic Netlink support for WireGuard
  - Multicast database and routing rules
  - DPLL pin information support
  - Comprehensive bridge and STP support
# netsnap
