# snapnet Example Output

## Sample JSON Structure

```json
{
  "devices": {
    "lo": {
      "index": 1,
      "name": "lo",
      "type": 772,
      "type_name": "LOOPBACK",
      "flags": 65609,
      "flag_names": ["UP", "LOOPBACK", "RUNNING", "LOWER_UP"],
      "mtu": 65536,
      "operstate": 0,
      "operstate_name": "UNKNOWN",
      "addresses": [
        {
          "family": "ipv4",
          "address": "127.0.0.1",
          "prefixlen": 8,
          "scope": 254,
          "scope_name": "host",
          "flags": 128,
          "flag_names": ["PERMANENT"]
        }
      ]
    },
    "eth0": {
      "index": 2,
      "name": "eth0",
      "type": 1,
      "type_name": "ETHER",
      "flags": 4099,
      "flag_names": ["UP", "BROADCAST", "RUNNING", "MULTICAST"],
      "mtu": 1500,
      "operstate": 6,
      "operstate_name": "UP",
      "link_type": "ether",
      "address": "00:11:22:33:44:55",
      "broadcast": "ff:ff:ff:ff:ff:ff",
      "addresses": [
        {
          "family": "ipv4",
          "address": "192.168.1.100",
          "prefixlen": 24,
          "broadcast": "192.168.1.255",
          "scope": 0,
          "scope_name": "global",
          "flags": 128,
          "flag_names": ["PERMANENT"]
        },
        {
          "family": "ipv6",
          "address": "fe80::211:22ff:fe33:4455",
          "prefixlen": 64,
          "scope": 253,
          "scope_name": "link",
          "flags": 128,
          "flag_names": ["PERMANENT"]
        }
      ]
    },
    "wg0": {
      "index": 5,
      "name": "wg0",
      "type": 65534,
      "type_name": "NONE",
      "flags": 4097,
      "flag_names": ["UP", "RUNNING"],
      "mtu": 1420,
      "operstate": 0,
      "operstate_name": "UNKNOWN",
      "kind": "wireguard",
      "wireguard": {
        "listen_port": 51820,
        "fwmark": 0,
        "public_key": "ABC123...",
        "peers": [
          {
            "public_key": "XYZ789...",
            "endpoint": "203.0.113.1:51820",
            "latest_handshake": 1234567890,
            "rx_bytes": 1048576,
            "tx_bytes": 2097152,
            "persistent_keepalive": 25,
            "allowed_ips": [
              "10.0.0.0/24",
              "192.168.100.0/24"
            ]
          }
        ]
      }
    }
  },
  "routes": [
    {
      "family": "ipv4",
      "dst": "0.0.0.0/0",
      "gateway": "192.168.1.1",
      "dev": "eth0",
      "protocol": "boot",
      "scope": "universe",
      "type": "unicast",
      "flags": 0,
      "table": 254,
      "table_name": "main"
    },
    {
      "family": "ipv4",
      "dst": "192.168.1.0/24",
      "dev": "eth0",
      "protocol": "kernel",
      "scope": "link",
      "src": "192.168.1.100",
      "type": "unicast",
      "flags": 0,
      "table": 254,
      "table_name": "main"
    },
    {
      "family": "ipv6",
      "dst": "fe80::/64",
      "dev": "eth0",
      "protocol": "kernel",
      "metric": 256,
      "type": "unicast",
      "flags": 0,
      "table": 254,
      "table_name": "main"
    }
  ],
  "neighbors": [
    {
      "ifindex": 2,
      "ifname": "eth0",
      "family": "ipv4",
      "state": 2,
      "state_name": "REACHABLE",
      "flags": 0,
      "flag_names": [],
      "type": 1,
      "type_name": "ETHER",
      "dst": "192.168.1.1",
      "lladdr": "aa:bb:cc:dd:ee:ff",
      "cacheinfo": {
        "confirmed": 123,
        "used": 45,
        "updated": 123
      }
    },
    {
      "ifindex": 2,
      "ifname": "eth0",
      "family": "ipv6",
      "state": 2,
      "state_name": "REACHABLE",
      "flags": 128,
      "flag_names": ["ROUTER"],
      "type": 1,
      "type_name": "ETHER",
      "dst": "fe80::aabb:ccff:fedd:eeff",
      "lladdr": "aa:bb:cc:dd:ee:ff"
    }
  ],
  "mdb": [
    {
      "ifindex": 3,
      "dev": "br0",
      "family": "ipv4",
      "addr": "224.0.0.1",
      "state": 0,
      "state_name": "permanent",
      "flags": 0
    },
    {
      "ifindex": 3,
      "dev": "br0",
      "family": "ipv6",
      "addr": "33:33:00:00:00:01",
      "state": 0,
      "state_name": "permanent",
      "flags": 0
    }
  ],
  "rules": [
    {
      "family": "ipv4",
      "priority": 0,
      "action": "to-table",
      "table": 255,
      "table_name": "local",
      "flags": 0
    },
    {
      "family": "ipv4",
      "priority": 32766,
      "action": "to-table",
      "table": 254,
      "table_name": "main",
      "flags": 0
    },
    {
      "family": "ipv4",
      "priority": 32767,
      "action": "to-table",
      "table": 253,
      "table_name": "default",
      "flags": 0
    },
    {
      "family": "ipv6",
      "priority": 0,
      "action": "to-table",
      "table": 255,
      "table_name": "local",
      "flags": 0
    }
  ],
  "_metadata": {
    "version": "2.0.1",
    "python_version": "3.12.3"
  }
}
```

## Compact Output (Default)

When run without `--pretty`, output is compact (single line):

```json
{"devices":{"lo":{...},"eth0":{...}},"routes":[...],"neighbors":[...],"mdb":[...],"rules":[...], "_metadata":{"version":"2.0.1","python_version":"3.12.3"}}
```

## With Errors

If some modules fail:

```json
{
  "devices": {...},
  "routes": [],
  "neighbors": [...],
  "mdb": [],
  "rules": [...],
  "_metadata": {
    "version": "2.0.1",
    "python_version": "3.12.3",
    "errors": [
      "route_info: Permission denied",
      "mdb_info: Permission denied"
    ]
  }
}
```

## Without Metadata

With `--no-metadata` option:

```json
{
  "devices": {...},
  "routes": [...],
  "neighbors": [...],
  "mdb": [...],
  "rules": [...]
}
```

## Field Descriptions

### devices Section
- Dictionary keyed by interface name
- Each device has: index, name, type, flags, MTU, state, addresses
- WireGuard devices include `wireguard` section with peers
- Bridge devices include `bridge_config` section
- VLAN devices include `vlan` section

### routes Section
- Array of route objects
- Each route has: family, destination, gateway, device, protocol
- Includes all routing tables (main, local, default, custom)
- Both IPv4 and IPv6 routes

### neighbors Section
- Array of neighbor objects
- Each neighbor has: interface, family, destination, MAC, state
- Includes ARP (IPv4), NDP (IPv6), and FDB (bridge) entries
- State information (REACHABLE, STALE, etc.)

### mdb Section
- Array of multicast database entries
- Each entry has: interface, family, address, state
- Shows multicast forwarding for bridges

### rules Section
- Array of policy routing rules
- Each rule has: family, priority, action, table
- Shows FIB rules for all families

### _metadata Section
- `version` - SnapNet version
- `python_version` - Python version
- `errors` - Array of errors (if any occurred)

## Size Examples

### Small Network (Laptop)
```
Devices: 3 (lo, wlan0, docker0)
Routes: 15
Neighbors: 5
MDB: 0
Rules: 6
JSON size: ~12 KB
```

### Medium Network (Server)
```
Devices: 8 (lo, eth0, eth1, br0, multiple veths)
Routes: 50
Neighbors: 30
MDB: 10
Rules: 6
JSON size: ~60 KB
```

### Large Network (Router/Gateway)
```
Devices: 50+ (many VLANs, bridges, tunnels)
Routes: 500+
Neighbors: 200+
MDB: 50
Rules: 20
JSON size: ~800 KB
```

## Processing Examples

### Extract Counts

```bash
sudo snapnet | jq '{
  devices: (.devices | length),
  routes: (.routes | length),
  neighbors: (.neighbors | length),
  mdb: (.mdb | length),
  rules: (.rules | length)
}'
```

Output:
```json
{
  "devices": 3,
  "routes": 15,
  "neighbors": 5,
  "mdb": 0,
  "rules": 6
}
```

### List Interface Names

```bash
sudo snapnet | jq -r '.devices | keys[]'
```

Output:
```
lo
eth0
wlan0
```

### Get IPv4 Addresses

```bash
sudo snapnet | jq -r '.devices[].addresses[]? | select(.family == "ipv4") | "\(.address)/\(.prefixlen)"'
```

Output:
```
127.0.0.1/8
192.168.1.100/24
```

### Find Gateway

```bash
sudo snapnet | jq -r '.routes[] | select(.dst == "0.0.0.0/0") | .gateway'
```

Output:
```
192.168.1.1
```

### Count by Neighbor State

```bash
sudo snapnet | jq '.neighbors | group_by(.state_name) | map({state: .[0].state_name, count: length})'
```

Output:
```json
[
  {"state": "REACHABLE", "count": 3},
  {"state": "STALE", "count": 2}
]
```
