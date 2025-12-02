#!/usr/bin/env python3
"""
Example: Comprehensive network monitoring with NetSnap

This example demonstrates Pattern 2 (Context Manager) for gathering
complete network information in a monitoring snapshot.

Pattern 2 is ideal here because we're making multiple related queries
within each function scope.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

def gather_network_snapshot():
    """
    Gather complete network information snapshot.
    
    Uses Pattern 2 (Context Manager) for query classes that support it,
    and Pattern 1 (Direct Call) for RTNetlinkQuery.
    
    RTNetlinkQuery methods:
      - get_interfaces(): Returns complete interface information (includes addresses)
    """
    from netsnap.device_info import RTNetlinkQuery
    from netsnap.route_info import RoutingTableQuery
    from netsnap.neighbor_info import NeighborTableQuery
    from netsnap.rule_info import RoutingRuleQuery
    from netsnap.mdb_info import MDBQuery
    
    snapshot = {
        'timestamp': datetime.now().isoformat(),
        'data': {}
    }
    
    print("Gathering network snapshot...")
    print("-" * 70)
    
    # Get interface information using Pattern 1 (Direct Call)
    # RTNetlinkQuery auto-manages socket per call
    print("  ✓ Collecting interface information...")
    rtq = RTNetlinkQuery()
    snapshot['data']['interfaces'] = rtq.get_interfaces()
    
    # Get routing information
    print("  ✓ Collecting routing table...")
    with RoutingTableQuery() as rt_query:
        snapshot['data']['ipv4_routes'] = rt_query.get_routes(family='ipv4')
        snapshot['data']['ipv6_routes'] = rt_query.get_routes(family='ipv6')
    
    # Get neighbor information
    print("  ✓ Collecting neighbor tables...")
    with NeighborTableQuery() as ntq:
        snapshot['data']['arp_cache'] = ntq.get_neighbors(family='ipv4')
        snapshot['data']['ndp_cache'] = ntq.get_neighbors(family='ipv6')
        snapshot['data']['bridge_fdb'] = ntq.get_neighbors(family='bridge')
    
    # Get routing rules
    print("  ✓ Collecting routing rules...")
    with RoutingRuleQuery() as rule_query:
        snapshot['data']['ipv4_rules'] = rule_query.get_rules(family='ipv4')
        snapshot['data']['ipv6_rules'] = rule_query.get_rules(family='ipv6')
    
    # Get multicast database
    print("  ✓ Collecting multicast database...")
    with MDBQuery() as mdb_query:
        snapshot['data']['mdb_entries'] = mdb_query.get_mdb()
    
    return snapshot

def analyze_snapshot(snapshot):
    """Analyze the network snapshot"""
    data = snapshot['data']
    interfaces = data.get('interfaces', {})
    
    print("\nNetwork Analysis:")
    print("=" * 70)
    
    # Interface analysis
    type_counts = {}
    up_count = 0
    down_count = 0
    total_addresses = 0
    
    for if_name, if_info in interfaces.items():
        # Count types
        kind = if_info.get('kind', 'physical')
        type_counts[kind] = type_counts.get(kind, 0) + 1
        
        # Count states
        if if_info.get('operstate_name') == 'up':
            up_count += 1
        else:
            down_count += 1
        
        # Count addresses
        if 'addresses' in if_info:
            total_addresses += len(if_info['addresses'])
    
    print(f"\nInterfaces: {len(interfaces)} total ({up_count} up, {down_count} down)")
    print(f"Addresses: {total_addresses} total")
    
    print("\nInterface Types:")
    for kind, count in sorted(type_counts.items()):
        print(f"  {kind}: {count}")
    
    # Routing information
    ipv4_routes = data.get('ipv4_routes', [])
    ipv6_routes = data.get('ipv6_routes', [])
    print(f"\nRoutes:")
    print(f"  IPv4: {len(ipv4_routes)}")
    print(f"  IPv6: {len(ipv6_routes)}")
    
    # Neighbor information
    arp_cache = data.get('arp_cache', [])
    ndp_cache = data.get('ndp_cache', [])
    bridge_fdb = data.get('bridge_fdb', [])
    print(f"\nNeighbors:")
    print(f"  ARP cache: {len(arp_cache)}")
    print(f"  NDP cache: {len(ndp_cache)}")
    print(f"  Bridge FDB: {len(bridge_fdb)}")
    
    # Routing rules
    ipv4_rules = data.get('ipv4_rules', [])
    ipv6_rules = data.get('ipv6_rules', [])
    print(f"\nRouting Rules:")
    print(f"  IPv4: {len(ipv4_rules)}")
    print(f"  IPv6: {len(ipv6_rules)}")
    
    # Multicast database
    mdb_entries = data.get('mdb_entries', [])
    print(f"\nMulticast Database: {len(mdb_entries)} entries")
    
    # Find special interfaces
    special = {
        'bridges': [],
        'wireguard': [],
        'vlans': [],
        'bonds': []
    }
    
    for if_name, if_info in interfaces.items():
        kind = if_info.get('kind')
        if kind == 'bridge':
            special['bridges'].append(if_name)
        elif kind == 'wireguard':
            special['wireguard'].append(if_name)
        elif kind == 'vlan':
            special['vlans'].append(if_name)
        elif kind == 'bond':
            special['bonds'].append(if_name)
    
    if any(special.values()):
        print("\nSpecial Interfaces:")
        for category, names in special.items():
            if names:
                print(f"  {category.title()}: {', '.join(names)}")

def save_snapshot(snapshot, filename='network_snapshot.json'):
    """Save snapshot to file"""
    output_path = Path(filename)
    with open(output_path, 'w') as f:
        json.dump(snapshot, f, indent=2)
    print(f"\n✓ Snapshot saved to: {output_path.absolute()}")
    
    # Calculate size
    file_size = output_path.stat().st_size
    if file_size > 1024 * 1024:
        size_str = f"{file_size / (1024 * 1024):.2f} MB"
    elif file_size > 1024:
        size_str = f"{file_size / 1024:.2f} KB"
    else:
        size_str = f"{file_size} bytes"
    print(f"  Size: {size_str}")

def main():
    print("NetSnap Comprehensive Monitoring Example")
    print("=" * 70)
    print("\nThis example uses Pattern 2 (Context Manager) for most queries")
    print("and Pattern 1 (Direct Call) for RTNetlinkQuery.\n")
    
    try:
        # Gather snapshot
        snapshot = gather_network_snapshot()
        
        # Analyze
        analyze_snapshot(snapshot)
        
        # Save
        save_snapshot(snapshot)
        
        print("\n" + "=" * 70)
        print("✓ Monitoring complete!")
        print("\nSnapshot includes:")
        print("  • Interfaces (with addresses)")
        print("  • IPv4 and IPv6 routing tables")
        print("  • ARP, NDP, and bridge FDB")
        print("  • Routing rules")
        print("  • Multicast database")
        
    except PermissionError:
        print("\n✗ Permission denied: This example requires root privileges")
        print("  Run with: sudo python3 examples/comprehensive_monitoring.py")
        sys.exit(1)
    except ImportError as e:
        print(f"\n✗ Import error: {e}")
        print("  Install netsnap package first: pip install netsnap")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()