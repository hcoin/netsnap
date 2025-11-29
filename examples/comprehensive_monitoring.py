#!/usr/bin/env python3
"""
Example: Comprehensive network monitoring with NetSnap

This example demonstrates how to gather complete network information
and create a monitoring snapshot.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

def gather_network_snapshot():
    """Gather complete network information snapshot"""
    from netsnap import device_info
    
    snapshot = {
        'timestamp': datetime.now().isoformat(),
        'data': {}
    }
    
    print("Gathering network snapshot...")
    print("-" * 70)
    
    # Get interface and address information
    print("  ✓ Collecting interface information...")
    with device_info.RTNetlinkQuery() as rtq:
        snapshot['data']['interfaces'] = rtq.get_interfaces()
    
    return snapshot

def analyze_snapshot(snapshot):
    """Analyze the network snapshot"""
    interfaces = snapshot['data']['interfaces']
    
    print("\nNetwork Analysis:")
    print("=" * 70)
    
    # Count interface types
    type_counts = {}
    up_count = 0
    down_count = 0
    
    for if_name, if_info in interfaces.items():
        # Count types
        kind = if_info.get('kind', 'physical')
        type_counts[kind] = type_counts.get(kind, 0) + 1
        
        # Count states
        if if_info.get('operstate_name') == 'up':
            up_count += 1
        else:
            down_count += 1
    
    print(f"\nTotal Interfaces: {len(interfaces)}")
    print(f"  Up: {up_count}")
    print(f"  Down: {down_count}")
    
    print("\nInterface Types:")
    for kind, count in sorted(type_counts.items()):
        print(f"  {kind}: {count}")
    
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

def main():
    print("NetSnap Comprehensive Monitoring Example")
    print("=" * 70)
    
    try:
        # Gather snapshot
        snapshot = gather_network_snapshot()
        
        # Analyze
        analyze_snapshot(snapshot)
        
        # Save
        save_snapshot(snapshot)
        
        print("\n" + "=" * 70)
        print("✓ Monitoring complete!")
        
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
