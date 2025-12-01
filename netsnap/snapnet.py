#!/usr/bin/env python3
"""
SnapNet - Comprehensive Network Snapshot Tool

Captures complete network configuration including:
- Network devices/interfaces (addresses, state, WireGuard, bridges, etc.)
- Routing tables (IPv4, IPv6, all tables)
- Neighbor tables (ARP, NDP, FDB)
- Multicast database (bridge MDB entries)
- Policy routing rules

Requirements:
    - Python 3.8+
    - cffi>=1.0.0
    - Root/sudo access for full information

Usage:
    sudo snapnet                    # Full network snapshot as JSON
    sudo snapnet --help             # Show help
    snapnet --version               # Show version
"""

import sys
import json
import argparse
from typing import Dict, Any

__version__ = "2.0.1"

# Check Python version
if sys.version_info < (3, 8):
    print("Error: Python 3.8 or higher is required", file=sys.stderr)
    sys.exit(1)


def get_version() -> str:
    """Get SnapNet version"""
    return __version__


def capture_network_snapshot(capture_unknown_attrs) -> Dict[str, Any]:
    """
    Capture complete network snapshot from all SnapNet modules.
    
    Returns:
        Dictionary containing all network information
    """
    snapshot = {}
    errors = []
    
    # Capture device information
    try:
        from netsnap import device_info
        with device_info.RTNetlinkQuery(capture_unknown_attrs) as rtq:
            snapshot['devices'] = rtq.get_interfaces()
    except Exception as e:
        snapshot['devices'] = {}
        errors.append(f"device_info: {str(e)}")
    
    # Capture routing information
    try:
        from netsnap import route_info
        with route_info.RoutingTableQuery(capture_unknown_attrs) as rtq:
            snapshot['routes'] = rtq.get_routes()
    except Exception as e:
        snapshot['routes'] = []
        errors.append(f"route_info: {str(e)}")
    
    # Capture neighbor information
    try:
        from netsnap import neighbor_info
        with neighbor_info.NeighborTableQuery(capture_unknown_attrs) as ntq:
            snapshot['neighbors'] = ntq.get_neighbors()
    except Exception as e:
        snapshot['neighbors'] = []
        errors.append(f"neighbor_info: {str(e)}")
    
    # Capture multicast database information
    try:
        from netsnap import mdb_info
        with mdb_info.MDBQuery(capture_unknown_attrs) as mtq:
            snapshot['mdb'] = mtq.get_mdb()
    except Exception as e:
        snapshot['mdb'] = []
        errors.append(f"mdb_info: {str(e)}")
    
    # Capture routing rules information
    try:
        from netsnap import rule_info
        with rule_info.RoutingRuleQuery(capture_unknown_attrs) as rtq:
            snapshot['rules'] = rtq.get_rules()
    except Exception as e:
        snapshot['rules'] = []
        errors.append(f"rule_info: {str(e)}")
    
    # Add metadata
    snapshot['_metadata'] = {
        'version': get_version(),
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }
    
    # Add errors if any occurred
    if errors:
        snapshot['_metadata']['errors'] = errors
    
    return snapshot


def main() -> int:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        prog='snapnet',
        description='Comprehensive network snapshot tool - captures complete network configuration',
        epilog='Note: Run with sudo/root for complete information',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--version','-v', action='version',
                        version=f'snapnet {get_version()}')
    
    parser.add_argument('--compact','-c', action='store_true',
                        help='Compact JSON output (default: pretty-print)')
    
    parser.add_argument('--no-metadata', action='store_true',
                        help='Exclude metadata from output')

    parser.add_argument('--unknown',"-u", action='store_true',
                        help='Include unknown / new kernel attributes in output')
    
    args = parser.parse_args()
    
    try:
        # Capture network snapshot
        snapshot = capture_network_snapshot(args.unknown)
        
        # Remove metadata if requested
        if args.no_metadata and '_metadata' in snapshot:
            del snapshot['_metadata']
        
        # Output JSON
        if not args.compact:
            print(json.dumps(snapshot, indent=2, sort_keys=False))
        else:
            print(json.dumps(snapshot, separators=(',', ':')))
        
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
