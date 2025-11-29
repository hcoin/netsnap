#!/usr/bin/env python3
"""
Example: Basic usage of NetSnap package

This example demonstrates how to programmatically use the netsnap package
to query network information.
"""

import json
import sys

def main():
    print("NetSnap Package Usage Example")
    print("=" * 70)
    
    # Note: These modules require root privileges
    try:
        from netsnap import device_info, route_info, neighbor_info
        
        print("\n1. Getting network interfaces...")
        print("-" * 70)
        
        # Create RTNetlink query object
        with device_info.RTNetlinkQuery() as rtq:
            interfaces = rtq.get_interfaces()
        
        # Show basic interface info
        for if_name, if_info in list(interfaces.items())[:3]:  # Show first 3
            print(f"\nInterface: {if_name}")
            print(f"  Index: {if_info.get('index')}")
            print(f"  Type: {if_info.get('kind', 'unknown')}")
            print(f"  State: {if_info.get('operstate_name')}")
            print(f"  MTU: {if_info.get('mtu')}")
            if 'address' in if_info:
                print(f"  MAC: {if_info['address']}")
        
        print("\n" + "=" * 70)
        print("Example complete!")
        print("\nNote: Run with sudo to see actual data")
        print("      sudo python3 examples/basic_usage.py")
        
    except PermissionError:
        print("\n✗ Permission denied: This example requires root privileges")
        print("  Run with: sudo python3 examples/basic_usage.py")
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
