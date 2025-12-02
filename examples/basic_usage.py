#!/usr/bin/env python3
"""
Example: Basic usage of NetSnap package

This example demonstrates the three socket management patterns available
in the netsnap package:
  - Pattern 1: Direct call (recommended for single queries)
  - Pattern 2: Context manager (recommended for multiple queries in one function)
  - Pattern 3: Manual management (recommended for class instances with multiple queries)

Note: Pattern 3 (manual socket management with open()/close()) is currently 
supported by these query classes:
  - RoutingTableQuery (route_info)
  - NeighborTableQuery (neighbor_info)
  - RoutingRuleQuery (rule_info)
  - MDBQuery (mdb_info)

RTNetlinkQuery (device_info) currently uses Pattern 1 only (direct call with 
auto-managed sockets per call).

IMPORTANT: Pattern 3 opens multiple netlink sockets simultaneously, which may
require elevated privileges or hit system resource limits. Patterns 1 and 2 are
recommended for most use cases as they manage socket lifecycle automatically.
"""

import json
import sys

def pattern1_single_query():
    """Pattern 1: Direct Call - Recommended for single queries"""
    print("\nPattern 1: Direct Call (Single Query)")
    print("-" * 70)
    
    from netsnap.device_info import RTNetlinkQuery
    
    # Socket automatically opened and closed
    rtq = RTNetlinkQuery()
    interfaces = rtq.get_interfaces()
    
    print(f"Found {len(interfaces)} network interfaces")
    for if_name in list(interfaces.keys())[:3]:
        if_info = interfaces[if_name]
        print(f"  {if_name}: {if_info.get('operstate_name', 'unknown')}")

def pattern2_multiple_queries():
    """Pattern 2: Context Manager - Recommended for multiple queries in one function"""
    print("\nPattern 2: Context Manager (Multiple Queries in Function)")
    print("-" * 70)
    
    from netsnap.route_info import RoutingTableQuery
    
    # Socket opened on entry, closed on exit
    # Example: Query both IPv4 and IPv6 routes efficiently
    with RoutingTableQuery() as rt_query:
        ipv4_routes = rt_query.get_routes(family='ipv4')
        ipv6_routes = rt_query.get_routes(family='ipv6')
    
    print(f"Gathered {len(ipv4_routes)} IPv4 routes, {len(ipv6_routes)} IPv6 routes")
    
    # Show first route if available
    if ipv4_routes:
        first_route = ipv4_routes[0]
        print(f"\nFirst IPv4 route:")
        print(f"  Destination: {first_route.get('dst', 'default')}")
        print(f"  Gateway: {first_route.get('gateway', 'none')}")
        print(f"  Protocol: {first_route.get('protocol', 'unknown')}")

def pattern3_class_example():
    """Pattern 3: Manual Management - Recommended for class instances"""
    print("\nPattern 3: Manual Socket Management (Class Instance)")
    print("-" * 70)
    
    class NetworkMonitor:
        """
        Example class that maintains query objects.
        
        Note: Opening multiple netlink sockets simultaneously may require
        elevated privileges or hit resource limits. For production use,
        consider opening sockets only when needed.
        """
        
        def __init__(self):
            from netsnap.route_info import RoutingTableQuery
            from netsnap.neighbor_info import NeighborTableQuery
            
            # Use just two query objects to avoid resource limits
            self.rt_query = RoutingTableQuery()
            self.ntq = NeighborTableQuery()
            
            # Open sockets
            self.rt_query.open()
            self.ntq.open()
        
        def get_route_summary(self):
            """Get route summary - reusing open socket"""
            ipv4_routes = self.rt_query.get_routes(family='ipv4')
            ipv6_routes = self.rt_query.get_routes(family='ipv6')
            return {
                'ipv4': len(ipv4_routes),
                'ipv6': len(ipv6_routes)
            }
        
        def get_neighbor_summary(self):
            """Get neighbor summary - reusing open socket"""
            arp_cache = self.ntq.get_neighbors(family='ipv4')
            ndp_cache = self.ntq.get_neighbors(family='ipv6')
            bridge_fdb = self.ntq.get_neighbors(family='bridge')
            return {
                'arp': len(arp_cache),
                'ndp': len(ndp_cache),
                'fdb': len(bridge_fdb)
            }
        
        def close(self):
            """Close all sockets - don't forget this!"""
            self.rt_query.close()
            self.ntq.close()
        
        def __del__(self):
            """Cleanup on destruction"""
            try:
                self.close()
            except:
                pass  # Already closed or never opened
    
    # Use the monitor class
    try:
        monitor = NetworkMonitor()
    except RuntimeError as e:
        print(f"⚠ Pattern 3 requires elevated privileges or hit resource limits")
        print(f"  Error: {e}")
        print(f"  Consider using Pattern 1 or Pattern 2 for most use cases")
        return
    
    try:
        route_summary = monitor.get_route_summary()
        neighbor_summary = monitor.get_neighbor_summary()
        
        print(f"Routes: {route_summary['ipv4']} IPv4, {route_summary['ipv6']} IPv6")
        print(f"  (Made 2 queries reusing same socket)")
        print(f"Neighbors: {neighbor_summary['arp']} ARP, {neighbor_summary['ndp']} NDP, {neighbor_summary['fdb']} FDB")
        print(f"  (Made 3 queries reusing same socket)")
    finally:
        # Always close sockets
        monitor.close()

def main():
    print("NetSnap Package Usage Examples")
    print("=" * 70)
    print("\nDemonstrating three socket management patterns:\n")
    
    try:
        # Pattern 1: Single query
        pattern1_single_query()
        
        # Pattern 2: Multiple queries in one function
        pattern2_multiple_queries()
        
        # Pattern 3: Class instance with manual management
        pattern3_class_example()
        
        print("\n" + "=" * 70)
        print("✓ All patterns demonstrated successfully!")
        print("\nChoose the pattern that fits your use case:")
        print("  • Pattern 1: Quick single queries")
        print("  • Pattern 2: Multiple queries in a function (recommended)")
        print("  • Pattern 3: Long-lived objects making repeated queries")
        print("\nNote: Pattern 3 opens multiple sockets simultaneously, which may")
        print("      require elevated privileges. Patterns 1 & 2 are recommended")
        print("      for most use cases.")
        
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