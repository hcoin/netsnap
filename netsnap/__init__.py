"""
NetMon - Comprehensive Linux Network Monitoring Toolkit

A Python package for monitoring Linux network subsystems using RTNetlink
and Generic Netlink protocols.

Modules:
    device_info: Network interfaces and addresses
    route_info: Routing tables
    neighbor_info: Neighbor tables (ARP/NDP/FDB)
    mdb_info: Multicast database
    rule_info: Routing rules

Example:
    >>> from netmon import device_info
    >>> interfaces = device_info.get_interfaces()
"""

__version__ = "1.0.0"
__author__ = "Harry Coin"
__email__ = "hcoin@quietfountain.com"
__license__ = "MIT"

# Import main modules for convenient access
try:
    from . import device_info
    from . import route_info
    from . import neighbor_info
    from . import mdb_info
    from . import rule_info
except ImportError:
    # Modules may not be importable in all contexts (e.g., during build)
    pass

__all__ = [
    "device_info",
    "route_info",
    "neighbor_info",
    "mdb_info",
    "rule_info",
    "__version__",
]
