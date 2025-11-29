# Changelog

All notable changes to the netsnap project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-21

### Added
- Initial release of netsnap package
- Network device and address information tool (`device_info`)
  - Complete RTNetlink support for interface queries
  - WireGuard interface support via Generic Netlink
  - Bridge configuration and STP status
  - DPLL pin information support
  - Comprehensive attribute decoding (100+ interface attributes)
  - IPv4 and IPv6 address information with readiness computation
  
- Routing table information tool (`route_info`)
  - IPv4 and IPv6 route queries
  - Support for multiple routing tables
  - Multipath route (ECMP) support
  - Route metrics and protocols
  - Route types and scopes
  
- Neighbor table information tool (`neighbor_info`)
  - IPv4 ARP cache entries
  - IPv6 Neighbor Discovery (NDP) cache
  - Bridge FDB (Forwarding Database) entries
  - All neighbor states (REACHABLE, STALE, DELAY, PROBE, FAILED, etc.)
  - Hardware address mapping
  
- Multicast database tool (`mdb_info`)
  - Bridge multicast forwarding database
  - Multicast group memberships
  - Port-specific multicast entries
  
- Routing rules tool (`rule_info`)
  - IP routing policy database (RPDB)
  - Rule priorities and actions
  - Source/destination selectors
  - Table routing decisions

### Technical Features
- CFFI-based C integration for direct kernel communication
- Zero-copy netlink message processing
- Comprehensive error handling
- JSON output format for easy integration
- Human-readable summary modes
- Python 3.8+ compatibility
- Support for Python 3.12+ with setuptools requirement

### Documentation
- Comprehensive README with usage examples
- Inline code documentation
- HTML documentation for each tool
- MIT License

## [Unreleased]

### Planned
- Additional netlink family support
- Performance metrics collection
- Historical data tracking
- Configuration file support
- Web dashboard interface
