# Changelog

All notable changes to the netsnap project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2025-12-2
### Changed
- example programs to demonstrate various use cases properly.
- added example output of the comprehensive example.
  note all network and mac addresses listed in the public
  example are random.

## [2.2.0] - 2025-12-2
#### Added
- Support for direct calls to class functions, no longer requires
  use of with <class> as foo:
  however if more than one call is anticipated, using the
  'with' construction remains faster.  Note addition of 
  explicit open and close calls if equivalent functionality
  to 'with' is desired but can't be completed within one
  function.
- Refactored documentation for calling conventions.

## [2.1.0] - 2025-12-1
#### Added
- Support for TAP/TUN devices &  attributes in device_info

## [2.0.1] - 2025-11-30
### Changed
- Bugfix: snapnet now imports from the package instead of locally. 

## [2.0.0] - 2025-11-30

### Changed
- When run as a shell command with no arguments, the output is now
  undecorated pure json, ready to parse.  Added -t --text for those
  who want text/decorated output.  Added -j to all commands to
  force / ensure json output (as is often the habit on command
  line utilities).

- Readme now mentions better maintainability dervied from
  using the constants found in the kernel at runtime to map kernel
  responses passed as integers onto the correct symbolic meaning.
  No hard-coded kernel constants in the python code.
  
- added -d <devname> and --device <devname> to device_info to
  filter output to one device.
  
- improved tests, all pass.

### Added

- snapnet.py -- combines all other output into single
  comprehensive json snapshot of the current kernel.
  use snapnet.py -u to include new/unknown kernel
  attributes in the output.
  


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
- Comprehensive snapshot command.


