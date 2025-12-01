#!/usr/bin/env python3
"""
RTNetlink Interface Query with C Library via CFFI
Extended with veth, Bridge Port/STP Support, WireGuard Generic Netlink, and DPLL Pin Support

Complete bridge master configuration support including:
- STP timers and status flags
- Multicast snooping (IGMP/MLD)
- Netfilter integration
- VLAN statistics
- Group forwarding

DPLL (Digital Phase-Locked Loop) Pin Support:
- Hardware time synchronization information
- Pin type (MUX, EXT, SYNCE_ETH_PORT, INT_OSCILLATOR, GNSS)
- Pin direction and state
- Frequency and phase adjustment
- Capabilities and priority

Requirements:
    - Python 3.8+
    - cffi>=1.0.0
    - setuptools (required for Python 3.12+)

Install:
    pip install cffi setuptools

Usage:
    sudo python3 device_info.py                 # Full JSON output
    sudo python3 device_info.py --extended      # Show extended interface details
    sudo python3 device_info.py --addresses     # Show detailed address info
    sudo python3 device_info.py --wireguard     # Show only WireGuard interfaces
    sudo python3 device_info.py --summary       # Show summary of special interfaces
    sudo python3 device_info.py -d eth0         # Show only eth0 interface
    sudo python3 device_info.py --device wlan0  # Show only wlan0 interface
    sudo python3 device_info.py -d eth0 --extended  # Show extended info for eth0 only
"""

from cffi import FFI
import json
import sys
#import os
import ipaddress
from typing import Dict, List, Any

# Check Python version
if sys.version_info < (3, 8):
    raise RuntimeError("Python 3.8 or higher is required")

# For Python 3.12+, verify setuptools is available
if sys.version_info >= (3, 12):
    try:
        import setuptools # noqa
    except ImportError:
        raise RuntimeError(
            "Python 3.12+ requires setuptools for CFFI. "
            "Install it with: pip install setuptools"
        )
# C library source code - WITH GENERIC NETLINK SUPPORT FOR WIREGUARD
C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <errno.h>

// Netlink attribute type flags
#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK (~(NLA_F_NESTED | NLA_F_NET_BYTEORDER))
#endif

// Verify we have minimum required kernel headers
#if !defined(NETLINK_ROUTE) || !defined(RTM_GETLINK) || !defined(RTM_GETADDR)
#error "Kernel headers too old - need Linux 2.6+ with rtnetlink support"
#endif

// Response buffer structure
typedef struct {
    unsigned char* data;
    size_t length;
    size_t capacity;
    unsigned int seq;
} response_buffer_t;

// Bridge port information
typedef struct {
    int has_bridge_info;
    unsigned char state;
    unsigned short priority;
    unsigned int cost;
    unsigned char mode;
    unsigned char guard;
    unsigned char protect;
    unsigned char fast_leave;
    unsigned char learning;
    unsigned char unicast_flood;
    unsigned char proxyarp;
    unsigned char proxyarp_wifi;
    unsigned char multicast_router;
    unsigned char mcast_to_ucast;
    unsigned char mcast_flood;
    unsigned char bcast_flood;
    unsigned short group_fwd_mask;
    unsigned char neigh_suppress;
    unsigned char isolated;
    unsigned char mrp_ring_open;
    unsigned char mrp_in_open;
    unsigned int mcast_eht_hosts_limit;
    unsigned int mcast_eht_hosts_cnt;
    unsigned char locked;
    unsigned char mab;
    unsigned int mcast_n_groups;
    unsigned int mcast_max_groups;
    unsigned char neigh_vlan_suppress;
    unsigned char root_id[8];
    unsigned char bridge_id[8];
    unsigned short designated_port;
    unsigned int designated_cost;
    unsigned short port_id;
    unsigned short port_no;
    unsigned char topology_change_ack;
    unsigned char config_pending;
    unsigned long long message_age_timer;
    unsigned long long forward_delay_timer;
    unsigned long long hold_timer;
    unsigned char vlan_tunnel;
    int has_priority;
    int has_cost;
    int has_mode;
    int has_guard;
    int has_protect;
    int has_fast_leave;
    int has_learning;
    int has_unicast_flood;
    int has_proxyarp;
    int has_proxyarp_wifi;
    int has_multicast_router;
    int has_mcast_to_ucast;
    int has_mcast_flood;
    int has_bcast_flood;
    int has_group_fwd_mask;
    int has_neigh_suppress;
    int has_isolated;
    int has_mrp_ring_open;
    int has_mrp_in_open;
    int has_mcast_eht_hosts_limit;
    int has_mcast_eht_hosts_cnt;
    int has_locked;
    int has_mab;
    int has_mcast_n_groups;
    int has_mcast_max_groups;
    int has_neigh_vlan_suppress;
    int has_root_id;
    int has_bridge_id;
    int has_designated_port;
    int has_designated_cost;
    int has_port_id;
    int has_port_no;
    int has_topology_change_ack;
    int has_config_pending;
    int has_message_age_timer;
    int has_forward_delay_timer;
    int has_hold_timer;
    int has_vlan_tunnel;
    unsigned short unknown_attrs[64];
    int unknown_attrs_count;
    int data_source_priority;
} bridge_port_info_t;
// Bridge master configuration - UPDATED WITH ALL NEW ATTRIBUTES
typedef struct {
    int has_bridge_config;
    unsigned int stp_enabled;
    unsigned int forward_delay;
    unsigned int hello_time;
    unsigned int max_age;
    unsigned short priority;
    unsigned char root_id[8];
    unsigned char bridge_id[8];
    unsigned short root_port;
    unsigned int root_path_cost;
    unsigned int ageing_time;
    unsigned char vlan_filtering;
    unsigned short vlan_protocol;
    unsigned short vlan_default_pvid;
    unsigned int fdb_n_learned;
    unsigned int fdb_max_learned;
    unsigned short group_fwd_mask;
    unsigned char topology_change;
    unsigned char topology_change_detected;
    unsigned long long hello_timer;
    unsigned long long tcn_timer;
    unsigned long long topology_change_timer;
    unsigned long long gc_timer;
    unsigned char group_addr[6];
    unsigned char mcast_router;
    unsigned char mcast_snooping;
    unsigned char mcast_query_use_ifaddr;
    unsigned char mcast_querier;
    unsigned int mcast_hash_elasticity;
    unsigned int mcast_hash_max;
    unsigned int mcast_last_member_cnt;
    unsigned int mcast_startup_query_cnt;
    unsigned long long mcast_last_member_intvl;
    unsigned long long mcast_membership_intvl;
    unsigned long long mcast_querier_intvl;
    unsigned long long mcast_query_intvl;
    unsigned long long mcast_query_response_intvl;
    unsigned long long mcast_startup_query_intvl;
    unsigned char nf_call_iptables;
    unsigned char nf_call_ip6tables;
    unsigned char nf_call_arptables;
    unsigned char vlan_stats_enabled;
    unsigned char mcast_stats_enabled;
    unsigned char mcast_igmp_version;
    unsigned char mcast_mld_version;
    unsigned char vlan_stats_per_port;
    unsigned long long multi_boolopt;
    int has_stp_enabled;
    int has_forward_delay;
    int has_hello_time;
    int has_max_age;
    int has_priority;
    int has_root_id;
    int has_bridge_id;
    int has_root_port;
    int has_root_path_cost;
    int has_ageing_time;
    int has_vlan_filtering;
    int has_vlan_protocol;
    int has_vlan_default_pvid;
    int has_fdb_n_learned;
    int has_fdb_max_learned;
    int has_group_fwd_mask;
    int has_topology_change;
    int has_topology_change_detected;
    int has_hello_timer;
    int has_tcn_timer;
    int has_topology_change_timer;
    int has_gc_timer;
    int has_group_addr;
    int has_mcast_router;
    int has_mcast_snooping;
    int has_mcast_query_use_ifaddr;
    int has_mcast_querier;
    int has_mcast_hash_elasticity;
    int has_mcast_hash_max;
    int has_mcast_last_member_cnt;
    int has_mcast_startup_query_cnt;
    int has_mcast_last_member_intvl;
    int has_mcast_membership_intvl;
    int has_mcast_querier_intvl;
    int has_mcast_query_intvl;
    int has_mcast_query_response_intvl;
    int has_mcast_startup_query_intvl;
    int has_nf_call_iptables;
    int has_nf_call_ip6tables;
    int has_nf_call_arptables;
    int has_vlan_stats_enabled;
    int has_mcast_stats_enabled;
    int has_mcast_igmp_version;
    int has_mcast_mld_version;
    int has_vlan_stats_per_port;
    int has_multi_boolopt;
} bridge_config_t;

// GENEVE tunnel information
typedef struct {
    unsigned int id;           // VNI (Virtual Network Identifier)
    unsigned int remote;       // Remote IPv4 address
    unsigned char ttl;         // Time to Live
    unsigned char tos;         // Type of Service
    unsigned short port;       // Destination UDP port
    unsigned char collect_metadata;  // Collect metadata mode
    unsigned char remote6[16]; // Remote IPv6 address
    unsigned char udp_csum;    // UDP checksum enabled
    unsigned char udp_zero_csum6_tx;  // Zero checksum IPv6 TX
    unsigned char udp_zero_csum6_rx;  // Zero checksum IPv6 RX
    unsigned int label;        // IPv6 flow label
    unsigned char ttl_inherit; // Inherit TTL from inner packet
    unsigned char df;          // Don't Fragment setting
    unsigned char inner_proto_inherit; // Inherit inner protocol
    int has_id;
    int has_remote;
    int has_ttl;
    int has_tos;
    int has_port;
    int has_collect_metadata;
    int has_remote6;
    int has_udp_csum;
    int has_udp_zero_csum6_tx;
    int has_udp_zero_csum6_rx;
    int has_label;
    int has_ttl_inherit;
    int has_df;
    int has_inner_proto_inherit;
} geneve_info_t;


// WireGuard peer information
typedef struct {
    unsigned char public_key[32];
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned long long last_handshake_time;
    int has_public_key;
    int has_rx_bytes;
    int has_tx_bytes;
    int has_last_handshake;
} wg_peer_info_t;

// WireGuard device information
typedef struct {
    int has_config;
    unsigned char public_key[32];
    unsigned short listen_port;
    unsigned int fwmark;
    int has_public_key;
    int has_listen_port;
    int has_fwmark;
    wg_peer_info_t* peers;
    int peer_count;
} wg_device_info_t;

// DPLL (Digital Phase-Locked Loop) Pin information
typedef struct {
    int has_dpll_pin;
    unsigned long long pin_id;
    unsigned long long parent_id;
    unsigned long long clock_id;
    char module_name[64];
    char board_label[64];
    char panel_label[64];
    char package_label[64];
    unsigned char pin_type;
    unsigned char pin_direction;
    unsigned char pin_state;
    unsigned int pin_capabilities;
    unsigned int pin_priority;
    unsigned long long frequency;
    unsigned long long frequency_min;
    unsigned long long frequency_max;
    long long phase_adjust;
    long long phase_adjust_min;
    long long phase_adjust_max;
    long long phase_offset;
    long long fractional_frequency_offset;
    int has_pin_id;
    int has_parent_id;
    int has_clock_id;
    int has_module_name;
    int has_board_label;
    int has_panel_label;
    int has_package_label;
    int has_pin_type;
    int has_pin_direction;
    int has_pin_state;
    int has_pin_capabilities;
    int has_pin_priority;
    int has_frequency;
    int has_frequency_min;
    int has_frequency_max;
    int has_phase_adjust;
    int has_phase_adjust_min;
    int has_phase_adjust_max;
    int has_phase_offset;
    int has_fractional_frequency_offset;
    unsigned short unknown_attrs[32];
    int unknown_attrs_count;
} dpll_pin_info_t;

// Interface link information
typedef struct {
    int index;
    int type;
    unsigned int flags;
    unsigned int mtu;
    char name[IFNAMSIZ];
    unsigned char mac[6];
    int has_mac;
    unsigned char broadcast[6];
    int has_broadcast;
    unsigned char perm_address[6];
    int has_perm_address;
    unsigned char operstate;
    unsigned char _pad_operstate[3];  // Padding for alignment
    unsigned int txqlen;
    char qdisc[32];
    char ifalias[256];
    char kind[32];
    int has_txqlen;
    int has_qdisc;
    int has_ifalias;
    int has_kind;
    int master_index;
    int has_master;
    int link_index;
    int has_link;
    char parent_dev_name[IFNAMSIZ];
    int has_parent_dev_name;
    int vlan_id;
    int has_vlan_id;
    unsigned int vlan_flags;
    unsigned int vlan_flags_mask;
    int has_vlan_flags;
    unsigned short vlan_protocol;
    unsigned char _pad_vlan_protocol[2];  // Padding for alignment
    int has_vlan_protocol;
    int veth_peer_index;
    int has_veth_peer;
    unsigned int bridge_forward_delay;
    int has_bridge_forward_delay;
    unsigned int tunnel_local;
    unsigned int tunnel_remote;
    int has_tunnel_local;
    int has_tunnel_remote;
    bridge_port_info_t bridge_port;
    bridge_config_t bridge_config;
    wg_device_info_t wireguard;
    geneve_info_t geneve;
    dpll_pin_info_t dpll_pin;
    char slave_kind[32];
    int has_slave_kind;
    unsigned char linkmode;
    unsigned char _pad_linkmode[3];  // Padding for alignment
    int has_linkmode;
    unsigned int min_mtu;
    unsigned int max_mtu;
    int has_min_mtu;
    int has_max_mtu;
    unsigned int group;
    int has_group;
    unsigned int promiscuity;
    int has_promiscuity;
    unsigned int allmulti;
    int has_allmulti;
    unsigned int num_tx_queues;
    unsigned int num_rx_queues;
    int has_num_tx_queues;
    int has_num_rx_queues;
    unsigned int gso_max_segs;
    unsigned int gso_max_size;
    unsigned int gro_max_size;
    unsigned int gso_ipv4_max_size;
    unsigned int gro_ipv4_max_size;
    unsigned int tso_max_size;
    unsigned int tso_max_segs;
    int has_gso_max_segs;
    int has_gso_max_size;
    int has_gro_max_size;
    int has_gso_ipv4_max_size;
    int has_gro_ipv4_max_size;
    int has_tso_max_size;
    int has_tso_max_segs;
    unsigned char carrier;
    unsigned char _pad_carrier[3];  // Padding for alignment
    int has_carrier;
    unsigned int carrier_changes;
    unsigned long long carrier_up_count;
    unsigned long long carrier_down_count;
    int has_carrier_changes;
    int has_carrier_up_count;
    int has_carrier_down_count;
    unsigned char proto_down;
    unsigned char _pad_proto_down[3];  // Padding for alignment
    int has_proto_down;
    unsigned long long map_mem_start;
    unsigned long long map_mem_end;
    unsigned long long map_base_addr;
    unsigned short map_irq;
    unsigned char map_dma;
    unsigned char map_port;
    unsigned char _pad_map[2];  // Padding for alignment (2 bytes to reach 4-byte boundary)
    int has_map;
    unsigned short unknown_ifla_attrs[64];
    int unknown_ifla_attrs_count;
    unsigned short unknown_linkinfo_attrs[64];
    int unknown_linkinfo_attrs_count;
    unsigned short unknown_info_data_attrs[64];
    int unknown_info_data_attrs_count; 
} link_info_t;

// Link statistics
typedef struct {
    unsigned long long rx_packets;
    unsigned long long tx_packets;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned long long rx_errors;
    unsigned long long tx_errors;
    unsigned long long rx_dropped;
    unsigned long long tx_dropped;
    unsigned long long multicast;
    unsigned long long collisions;
    unsigned long long rx_length_errors;
    unsigned long long rx_over_errors;
    unsigned long long rx_crc_errors;
    unsigned long long rx_frame_errors;
    unsigned long long rx_fifo_errors;
    unsigned long long rx_missed_errors;
    unsigned long long tx_aborted_errors;
    unsigned long long tx_carrier_errors;
    unsigned long long tx_fifo_errors;
    unsigned long long tx_heartbeat_errors;
    unsigned long long tx_window_errors;
    unsigned long long rx_compressed;
    unsigned long long tx_compressed;
    unsigned long long rx_nohandler;
    int has_stats64;
} link_stats_t;

// Address information
typedef struct {
    int index;
    unsigned char family;
    unsigned char prefixlen;
    unsigned char flags;
    unsigned char scope;
    unsigned char address[16];
    unsigned char local[16];
    unsigned char broadcast[16];
    int has_local;
    int has_broadcast;
    char label[IFNAMSIZ];
    unsigned int preferred_lft;
    unsigned int valid_lft;
    unsigned int created_tstamp;
    unsigned int updated_tstamp;
    int has_cacheinfo;
    unsigned int extended_flags;
    int has_extended_flags;
    unsigned char protocol;
    int has_protocol;
    unsigned short unknown_ifa_attrs[64];
    int unknown_ifa_attrs_count;
} addr_info_t;

// WireGuard Generic Netlink attribute definitions
#ifndef WGDEVICE_A_UNSPEC
#define WGDEVICE_A_UNSPEC 0
#define WGDEVICE_A_IFINDEX 1
#define WGDEVICE_A_IFNAME 2
#define WGDEVICE_A_PRIVATE_KEY 3
#define WGDEVICE_A_PUBLIC_KEY 4
#define WGDEVICE_A_FLAGS 5
#define WGDEVICE_A_LISTEN_PORT 6
#define WGDEVICE_A_FWMARK 7
#define WGDEVICE_A_PEERS 8
#endif

#ifndef WGPEER_A_UNSPEC
#define WGPEER_A_UNSPEC 0
#define WGPEER_A_PUBLIC_KEY 1
#define WGPEER_A_PRESHARED_KEY 2
#define WGPEER_A_FLAGS 3
#define WGPEER_A_ENDPOINT 4
#define WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL 5
#define WGPEER_A_LAST_HANDSHAKE_TIME 6
#define WGPEER_A_RX_BYTES 7
#define WGPEER_A_TX_BYTES 8
#define WGPEER_A_ALLOWEDIPS 9
#define WGPEER_A_PROTOCOL_VERSION 10
#endif

#ifndef WG_CMD_GET_DEVICE
#define WG_CMD_GET_DEVICE 0
#endif

#ifndef WG_GENL_VERSION
#define WG_GENL_VERSION 1
#endif

// DPLL Pin attribute definitions (from linux/dpll.h)
#ifndef DPLL_A_PIN_ID
#define DPLL_A_PIN_ID 1
#define DPLL_A_PIN_PARENT_ID 2
#define DPLL_A_PIN_MODULE_NAME 3
#define DPLL_A_PIN_PAD 4
#define DPLL_A_PIN_CLOCK_ID 5
#define DPLL_A_PIN_BOARD_LABEL 6
#define DPLL_A_PIN_PANEL_LABEL 7
#define DPLL_A_PIN_PACKAGE_LABEL 8
#define DPLL_A_PIN_TYPE 9
#define DPLL_A_PIN_DIRECTION 10
#define DPLL_A_PIN_FREQUENCY 11
#define DPLL_A_PIN_FREQUENCY_SUPPORTED 12
#define DPLL_A_PIN_FREQUENCY_MIN 13
#define DPLL_A_PIN_FREQUENCY_MAX 14
#define DPLL_A_PIN_PRIO 15
#define DPLL_A_PIN_STATE 16
#define DPLL_A_PIN_CAPABILITIES 17
#define DPLL_A_PIN_PARENT_DEVICE 18
#define DPLL_A_PIN_PARENT_PIN 19
#define DPLL_A_PIN_PHASE_ADJUST_MIN 20
#define DPLL_A_PIN_PHASE_ADJUST_MAX 21
#define DPLL_A_PIN_PHASE_ADJUST 22
#define DPLL_A_PIN_PHASE_OFFSET 23
#define DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET 24
#endif

// DPLL Pin Type
#ifndef DPLL_PIN_TYPE_MUX
#define DPLL_PIN_TYPE_MUX 1
#define DPLL_PIN_TYPE_EXT 2
#define DPLL_PIN_TYPE_SYNCE_ETH_PORT 3
#define DPLL_PIN_TYPE_INT_OSCILLATOR 4
#define DPLL_PIN_TYPE_GNSS 5
#endif

// DPLL Pin Direction
#ifndef DPLL_PIN_DIRECTION_INPUT
#define DPLL_PIN_DIRECTION_INPUT 1
#define DPLL_PIN_DIRECTION_OUTPUT 2
#endif

// DPLL Pin State
#ifndef DPLL_PIN_STATE_CONNECTED
#define DPLL_PIN_STATE_CONNECTED 1
#define DPLL_PIN_STATE_DISCONNECTED 2
#define DPLL_PIN_STATE_SELECTABLE 3
#endif

// DPLL Pin Capabilities
#ifndef DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE
#define DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE 1
#define DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE 2
#define DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE 4
#endif

// Bridge STP state definitions
#ifndef BR_STATE_DISABLED
#define BR_STATE_DISABLED 0
#define BR_STATE_LISTENING 1
#define BR_STATE_LEARNING 2
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4
#endif

// IFLA_BRPORT_* attribute definitions
#ifndef IFLA_BRPORT_STATE
#define IFLA_BRPORT_STATE 1
#define IFLA_BRPORT_PRIORITY 2
#define IFLA_BRPORT_COST 3
#define IFLA_BRPORT_MODE 4
#define IFLA_BRPORT_GUARD 5
#define IFLA_BRPORT_PROTECT 6
#define IFLA_BRPORT_FAST_LEAVE 7
#define IFLA_BRPORT_LEARNING 8
#define IFLA_BRPORT_UNICAST_FLOOD 9
#define IFLA_BRPORT_PROXYARP 10
#define IFLA_BRPORT_LEARNING_SYNC 11
#define IFLA_BRPORT_PROXYARP_WIFI 12
#define IFLA_BRPORT_MCAST_TO_UCAST 13
#define IFLA_BRPORT_MCAST_FLOOD 14
#define IFLA_BRPORT_BCAST_FLOOD 15
#define IFLA_BRPORT_MULTICAST_ROUTER 16
#define IFLA_BRPORT_PAD 17
#define IFLA_BRPORT_MCAST_TO_UCAST_TIMER 18
#define IFLA_BRPORT_MCAST_HELLO_TIMER 19
#define IFLA_BRPORT_BACKUP_PORT 20
#define IFLA_BRPORT_ROOT_ID 21
#define IFLA_BRPORT_BRIDGE_ID 22
#define IFLA_BRPORT_DESIGNATED_PORT 23
#define IFLA_BRPORT_GROUP_FWD_MASK 24
#define IFLA_BRPORT_MCAST_ROUTER 25
#define IFLA_BRPORT_NEIGH_SUPPRESS 26
#define IFLA_BRPORT_ISOLATED 27
#define IFLA_BRPORT_BACKUP_NH_ID 28
#define IFLA_BRPORT_MRP_RING_OPEN 29
#define IFLA_BRPORT_MRP_IN_OPEN 30
#define IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT 31
#define IFLA_BRPORT_MCAST_EHT_HOSTS_CNT 32
#define IFLA_BRPORT_LOCKED 40
#define IFLA_BRPORT_MAB 41
#define IFLA_BRPORT_MCAST_N_GROUPS 42
#define IFLA_BRPORT_MCAST_MAX_GROUPS 43
#define IFLA_BRPORT_NEIGH_VLAN_SUPPRESS 44
#define IFLA_BRPORT_BACKUP_NHID 45
#define IFLA_BRPORT_VLAN_TUNNEL 46
#define IFLA_BRPORT_DESIGNATED_COST 47
#endif

// VETH attribute definitions
#ifndef VETH_INFO_UNSPEC
#define VETH_INFO_UNSPEC 0
#define VETH_INFO_PEER 1
#endif

// VLAN attribute definitions
#ifndef IFLA_VLAN_ID
#define IFLA_VLAN_ID 1
#define IFLA_VLAN_FLAGS 2
#define IFLA_VLAN_PROTOCOL 5
#endif

// Bridge master attribute definitions
#ifndef IFLA_BR_FORWARD_DELAY
#define IFLA_BR_FORWARD_DELAY 1
#define IFLA_BR_HELLO_TIME 2
#define IFLA_BR_MAX_AGE 3
#define IFLA_BR_AGEING_TIME 4
#define IFLA_BR_STP_STATE 5
#define IFLA_BR_PRIORITY 6
#define IFLA_BR_VLAN_FILTERING 7
#define IFLA_BR_VLAN_PROTOCOL 8
#define IFLA_BR_GROUP_FWD_MASK 9
#define IFLA_BR_ROOT_ID 10
#define IFLA_BR_BRIDGE_ID 11
#define IFLA_BR_ROOT_PORT 12
#define IFLA_BR_ROOT_PATH_COST 13
#define IFLA_BR_TOPOLOGY_CHANGE 14
#define IFLA_BR_TOPOLOGY_CHANGE_DETECTED 15
#define IFLA_BR_HELLO_TIMER 16
#define IFLA_BR_TCN_TIMER 17
#define IFLA_BR_TOPOLOGY_CHANGE_TIMER 18
#define IFLA_BR_GC_TIMER 19
#define IFLA_BR_GROUP_ADDR 20
#define IFLA_BR_MCAST_ROUTER 22
#define IFLA_BR_MCAST_SNOOPING 23
#define IFLA_BR_MCAST_QUERY_USE_IFADDR 24
#define IFLA_BR_MCAST_QUERIER 25
#define IFLA_BR_MCAST_HASH_ELASTICITY 26
#define IFLA_BR_MCAST_HASH_MAX 27
#define IFLA_BR_MCAST_LAST_MEMBER_CNT 28
#define IFLA_BR_MCAST_STARTUP_QUERY_CNT 29
#define IFLA_BR_MCAST_LAST_MEMBER_INTVL 30
#define IFLA_BR_MCAST_MEMBERSHIP_INTVL 31
#define IFLA_BR_MCAST_QUERIER_INTVL 32
#define IFLA_BR_MCAST_QUERY_INTVL 33
#define IFLA_BR_MCAST_QUERY_RESPONSE_INTVL 34
#define IFLA_BR_MCAST_STARTUP_QUERY_INTVL 35
#define IFLA_BR_NF_CALL_IPTABLES 36
#define IFLA_BR_NF_CALL_IP6TABLES 37
#define IFLA_BR_NF_CALL_ARPTABLES 38
#define IFLA_BR_VLAN_DEFAULT_PVID 39
#define IFLA_BR_VLAN_STATS_ENABLED 41
#define IFLA_BR_MCAST_STATS_ENABLED 42
#define IFLA_BR_MCAST_IGMP_VERSION 43
#define IFLA_BR_MCAST_MLD_VERSION 44
#define IFLA_BR_VLAN_STATS_PER_PORT 45
#define IFLA_BR_MULTI_BOOLOPT 46
#define IFLA_BR_FDB_N_LEARNED 48
#define IFLA_BR_FDB_MAX_LEARNED 49
#endif

// Additional IFLA_* attribute definitions
#ifndef IFLA_MAP
#define IFLA_LINK 5
#define IFLA_QDISC 6
#define IFLA_STATS 7
#define IFLA_MASTER 10
#define IFLA_MAP 14
#define IFLA_LINKMODE 17
#define IFLA_LINKINFO 18
#define IFLA_PROTINFO 19
#define IFLA_TXQLEN 13
#define IFLA_IFALIAS 20
#define IFLA_STATS64 23
#define IFLA_AF_SPEC 26
#define IFLA_GROUP 27
#define IFLA_PROMISCUITY 30
#define IFLA_NUM_TX_QUEUES 31
#define IFLA_NUM_RX_QUEUES 32
#define IFLA_CARRIER 33
#define IFLA_CARRIER_CHANGES 35
#define IFLA_PROTO_DOWN 39
#define IFLA_GSO_MAX_SEGS 40
#define IFLA_GSO_MAX_SIZE 41
#define IFLA_XDP 43
#define IFLA_CARRIER_UP_COUNT 47
#define IFLA_CARRIER_DOWN_COUNT 48
#define IFLA_MIN_MTU 50
#define IFLA_MAX_MTU 51
#define IFLA_PERM_ADDRESS 54
#define IFLA_PARENT_DEV_NAME 56
#define IFLA_GRO_MAX_SIZE 58
#define IFLA_TSO_MAX_SIZE 59
#define IFLA_TSO_MAX_SEGS 60
#define IFLA_ALLMULTI 61
#define IFLA_GSO_IPV4_MAX_SIZE 63
#define IFLA_GRO_IPV4_MAX_SIZE 64
#define IFLA_DPLL_PIN 65
#endif

// IFLA_INFO_* attribute definitions (nested under IFLA_LINKINFO)
#ifndef IFLA_INFO_KIND
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define IFLA_INFO_SLAVE_KIND 4
#define IFLA_INFO_SLAVE_DATA 5
#endif

// IFA_* attribute definitions
#ifndef IFA_CACHEINFO
#define IFA_CACHEINFO 6
#define IFA_FLAGS 8
#define IFA_PROTO 11
#endif

// Hardware type (ARPHRD_*) definitions
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
#define ARPHRD_IPIP 768
#define ARPHRD_LOOPBACK 772
#define ARPHRD_SIT 776
#define ARPHRD_IPGRE 778
#define ARPHRD_IEEE80211 801
#endif

// Interface operational state (IF_OPER_*) definitions
#ifndef IF_OPER_UNKNOWN
#define IF_OPER_UNKNOWN 0
#define IF_OPER_NOTPRESENT 1
#define IF_OPER_DOWN 2
#define IF_OPER_LOWERLAYERDOWN 3
#define IF_OPER_TESTING 4
#define IF_OPER_DORMANT 5
#define IF_OPER_UP 6
#endif

// Address scope (RT_SCOPE_*) definitions
#ifndef RT_SCOPE_UNIVERSE
#define RT_SCOPE_UNIVERSE 0
#define RT_SCOPE_SITE 200
#define RT_SCOPE_LINK 253
#define RT_SCOPE_HOST 254
#define RT_SCOPE_NOWHERE 255
#endif

// GENEVE attribute definitions
#ifndef IFLA_GENEVE_ID
#define IFLA_GENEVE_ID 1
#define IFLA_GENEVE_REMOTE 2
#define IFLA_GENEVE_TTL 3
#define IFLA_GENEVE_TOS 4
#define IFLA_GENEVE_PORT 5
#define IFLA_GENEVE_COLLECT_METADATA 6
#define IFLA_GENEVE_REMOTE6 7
#define IFLA_GENEVE_UDP_CSUM 8
#define IFLA_GENEVE_UDP_ZERO_CSUM6_TX 9
#define IFLA_GENEVE_UDP_ZERO_CSUM6_RX 10
#define IFLA_GENEVE_LABEL 11
#define IFLA_GENEVE_TTL_INHERIT 12
#define IFLA_GENEVE_DF 13
#define IFLA_GENEVE_INNER_PROTO_INHERIT 14
#endif

// Create netlink socket
int nl_create_socket() {
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    int bufsize = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    
    return sock;
}

// Create generic netlink socket
int genl_create_socket() {
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    int bufsize = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    
    return sock;
}

void nl_close_socket(int sock) {
    if (sock >= 0) {
        close(sock);
    }
}

static unsigned int nl_generate_seq(void) {
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL) ^ getpid());
        initialized = 1;
    }
    return (unsigned int)rand();
}

// Helper to add rtattr to message
static void add_rtattr(struct nlmsghdr* nlh, int type, const void* data, int len) {
    struct rtattr* rta = (struct rtattr*)((char*)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    if (data && len > 0) {
        memcpy(RTA_DATA(rta), data, len);
    }
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

// Get Generic Netlink family ID by name
int genl_get_family_id(int sock, const char* family_name) {
    unsigned char buf[4096];
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    struct genlmsghdr* gnlh;
    unsigned int seq = nl_generate_seq();
    
    memset(buf, 0, sizeof(buf));
    
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = 0;
    
    gnlh = (struct genlmsghdr*)NLMSG_DATA(nlh);
    gnlh->cmd = CTRL_CMD_GETFAMILY;
    gnlh->version = 1;
    
    add_rtattr(nlh, CTRL_ATTR_FAMILY_NAME, family_name, strlen(family_name) + 1);
    
    if (send(sock, nlh, nlh->nlmsg_len, 0) < 0) {
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    ssize_t len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) {
        return -1;
    }
    
    nlh = (struct nlmsghdr*)buf;
    
    // Verify sequence number matches our request
    if (nlh->nlmsg_seq != seq) {
        return -1;
    }
    
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        return -1;
    }
    
    gnlh = (struct genlmsghdr*)NLMSG_DATA(nlh);
    struct rtattr* rta = (struct rtattr*)((char*)gnlh + GENL_HDRLEN);
    int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
    
    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        if (rta->rta_type == CTRL_ATTR_FAMILY_ID) {
            return *(unsigned short*)RTA_DATA(rta);
        }
    }
    
    return -1;
}

// Query WireGuard device by interface index
int genl_query_wireguard(int sock, int family_id, unsigned int ifindex, wg_device_info_t* wg_info) {
    if (!wg_info) return -1;
    
    memset(wg_info, 0, sizeof(wg_device_info_t));
    
    unsigned char buf[8192];
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    struct genlmsghdr* gnlh;
    unsigned int seq = nl_generate_seq();
    
    memset(buf, 0, sizeof(buf));
    
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = 0;
    
    gnlh = (struct genlmsghdr*)NLMSG_DATA(nlh);
    gnlh->cmd = WG_CMD_GET_DEVICE;
    gnlh->version = WG_GENL_VERSION;
    
    add_rtattr(nlh, WGDEVICE_A_IFINDEX, &ifindex, sizeof(ifindex));
    
    if (send(sock, nlh, nlh->nlmsg_len, 0) < 0) {
        return -1;
    }
    
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int done = 0;
    while (!done) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (len == 0) break;
        
        nlh = (struct nlmsghdr*)buf;
        size_t remaining = len;
        
        while (NLMSG_OK(nlh, remaining)) {
            if (nlh->nlmsg_seq != seq) {
                nlh = NLMSG_NEXT(nlh, remaining);
                continue;
            }
            
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                return -1;
            }
            
            gnlh = (struct genlmsghdr*)NLMSG_DATA(nlh);
            struct rtattr* rta = (struct rtattr*)((char*)gnlh + GENL_HDRLEN);
            int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
            
            wg_info->has_config = 1;
            
            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                switch (rta->rta_type) {
                    case WGDEVICE_A_PUBLIC_KEY:
                        if (RTA_PAYLOAD(rta) == 32) {
                            memcpy(wg_info->public_key, RTA_DATA(rta), 32);
                            wg_info->has_public_key = 1;
                        }
                        break;
                    case WGDEVICE_A_LISTEN_PORT:
                        if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                            wg_info->listen_port = *(unsigned short*)RTA_DATA(rta);
                            wg_info->has_listen_port = 1;
                        }
                        break;
                    case WGDEVICE_A_FWMARK:
                        if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                            wg_info->fwmark = *(unsigned int*)RTA_DATA(rta);
                            wg_info->has_fwmark = 1;
                        }
                        break;
                    case WGDEVICE_A_PEERS: {
                        // Count peers first
                        int peer_count = 0;
                        struct rtattr* peer_rta = RTA_DATA(rta);
                        int peer_rta_len = RTA_PAYLOAD(rta);
                        
                        for (; RTA_OK(peer_rta, peer_rta_len); peer_rta = RTA_NEXT(peer_rta, peer_rta_len)) {
                            peer_count++;
                        }
                        
                        if (peer_count > 0) {
                            wg_info->peers = calloc(peer_count, sizeof(wg_peer_info_t));
                            if (!wg_info->peers) break;
                            wg_info->peer_count = 0;
                            
                            // Parse peers
                            peer_rta = RTA_DATA(rta);
                            peer_rta_len = RTA_PAYLOAD(rta);
                            
                            for (; RTA_OK(peer_rta, peer_rta_len); peer_rta = RTA_NEXT(peer_rta, peer_rta_len)) {
                                wg_peer_info_t* peer = &wg_info->peers[wg_info->peer_count];
                                
                                struct rtattr* peer_attr = RTA_DATA(peer_rta);
                                int peer_attr_len = RTA_PAYLOAD(peer_rta);
                                
                                for (; RTA_OK(peer_attr, peer_attr_len); peer_attr = RTA_NEXT(peer_attr, peer_attr_len)) {
                                    switch (peer_attr->rta_type) {
                                        case WGPEER_A_PUBLIC_KEY:
                                            if (RTA_PAYLOAD(peer_attr) == 32) {
                                                memcpy(peer->public_key, RTA_DATA(peer_attr), 32);
                                                peer->has_public_key = 1;
                                            }
                                            break;
                                        case WGPEER_A_RX_BYTES:
                                            if (RTA_PAYLOAD(peer_attr) >= sizeof(unsigned long long)) {
                                                peer->rx_bytes = *(unsigned long long*)RTA_DATA(peer_attr);
                                                peer->has_rx_bytes = 1;
                                            }
                                            break;
                                        case WGPEER_A_TX_BYTES:
                                            if (RTA_PAYLOAD(peer_attr) >= sizeof(unsigned long long)) {
                                                peer->tx_bytes = *(unsigned long long*)RTA_DATA(peer_attr);
                                                peer->has_tx_bytes = 1;
                                            }
                                            break;
                                        case WGPEER_A_LAST_HANDSHAKE_TIME:
                                            if (RTA_PAYLOAD(peer_attr) >= sizeof(unsigned long long)) {
                                                peer->last_handshake_time = *(unsigned long long*)RTA_DATA(peer_attr);
                                                peer->has_last_handshake = 1;
                                            }
                                            break;
                                    }
                                }
                                
                                wg_info->peer_count++;
                            }
                        }
                        break;
                    }
                }
            }
            
            nlh = NLMSG_NEXT(nlh, remaining);
        }
    }
    
    return wg_info->has_config ? 0 : -1;
}

void genl_free_wireguard(wg_device_info_t* wg_info) {
    if (wg_info && wg_info->peers) {
        free(wg_info->peers);
        wg_info->peers = NULL;
        wg_info->peer_count = 0;
    }
}

// Forward declaration for track_unknown_attr
static void track_unknown_attr(unsigned short* unknown_list, int* count, int max_count,
                                unsigned short attr_type, const unsigned short* known_list, int known_count);

// Parse DPLL pin nested attributes
static void nl_parse_dpll_pin(struct rtattr* rta, dpll_pin_info_t* dpll_pin) {
    struct rtattr* dpll_attr = RTA_DATA(rta);
    int dpll_attr_len = RTA_PAYLOAD(rta);
    
    // Initialize unknown attributes tracking
    dpll_pin->unknown_attrs_count = 0;
    
    // Known DPLL pin attributes
    static const unsigned short known_dpll_attrs[] = {
        DPLL_A_PIN_ID, DPLL_A_PIN_PARENT_ID, DPLL_A_PIN_MODULE_NAME,
        DPLL_A_PIN_CLOCK_ID, DPLL_A_PIN_BOARD_LABEL, DPLL_A_PIN_PANEL_LABEL,
        DPLL_A_PIN_PACKAGE_LABEL, DPLL_A_PIN_TYPE, DPLL_A_PIN_DIRECTION,
        DPLL_A_PIN_FREQUENCY, DPLL_A_PIN_FREQUENCY_MIN, DPLL_A_PIN_FREQUENCY_MAX,
        DPLL_A_PIN_PRIO, DPLL_A_PIN_STATE, DPLL_A_PIN_CAPABILITIES,
        DPLL_A_PIN_PHASE_ADJUST_MIN, DPLL_A_PIN_PHASE_ADJUST_MAX,
        DPLL_A_PIN_PHASE_ADJUST, DPLL_A_PIN_PHASE_OFFSET,
        DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET, DPLL_A_PIN_PAD,
        DPLL_A_PIN_FREQUENCY_SUPPORTED, DPLL_A_PIN_PARENT_DEVICE, DPLL_A_PIN_PARENT_PIN
    };
    static const int known_dpll_count = sizeof(known_dpll_attrs) / sizeof(known_dpll_attrs[0]);
    
    for (; RTA_OK(dpll_attr, dpll_attr_len); dpll_attr = RTA_NEXT(dpll_attr, dpll_attr_len)) {
        // Track unknown attributes
        track_unknown_attr(dpll_pin->unknown_attrs, 
                          &dpll_pin->unknown_attrs_count,
                          32, dpll_attr->rta_type, known_dpll_attrs, known_dpll_count);
        
        switch (dpll_attr->rta_type) {
            case DPLL_A_PIN_ID:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned long long)) {
                    dpll_pin->pin_id = *(unsigned long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_pin_id = 1;
                }
                break;
            case DPLL_A_PIN_PARENT_ID:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned long long)) {
                    dpll_pin->parent_id = *(unsigned long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_parent_id = 1;
                }
                break;
            case DPLL_A_PIN_CLOCK_ID:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned long long)) {
                    dpll_pin->clock_id = *(unsigned long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_clock_id = 1;
                }
                break;
            case DPLL_A_PIN_MODULE_NAME:
                if (RTA_PAYLOAD(dpll_attr) > 0) {
                    strncpy(dpll_pin->module_name, RTA_DATA(dpll_attr), 63);
                    dpll_pin->module_name[63] = '\0';
                    dpll_pin->has_module_name = 1;
                }
                break;
            case DPLL_A_PIN_BOARD_LABEL:
                if (RTA_PAYLOAD(dpll_attr) > 0) {
                    strncpy(dpll_pin->board_label, RTA_DATA(dpll_attr), 63);
                    dpll_pin->board_label[63] = '\0';
                    dpll_pin->has_board_label = 1;
                }
                break;
            case DPLL_A_PIN_PANEL_LABEL:
                if (RTA_PAYLOAD(dpll_attr) > 0) {
                    strncpy(dpll_pin->panel_label, RTA_DATA(dpll_attr), 63);
                    dpll_pin->panel_label[63] = '\0';
                    dpll_pin->has_panel_label = 1;
                }
                break;
            case DPLL_A_PIN_PACKAGE_LABEL:
                if (RTA_PAYLOAD(dpll_attr) > 0) {
                    strncpy(dpll_pin->package_label, RTA_DATA(dpll_attr), 63);
                    dpll_pin->package_label[63] = '\0';
                    dpll_pin->has_package_label = 1;
                }
                break;
            case DPLL_A_PIN_TYPE:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned char)) {
                    dpll_pin->pin_type = *(unsigned char*)RTA_DATA(dpll_attr);
                    dpll_pin->has_pin_type = 1;
                }
                break;
            case DPLL_A_PIN_DIRECTION:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned char)) {
                    dpll_pin->pin_direction = *(unsigned char*)RTA_DATA(dpll_attr);
                    dpll_pin->has_pin_direction = 1;
                }
                break;
            case DPLL_A_PIN_STATE:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned char)) {
                    dpll_pin->pin_state = *(unsigned char*)RTA_DATA(dpll_attr);
                    dpll_pin->has_pin_state = 1;
                }
                break;
            case DPLL_A_PIN_CAPABILITIES:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned int)) {
                    dpll_pin->pin_capabilities = *(unsigned int*)RTA_DATA(dpll_attr);
                    dpll_pin->has_pin_capabilities = 1;
                }
                break;
            case DPLL_A_PIN_PRIO:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned int)) {
                    dpll_pin->pin_priority = *(unsigned int*)RTA_DATA(dpll_attr);
                    dpll_pin->has_pin_priority = 1;
                }
                break;
            case DPLL_A_PIN_FREQUENCY:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned long long)) {
                    dpll_pin->frequency = *(unsigned long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_frequency = 1;
                }
                break;
            case DPLL_A_PIN_FREQUENCY_MIN:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned long long)) {
                    dpll_pin->frequency_min = *(unsigned long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_frequency_min = 1;
                }
                break;
            case DPLL_A_PIN_FREQUENCY_MAX:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(unsigned long long)) {
                    dpll_pin->frequency_max = *(unsigned long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_frequency_max = 1;
                }
                break;
            case DPLL_A_PIN_PHASE_ADJUST:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(long long)) {
                    dpll_pin->phase_adjust = *(long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_phase_adjust = 1;
                }
                break;
            case DPLL_A_PIN_PHASE_ADJUST_MIN:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(long long)) {
                    dpll_pin->phase_adjust_min = *(long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_phase_adjust_min = 1;
                }
                break;
            case DPLL_A_PIN_PHASE_ADJUST_MAX:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(long long)) {
                    dpll_pin->phase_adjust_max = *(long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_phase_adjust_max = 1;
                }
                break;
            case DPLL_A_PIN_PHASE_OFFSET:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(long long)) {
                    dpll_pin->phase_offset = *(long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_phase_offset = 1;
                }
                break;
            case DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET:
                if (RTA_PAYLOAD(dpll_attr) >= sizeof(long long)) {
                    dpll_pin->fractional_frequency_offset = *(long long*)RTA_DATA(dpll_attr);
                    dpll_pin->has_fractional_frequency_offset = 1;
                }
                break;
        }
    }
    
    dpll_pin->has_dpll_pin = 1;
}

int nl_send_getlink(int sock, unsigned int* seq_out) {
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req;
    
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = nl_generate_seq();
    req.nlh.nlmsg_pid = 0;
    req.ifi.ifi_family = AF_UNSPEC;
    
    if (seq_out) {
        *seq_out = req.nlh.nlmsg_seq;
    }
    
    return send(sock, &req, req.nlh.nlmsg_len, 0);
}

int nl_send_getaddr(int sock, unsigned int* seq_out) {
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;
    
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = nl_generate_seq();
    req.nlh.nlmsg_pid = 0;
    req.ifa.ifa_family = AF_UNSPEC;
    
    if (seq_out) {
        *seq_out = req.nlh.nlmsg_seq;
    }
    
    return send(sock, &req, req.nlh.nlmsg_len, 0);
}

response_buffer_t* nl_recv_response(int sock, unsigned int expected_seq) {
    response_buffer_t* buf = malloc(sizeof(response_buffer_t));
    if (!buf) return NULL;
    
    buf->capacity = 65536;
    buf->length = 0;
    buf->seq = expected_seq;
    buf->data = malloc(buf->capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int done = 0;
    
    while (!done) {
        unsigned char temp_buf[65536];
        ssize_t len = recv(sock, temp_buf, sizeof(temp_buf), 0);
        
        if (len < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (buf->length > 0) break;
                free(buf->data);
                free(buf);
                return NULL;
            }
            free(buf->data);
            free(buf);
            return NULL;
        }
        if (len == 0) break;
        
        struct nlmsghdr* nlh = (struct nlmsghdr*)temp_buf;
        size_t remaining = len;
        
        while (NLMSG_OK(nlh, remaining)) {
            if (nlh->nlmsg_seq == expected_seq) {
                if (nlh->nlmsg_type == NLMSG_DONE) {
                    done = 1;
                }
                
                size_t msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
                
                while (buf->length + msg_len > buf->capacity) {
                    buf->capacity *= 2;
                    unsigned char* new_data = realloc(buf->data, buf->capacity);
                    if (!new_data) {
                        free(buf->data);
                        free(buf);
                        return NULL;
                    }
                    buf->data = new_data;
                }
                
                memcpy(buf->data + buf->length, nlh, msg_len);
                buf->length += msg_len;
                
                if (done) break;
            }
            
            nlh = NLMSG_NEXT(nlh, remaining);
        }
    }
    
    return buf;
}

void nl_free_response(response_buffer_t* buf) {
    if (buf) {
        if (buf->data) free(buf->data);
        free(buf);
    }
}

static void track_unknown_attr(unsigned short* unknown_list, int* count, int max_count, 
                               unsigned short attr_type, const unsigned short* known_attrs, 
                               int known_count) {
    // Strip flags to get base attribute type
    unsigned short base_type = attr_type & NLA_TYPE_MASK;
    
    // Check if this is a known attribute (compare base types)
    for (int i = 0; i < known_count; i++) {
        if (known_attrs[i] == base_type) {
            return;
        }
    }
    
    // Check if already in unknown list (store full type with flags)
    for (int i = 0; i < *count; i++) {
        if (unknown_list[i] == attr_type) {
            return;
        }
    }
    
    // Add to unknown list
    if (*count < max_count) {
        unknown_list[*count] = attr_type;
        (*count)++;
    }
}
void nl_parse_protinfo(struct rtattr* protinfo_attr, link_info_t* link) {
    if (!protinfo_attr || !link) return;
    
    if (link->bridge_port.data_source_priority >= 2) {
        return;
    }
    
    int info_len = RTA_PAYLOAD(protinfo_attr);
    struct rtattr* rta = RTA_DATA(protinfo_attr);
    
    link->bridge_port.has_bridge_info = 1;
    link->bridge_port.data_source_priority = 1;
    link->bridge_port.unknown_attrs_count = 0;
    
    static const unsigned short known_brport_attrs[] = {
        IFLA_BRPORT_STATE, IFLA_BRPORT_PRIORITY, IFLA_BRPORT_COST,
        IFLA_BRPORT_MODE, IFLA_BRPORT_GUARD, IFLA_BRPORT_PROTECT,
        IFLA_BRPORT_FAST_LEAVE, IFLA_BRPORT_LEARNING, IFLA_BRPORT_UNICAST_FLOOD,
        IFLA_BRPORT_PROXYARP, IFLA_BRPORT_PROXYARP_WIFI, IFLA_BRPORT_MCAST_ROUTER,
        IFLA_BRPORT_MCAST_TO_UCAST, IFLA_BRPORT_MCAST_FLOOD, IFLA_BRPORT_BCAST_FLOOD,
        IFLA_BRPORT_MULTICAST_ROUTER, IFLA_BRPORT_PAD, IFLA_BRPORT_MCAST_TO_UCAST_TIMER,
        IFLA_BRPORT_MCAST_HELLO_TIMER, IFLA_BRPORT_BACKUP_PORT,
        IFLA_BRPORT_ROOT_ID, IFLA_BRPORT_BRIDGE_ID, IFLA_BRPORT_DESIGNATED_PORT,
        IFLA_BRPORT_GROUP_FWD_MASK, IFLA_BRPORT_NEIGH_SUPPRESS, IFLA_BRPORT_ISOLATED,
        IFLA_BRPORT_BACKUP_NH_ID, IFLA_BRPORT_MRP_RING_OPEN, IFLA_BRPORT_MRP_IN_OPEN,
        IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT, IFLA_BRPORT_MCAST_EHT_HOSTS_CNT,
        33, 34, 35, 36, 37, 38, 39,  // Reserved/vendor-specific
        IFLA_BRPORT_LOCKED, IFLA_BRPORT_MAB,
        IFLA_BRPORT_MCAST_N_GROUPS, IFLA_BRPORT_MCAST_MAX_GROUPS,
        IFLA_BRPORT_NEIGH_VLAN_SUPPRESS, IFLA_BRPORT_BACKUP_NHID,
        IFLA_BRPORT_VLAN_TUNNEL, IFLA_BRPORT_DESIGNATED_COST
    };
    static const int known_brport_count = sizeof(known_brport_attrs) / sizeof(known_brport_attrs[0]);
    
    for (; RTA_OK(rta, info_len); rta = RTA_NEXT(rta, info_len)) {
        track_unknown_attr(link->bridge_port.unknown_attrs, 
                          &link->bridge_port.unknown_attrs_count,
                          64, rta->rta_type, known_brport_attrs, known_brport_count);
        
        switch (rta->rta_type) {
            case IFLA_BRPORT_STATE:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.state = *(unsigned char*)RTA_DATA(rta);
                }
                break;
            case IFLA_BRPORT_PRIORITY:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                    link->bridge_port.priority = *(unsigned short*)RTA_DATA(rta);
                    link->bridge_port.has_priority = 1;
                }
                break;
            case IFLA_BRPORT_COST:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                    link->bridge_port.cost = *(unsigned int*)RTA_DATA(rta);
                    link->bridge_port.has_cost = 1;
                }
                break;
            case IFLA_BRPORT_MODE:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mode = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mode = 1;
                }
                break;
            case IFLA_BRPORT_GUARD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.guard = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_guard = 1;
                }
                break;
            case IFLA_BRPORT_PROTECT:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.protect = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_protect = 1;
                }
                break;
            case IFLA_BRPORT_FAST_LEAVE:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.fast_leave = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_fast_leave = 1;
                }
                break;
            case IFLA_BRPORT_LEARNING:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.learning = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_learning = 1;
                }
                break;
            case IFLA_BRPORT_UNICAST_FLOOD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.unicast_flood = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_unicast_flood = 1;
                }
                break;
            case IFLA_BRPORT_PROXYARP:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.proxyarp = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_proxyarp = 1;
                }
                break;
            case IFLA_BRPORT_PROXYARP_WIFI:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.proxyarp_wifi = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_proxyarp_wifi = 1;
                }
                break;
            case IFLA_BRPORT_MCAST_ROUTER:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.multicast_router = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_multicast_router = 1;
                }
                break;
            case IFLA_BRPORT_MCAST_TO_UCAST:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mcast_to_ucast = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mcast_to_ucast = 1;
                }
                break;
            case IFLA_BRPORT_MCAST_FLOOD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mcast_flood = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mcast_flood = 1;
                }
                break;
            case IFLA_BRPORT_BCAST_FLOOD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.bcast_flood = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_bcast_flood = 1;
                }
                break;
            case IFLA_BRPORT_GROUP_FWD_MASK:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                    link->bridge_port.group_fwd_mask = *(unsigned short*)RTA_DATA(rta);
                    link->bridge_port.has_group_fwd_mask = 1;
                }
                break;
            case IFLA_BRPORT_NEIGH_SUPPRESS:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.neigh_suppress = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_neigh_suppress = 1;
                }
                break;
            case IFLA_BRPORT_ISOLATED:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.isolated = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_isolated = 1;
                }
                break;
            case IFLA_BRPORT_LOCKED:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.locked = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_locked = 1;
                }
                break;
            case IFLA_BRPORT_MAB:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mab = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mab = 1;
                }
                break;
        }
    }
}

// Bridge slave data parsing - same structure, higher priority
void nl_parse_bridge_slave_data(struct rtattr* slave_data_attr, link_info_t* link) {
    if (!slave_data_attr || !link) return;
    
    int data_len = RTA_PAYLOAD(slave_data_attr);
    struct rtattr* rta = RTA_DATA(slave_data_attr);
    
    link->bridge_port.has_bridge_info = 1;
    link->bridge_port.data_source_priority = 2;
    link->bridge_port.unknown_attrs_count = 0;
    
    static const unsigned short known_brport_attrs[] = {
        IFLA_BRPORT_STATE, IFLA_BRPORT_PRIORITY, IFLA_BRPORT_COST,
        IFLA_BRPORT_MODE, IFLA_BRPORT_GUARD, IFLA_BRPORT_PROTECT,
        IFLA_BRPORT_FAST_LEAVE, IFLA_BRPORT_LEARNING, IFLA_BRPORT_UNICAST_FLOOD,
        IFLA_BRPORT_PROXYARP, IFLA_BRPORT_PROXYARP_WIFI, IFLA_BRPORT_MCAST_ROUTER,
        IFLA_BRPORT_MCAST_TO_UCAST, IFLA_BRPORT_MCAST_FLOOD, IFLA_BRPORT_BCAST_FLOOD,
        IFLA_BRPORT_MULTICAST_ROUTER, IFLA_BRPORT_PAD, IFLA_BRPORT_MCAST_TO_UCAST_TIMER,
        IFLA_BRPORT_MCAST_HELLO_TIMER, IFLA_BRPORT_BACKUP_PORT,
        IFLA_BRPORT_ROOT_ID, IFLA_BRPORT_BRIDGE_ID, IFLA_BRPORT_DESIGNATED_PORT,
        IFLA_BRPORT_GROUP_FWD_MASK, IFLA_BRPORT_NEIGH_SUPPRESS, IFLA_BRPORT_ISOLATED,
        IFLA_BRPORT_BACKUP_NH_ID, IFLA_BRPORT_MRP_RING_OPEN, IFLA_BRPORT_MRP_IN_OPEN,
        IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT, IFLA_BRPORT_MCAST_EHT_HOSTS_CNT,
        33, 34, 35, 36, 37, 38, 39,  // Reserved/vendor-specific
        IFLA_BRPORT_LOCKED, IFLA_BRPORT_MAB,
        IFLA_BRPORT_MCAST_N_GROUPS, IFLA_BRPORT_MCAST_MAX_GROUPS,
        IFLA_BRPORT_NEIGH_VLAN_SUPPRESS, IFLA_BRPORT_BACKUP_NHID,
        IFLA_BRPORT_VLAN_TUNNEL, IFLA_BRPORT_DESIGNATED_COST
    };
    static const int known_brport_count = sizeof(known_brport_attrs) / sizeof(known_brport_attrs[0]);
    
    for (; RTA_OK(rta, data_len); rta = RTA_NEXT(rta, data_len)) {
        track_unknown_attr(link->bridge_port.unknown_attrs, 
                          &link->bridge_port.unknown_attrs_count,
                          64, rta->rta_type, known_brport_attrs, known_brport_count);
        
        switch (rta->rta_type) {
            case IFLA_BRPORT_STATE:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.state = *(unsigned char*)RTA_DATA(rta);
                }
                break;
            case IFLA_BRPORT_PRIORITY:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                    link->bridge_port.priority = *(unsigned short*)RTA_DATA(rta);
                    link->bridge_port.has_priority = 1;
                }
                break;
            case IFLA_BRPORT_COST:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                    link->bridge_port.cost = *(unsigned int*)RTA_DATA(rta);
                    link->bridge_port.has_cost = 1;
                }
                break;
            case IFLA_BRPORT_MODE:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mode = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mode = 1;
                }
                break;
            case IFLA_BRPORT_GUARD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.guard = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_guard = 1;
                }
                break;
            case IFLA_BRPORT_PROTECT:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.protect = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_protect = 1;
                }
                break;
            case IFLA_BRPORT_FAST_LEAVE:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.fast_leave = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_fast_leave = 1;
                }
                break;
            case IFLA_BRPORT_LEARNING:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.learning = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_learning = 1;
                }
                break;
            case IFLA_BRPORT_UNICAST_FLOOD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.unicast_flood = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_unicast_flood = 1;
                }
                break;
            case IFLA_BRPORT_PROXYARP:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.proxyarp = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_proxyarp = 1;
                }
                break;
            case IFLA_BRPORT_PROXYARP_WIFI:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.proxyarp_wifi = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_proxyarp_wifi = 1;
                }
                break;
            case IFLA_BRPORT_MCAST_ROUTER:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.multicast_router = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_multicast_router = 1;
                }
                break;
            case IFLA_BRPORT_MCAST_TO_UCAST:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mcast_to_ucast = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mcast_to_ucast = 1;
                }
                break;
            case IFLA_BRPORT_MCAST_FLOOD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mcast_flood = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mcast_flood = 1;
                }
                break;
            case IFLA_BRPORT_BCAST_FLOOD:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.bcast_flood = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_bcast_flood = 1;
                }
                break;
            case IFLA_BRPORT_GROUP_FWD_MASK:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                    link->bridge_port.group_fwd_mask = *(unsigned short*)RTA_DATA(rta);
                    link->bridge_port.has_group_fwd_mask = 1;
                }
                break;
            case IFLA_BRPORT_NEIGH_SUPPRESS:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.neigh_suppress = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_neigh_suppress = 1;
                }
                break;
            case IFLA_BRPORT_ISOLATED:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.isolated = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_isolated = 1;
                }
                break;
            case IFLA_BRPORT_LOCKED:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.locked = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_locked = 1;
                }
                break;
            case IFLA_BRPORT_MAB:
                if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                    link->bridge_port.mab = *(unsigned char*)RTA_DATA(rta);
                    link->bridge_port.has_mab = 1;
                }
                break;
        }
    }
}

void nl_parse_info_data(const char* kind, struct rtattr* data_attr, link_info_t* link) {
    if (!kind || !data_attr || !link) return;
    
    int data_len = RTA_PAYLOAD(data_attr);
    struct rtattr* rta = RTA_DATA(data_attr);
    
    link->unknown_info_data_attrs_count = 0;
    
    if (strcmp(kind, "veth") == 0) {
        static const unsigned short known_veth_attrs[] = { VETH_INFO_PEER };
        static const int known_veth_count = sizeof(known_veth_attrs) / sizeof(known_veth_attrs[0]);
        
        for (; RTA_OK(rta, data_len); rta = RTA_NEXT(rta, data_len)) {
            track_unknown_attr(link->unknown_info_data_attrs, 
                              &link->unknown_info_data_attrs_count,
                              64, rta->rta_type, known_veth_attrs, known_veth_count);
            
            if (rta->rta_type == VETH_INFO_PEER) {
                if (RTA_PAYLOAD(rta) >= sizeof(struct ifinfomsg)) {
                    struct ifinfomsg* peer_ifi = (struct ifinfomsg*)RTA_DATA(rta);
                    link->veth_peer_index = peer_ifi->ifi_index;
                    link->has_veth_peer = 1;
                }
            }
        }
    } else if (strcmp(kind, "vlan") == 0) {
        static const unsigned short known_vlan_attrs[] = { IFLA_VLAN_ID, IFLA_VLAN_FLAGS, IFLA_VLAN_PROTOCOL };
        static const int known_vlan_count = sizeof(known_vlan_attrs) / sizeof(known_vlan_attrs[0]);
        
        for (; RTA_OK(rta, data_len); rta = RTA_NEXT(rta, data_len)) {
            track_unknown_attr(link->unknown_info_data_attrs, 
                              &link->unknown_info_data_attrs_count,
                              64, rta->rta_type, known_vlan_attrs, known_vlan_count);
            
            switch (rta->rta_type) {
                case IFLA_VLAN_ID:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        link->vlan_id = *(unsigned short*)RTA_DATA(rta);
                        link->has_vlan_id = 1;
                    }
                    break;
                case IFLA_VLAN_FLAGS:
                    if (RTA_PAYLOAD(rta) >= 8) {  // sizeof(struct ifla_vlan_flags)
                        unsigned int* flag_data = (unsigned int*)RTA_DATA(rta);
                        link->vlan_flags = flag_data[0];
                        link->vlan_flags_mask = flag_data[1];
                        link->has_vlan_flags = 1;
                    }
                    break;
                case IFLA_VLAN_PROTOCOL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        unsigned short proto = *(unsigned short*)RTA_DATA(rta);
                        // Convert from network byte order (big-endian) to host byte order
                        link->vlan_protocol = ntohs(proto);
                        link->has_vlan_protocol = 1;
                    }
                    break;
            }
        }
    } else if (strcmp(kind, "bridge") == 0) {
        // ***** THIS IS THE NEW SECTION WITH ALL 30+ ATTRIBUTES! *****
        static const unsigned short known_bridge_attrs[] = {
            IFLA_BR_FORWARD_DELAY, IFLA_BR_HELLO_TIME, IFLA_BR_MAX_AGE, IFLA_BR_AGEING_TIME,
            IFLA_BR_STP_STATE, IFLA_BR_PRIORITY, IFLA_BR_VLAN_FILTERING, IFLA_BR_VLAN_PROTOCOL,
            IFLA_BR_GROUP_FWD_MASK, IFLA_BR_ROOT_ID, IFLA_BR_BRIDGE_ID, IFLA_BR_ROOT_PORT,
            IFLA_BR_ROOT_PATH_COST, IFLA_BR_TOPOLOGY_CHANGE, IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
            IFLA_BR_HELLO_TIMER, IFLA_BR_TCN_TIMER, IFLA_BR_TOPOLOGY_CHANGE_TIMER, IFLA_BR_GC_TIMER,
            IFLA_BR_GROUP_ADDR, IFLA_BR_MCAST_ROUTER, IFLA_BR_MCAST_SNOOPING,
            IFLA_BR_MCAST_QUERY_USE_IFADDR, IFLA_BR_MCAST_QUERIER, IFLA_BR_MCAST_HASH_ELASTICITY,
            IFLA_BR_MCAST_HASH_MAX, IFLA_BR_MCAST_LAST_MEMBER_CNT, IFLA_BR_MCAST_STARTUP_QUERY_CNT,
            IFLA_BR_MCAST_LAST_MEMBER_INTVL, IFLA_BR_MCAST_MEMBERSHIP_INTVL, IFLA_BR_MCAST_QUERIER_INTVL,
            IFLA_BR_MCAST_QUERY_INTVL, IFLA_BR_MCAST_QUERY_RESPONSE_INTVL, IFLA_BR_MCAST_STARTUP_QUERY_INTVL,
            IFLA_BR_NF_CALL_IPTABLES, IFLA_BR_NF_CALL_IP6TABLES, IFLA_BR_NF_CALL_ARPTABLES,
            IFLA_BR_VLAN_DEFAULT_PVID, IFLA_BR_VLAN_STATS_ENABLED, IFLA_BR_MCAST_STATS_ENABLED,
            IFLA_BR_MCAST_IGMP_VERSION, IFLA_BR_MCAST_MLD_VERSION, IFLA_BR_VLAN_STATS_PER_PORT,
            IFLA_BR_MULTI_BOOLOPT, IFLA_BR_FDB_N_LEARNED, IFLA_BR_FDB_MAX_LEARNED
        };
        static const int known_bridge_count = sizeof(known_bridge_attrs) / sizeof(known_bridge_attrs[0]);
        
        link->bridge_config.has_bridge_config = 1;
        
        for (; RTA_OK(rta, data_len); rta = RTA_NEXT(rta, data_len)) {
            track_unknown_attr(link->unknown_info_data_attrs, 
                              &link->unknown_info_data_attrs_count,
                              64, rta->rta_type, known_bridge_attrs, known_bridge_count);
            
            switch (rta->rta_type) {
                case IFLA_BR_FORWARD_DELAY:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.forward_delay = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_forward_delay = 1;
                    }
                    break;
                case IFLA_BR_HELLO_TIME:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.hello_time = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_hello_time = 1;
                    }
                    break;
                case IFLA_BR_MAX_AGE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.max_age = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_max_age = 1;
                    }
                    break;
                case IFLA_BR_AGEING_TIME:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.ageing_time = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_ageing_time = 1;
                    }
                    break;
                case IFLA_BR_STP_STATE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.stp_enabled = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_stp_enabled = 1;
                    }
                    break;
                case IFLA_BR_PRIORITY:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        link->bridge_config.priority = *(unsigned short*)RTA_DATA(rta);
                        link->bridge_config.has_priority = 1;
                    }
                    break;
                case IFLA_BR_VLAN_FILTERING:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.vlan_filtering = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_vlan_filtering = 1;
                    }
                    break;
                case IFLA_BR_VLAN_PROTOCOL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        link->bridge_config.vlan_protocol = *(unsigned short*)RTA_DATA(rta);
                        link->bridge_config.has_vlan_protocol = 1;
                    }
                    break;
                case IFLA_BR_GROUP_FWD_MASK:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        link->bridge_config.group_fwd_mask = *(unsigned short*)RTA_DATA(rta);
                        link->bridge_config.has_group_fwd_mask = 1;
                    }
                    break;
                case IFLA_BR_ROOT_ID:
                    if (RTA_PAYLOAD(rta) >= 8) {
                        memcpy(link->bridge_config.root_id, RTA_DATA(rta), 8);
                        link->bridge_config.has_root_id = 1;
                    }
                    break;
                case IFLA_BR_BRIDGE_ID:
                    if (RTA_PAYLOAD(rta) >= 8) {
                        memcpy(link->bridge_config.bridge_id, RTA_DATA(rta), 8);
                        link->bridge_config.has_bridge_id = 1;
                    }
                    break;
                case IFLA_BR_ROOT_PORT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        link->bridge_config.root_port = *(unsigned short*)RTA_DATA(rta);
                        link->bridge_config.has_root_port = 1;
                    }
                    break;
                case IFLA_BR_ROOT_PATH_COST:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.root_path_cost = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_root_path_cost = 1;
                    }
                    break;
                case IFLA_BR_TOPOLOGY_CHANGE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.topology_change = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_topology_change = 1;
                    }
                    break;
                case IFLA_BR_TOPOLOGY_CHANGE_DETECTED:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.topology_change_detected = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_topology_change_detected = 1;
                    }
                    break;
                case IFLA_BR_HELLO_TIMER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.hello_timer = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_hello_timer = 1;
                    }
                    break;
                case IFLA_BR_TCN_TIMER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.tcn_timer = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_tcn_timer = 1;
                    }
                    break;
                case IFLA_BR_TOPOLOGY_CHANGE_TIMER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.topology_change_timer = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_topology_change_timer = 1;
                    }
                    break;
                case IFLA_BR_GC_TIMER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.gc_timer = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_gc_timer = 1;
                    }
                    break;
                case IFLA_BR_GROUP_ADDR:
                    if (RTA_PAYLOAD(rta) >= 6) {
                        memcpy(link->bridge_config.group_addr, RTA_DATA(rta), 6);
                        link->bridge_config.has_group_addr = 1;
                    }
                    break;
                case IFLA_BR_MCAST_ROUTER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.mcast_router = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_router = 1;
                    }
                    break;
                case IFLA_BR_MCAST_SNOOPING:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.mcast_snooping = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_snooping = 1;
                    }
                    break;
                case IFLA_BR_MCAST_QUERY_USE_IFADDR:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.mcast_query_use_ifaddr = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_query_use_ifaddr = 1;
                    }
                    break;
                case IFLA_BR_MCAST_QUERIER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.mcast_querier = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_querier = 1;
                    }
                    break;
                case IFLA_BR_MCAST_HASH_ELASTICITY:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.mcast_hash_elasticity = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_hash_elasticity = 1;
                    }
                    break;
                case IFLA_BR_MCAST_HASH_MAX:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.mcast_hash_max = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_hash_max = 1;
                    }
                    break;
                case IFLA_BR_MCAST_LAST_MEMBER_CNT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.mcast_last_member_cnt = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_last_member_cnt = 1;
                    }
                    break;
                case IFLA_BR_MCAST_STARTUP_QUERY_CNT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.mcast_startup_query_cnt = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_startup_query_cnt = 1;
                    }
                    break;
                case IFLA_BR_MCAST_LAST_MEMBER_INTVL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.mcast_last_member_intvl = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_last_member_intvl = 1;
                    }
                    break;
                case IFLA_BR_MCAST_MEMBERSHIP_INTVL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.mcast_membership_intvl = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_membership_intvl = 1;
                    }
                    break;
                case IFLA_BR_MCAST_QUERIER_INTVL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.mcast_querier_intvl = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_querier_intvl = 1;
                    }
                    break;
                case IFLA_BR_MCAST_QUERY_INTVL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.mcast_query_intvl = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_query_intvl = 1;
                    }
                    break;
                case IFLA_BR_MCAST_QUERY_RESPONSE_INTVL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.mcast_query_response_intvl = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_query_response_intvl = 1;
                    }
                    break;
                case IFLA_BR_MCAST_STARTUP_QUERY_INTVL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.mcast_startup_query_intvl = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_startup_query_intvl = 1;
                    }
                    break;
                case IFLA_BR_NF_CALL_IPTABLES:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.nf_call_iptables = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_nf_call_iptables = 1;
                    }
                    break;
                case IFLA_BR_NF_CALL_IP6TABLES:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.nf_call_ip6tables = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_nf_call_ip6tables = 1;
                    }
                    break;
                case IFLA_BR_NF_CALL_ARPTABLES:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.nf_call_arptables = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_nf_call_arptables = 1;
                    }
                    break;
                case IFLA_BR_VLAN_DEFAULT_PVID:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        link->bridge_config.vlan_default_pvid = *(unsigned short*)RTA_DATA(rta);
                        link->bridge_config.has_vlan_default_pvid = 1;
                    }
                    break;
                case IFLA_BR_VLAN_STATS_ENABLED:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.vlan_stats_enabled = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_vlan_stats_enabled = 1;
                    }
                    break;
                case IFLA_BR_MCAST_STATS_ENABLED:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.mcast_stats_enabled = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_stats_enabled = 1;
                    }
                    break;
                case IFLA_BR_MCAST_IGMP_VERSION:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.mcast_igmp_version = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_igmp_version = 1;
                    }
                    break;
                case IFLA_BR_MCAST_MLD_VERSION:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.mcast_mld_version = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_mcast_mld_version = 1;
                    }
                    break;
                case IFLA_BR_VLAN_STATS_PER_PORT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->bridge_config.vlan_stats_per_port = *(unsigned char*)RTA_DATA(rta);
                        link->bridge_config.has_vlan_stats_per_port = 1;
                    }
                    break;
                case IFLA_BR_MULTI_BOOLOPT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned long long)) {
                        link->bridge_config.multi_boolopt = *(unsigned long long*)RTA_DATA(rta);
                        link->bridge_config.has_multi_boolopt = 1;
                    }
                    break;
                case IFLA_BR_FDB_N_LEARNED:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.fdb_n_learned = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_fdb_n_learned = 1;
                    }
                    break;
                case IFLA_BR_FDB_MAX_LEARNED:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->bridge_config.fdb_max_learned = *(unsigned int*)RTA_DATA(rta);
                        link->bridge_config.has_fdb_max_learned = 1;
                    }
                    break;
            }
        }
    } else if (strcmp(kind, "geneve") == 0) {
        static const unsigned short known_geneve_attrs[] = { 
            IFLA_GENEVE_ID, IFLA_GENEVE_REMOTE, IFLA_GENEVE_TTL, IFLA_GENEVE_TOS,
            IFLA_GENEVE_PORT, IFLA_GENEVE_COLLECT_METADATA, IFLA_GENEVE_REMOTE6,
            IFLA_GENEVE_UDP_CSUM, IFLA_GENEVE_UDP_ZERO_CSUM6_TX, IFLA_GENEVE_UDP_ZERO_CSUM6_RX,
            IFLA_GENEVE_LABEL, IFLA_GENEVE_TTL_INHERIT, IFLA_GENEVE_DF, IFLA_GENEVE_INNER_PROTO_INHERIT
        };
        static const int known_geneve_count = sizeof(known_geneve_attrs) / sizeof(known_geneve_attrs[0]);
        
        memset(&link->geneve, 0, sizeof(geneve_info_t));
        
        for (; RTA_OK(rta, data_len); rta = RTA_NEXT(rta, data_len)) {
            track_unknown_attr(link->unknown_info_data_attrs, 
                              &link->unknown_info_data_attrs_count,
                              64, rta->rta_type, known_geneve_attrs, known_geneve_count);
            
            switch (rta->rta_type) {
                case IFLA_GENEVE_ID:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->geneve.id = *(unsigned int*)RTA_DATA(rta);
                        link->geneve.has_id = 1;
                    }
                    break;
                case IFLA_GENEVE_REMOTE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->geneve.remote = *(unsigned int*)RTA_DATA(rta);
                        link->geneve.has_remote = 1;
                    }
                    break;
                case IFLA_GENEVE_TTL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.ttl = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_ttl = 1;
                    }
                    break;
                case IFLA_GENEVE_TOS:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.tos = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_tos = 1;
                    }
                    break;
                case IFLA_GENEVE_PORT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        link->geneve.port = ntohs(*(unsigned short*)RTA_DATA(rta));
                        link->geneve.has_port = 1;
                    }
                    break;
                case IFLA_GENEVE_COLLECT_METADATA:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.collect_metadata = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_collect_metadata = 1;
                    }
                    break;
                case IFLA_GENEVE_REMOTE6:
                    if (RTA_PAYLOAD(rta) >= 16) {
                        memcpy(link->geneve.remote6, RTA_DATA(rta), 16);
                        link->geneve.has_remote6 = 1;
                    }
                    break;
                case IFLA_GENEVE_UDP_CSUM:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.udp_csum = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_udp_csum = 1;
                    }
                    break;
                case IFLA_GENEVE_UDP_ZERO_CSUM6_TX:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.udp_zero_csum6_tx = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_udp_zero_csum6_tx = 1;
                    }
                    break;
                case IFLA_GENEVE_UDP_ZERO_CSUM6_RX:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.udp_zero_csum6_rx = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_udp_zero_csum6_rx = 1;
                    }
                    break;
                case IFLA_GENEVE_LABEL:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->geneve.label = ntohl(*(unsigned int*)RTA_DATA(rta));
                        link->geneve.has_label = 1;
                    }
                    break;
                case IFLA_GENEVE_TTL_INHERIT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.ttl_inherit = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_ttl_inherit = 1;
                    }
                    break;
                case IFLA_GENEVE_DF:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.df = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_df = 1;
                    }
                    break;
                case IFLA_GENEVE_INNER_PROTO_INHERIT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->geneve.inner_proto_inherit = *(unsigned char*)RTA_DATA(rta);
                        link->geneve.has_inner_proto_inherit = 1;
                    }
                    break;
            }
        }        
    } else {
        for (; RTA_OK(rta, data_len); rta = RTA_NEXT(rta, data_len)) {
            static const unsigned short known_attrs[] = { 0 };
            track_unknown_attr(link->unknown_info_data_attrs, 
                              &link->unknown_info_data_attrs_count,
                              64, rta->rta_type, known_attrs, 0);
        }
    }
}

void nl_parse_linkinfo(struct rtattr* linkinfo_attr, link_info_t* link) {
    if (!linkinfo_attr || !link) return;
    
    int info_len = RTA_PAYLOAD(linkinfo_attr);
    struct rtattr* rta = RTA_DATA(linkinfo_attr);
    struct rtattr* info_data_attr = NULL;
    struct rtattr* slave_data_attr = NULL;
    
    link->unknown_linkinfo_attrs_count = 0;
    
    static const unsigned short known_linkinfo_attrs[] = { IFLA_INFO_KIND, IFLA_INFO_DATA, IFLA_INFO_SLAVE_KIND, IFLA_INFO_SLAVE_DATA };
    static const int known_linkinfo_count = sizeof(known_linkinfo_attrs) / sizeof(known_linkinfo_attrs[0]);
    
    struct rtattr* scan_rta = rta;
    int scan_len = info_len;
    
    for (; RTA_OK(scan_rta, scan_len); scan_rta = RTA_NEXT(scan_rta, scan_len)) {
        track_unknown_attr(link->unknown_linkinfo_attrs, 
                          &link->unknown_linkinfo_attrs_count,
                          64, scan_rta->rta_type, known_linkinfo_attrs, known_linkinfo_count);
        
        switch (scan_rta->rta_type) {
            case IFLA_INFO_KIND:
                if (RTA_PAYLOAD(scan_rta) > 0 && RTA_PAYLOAD(scan_rta) < 32) {
                    strncpy(link->kind, RTA_DATA(scan_rta), 31);
                    link->kind[31] = '\0';
                    link->has_kind = 1;
                }
                break;
            case IFLA_INFO_DATA:
                info_data_attr = scan_rta;
                break;
            case IFLA_INFO_SLAVE_KIND:
                if (RTA_PAYLOAD(scan_rta) > 0 && RTA_PAYLOAD(scan_rta) < 32) {
                    strncpy(link->slave_kind, RTA_DATA(scan_rta), 31);
                    link->slave_kind[31] = '\0';
                    link->has_slave_kind = 1;
                }
                break;
            case IFLA_INFO_SLAVE_DATA:
                slave_data_attr = scan_rta;
                break;
        }
    }
    
    if (link->has_kind && info_data_attr) {
        nl_parse_info_data(link->kind, info_data_attr, link);
    }
    
    if (link->has_slave_kind && slave_data_attr) {
        if (strcmp(link->slave_kind, "bridge") == 0) {
            nl_parse_bridge_slave_data(slave_data_attr, link);
        }
    }
}

int nl_parse_link_stats(struct rtattr* rta, link_stats_t* stats, int current_priority) {
    if (!rta || !stats) return 0;
    
    if (rta->rta_type == IFLA_STATS64) {
        if (RTA_PAYLOAD(rta) >= sizeof(struct rtnl_link_stats64)) {
            struct rtnl_link_stats64* s = (struct rtnl_link_stats64*)RTA_DATA(rta);
            stats->rx_packets = s->rx_packets;
            stats->tx_packets = s->tx_packets;
            stats->rx_bytes = s->rx_bytes;
            stats->tx_bytes = s->tx_bytes;
            stats->rx_errors = s->rx_errors;
            stats->tx_errors = s->tx_errors;
            stats->rx_dropped = s->rx_dropped;
            stats->tx_dropped = s->tx_dropped;
            stats->multicast = s->multicast;
            stats->collisions = s->collisions;
            stats->rx_length_errors = s->rx_length_errors;
            stats->rx_over_errors = s->rx_over_errors;
            stats->rx_crc_errors = s->rx_crc_errors;
            stats->rx_frame_errors = s->rx_frame_errors;
            stats->rx_fifo_errors = s->rx_fifo_errors;
            stats->rx_missed_errors = s->rx_missed_errors;
            stats->tx_aborted_errors = s->tx_aborted_errors;
            stats->tx_carrier_errors = s->tx_carrier_errors;
            stats->tx_fifo_errors = s->tx_fifo_errors;
            stats->tx_heartbeat_errors = s->tx_heartbeat_errors;
            stats->tx_window_errors = s->tx_window_errors;
            stats->rx_compressed = s->rx_compressed;
            stats->tx_compressed = s->tx_compressed;
            stats->rx_nohandler = s->rx_nohandler;
            stats->has_stats64 = 1;
            return 2;
        }
    } else if (rta->rta_type == IFLA_STATS) {
        if (current_priority < 2 && RTA_PAYLOAD(rta) >= sizeof(struct rtnl_link_stats)) {
            struct rtnl_link_stats* s = (struct rtnl_link_stats*)RTA_DATA(rta);
            stats->rx_packets = s->rx_packets;
            stats->tx_packets = s->tx_packets;
            stats->rx_bytes = s->rx_bytes;
            stats->tx_bytes = s->tx_bytes;
            stats->rx_errors = s->rx_errors;
            stats->tx_errors = s->tx_errors;
            stats->rx_dropped = s->rx_dropped;
            stats->tx_dropped = s->tx_dropped;
            stats->multicast = s->multicast;
            stats->collisions = s->collisions;
            stats->rx_length_errors = s->rx_length_errors;
            stats->rx_over_errors = s->rx_over_errors;
            stats->rx_crc_errors = s->rx_crc_errors;
            stats->rx_frame_errors = s->rx_frame_errors;
            stats->rx_fifo_errors = s->rx_fifo_errors;
            stats->rx_missed_errors = s->rx_missed_errors;
            stats->tx_aborted_errors = s->tx_aborted_errors;
            stats->tx_carrier_errors = s->tx_carrier_errors;
            stats->tx_fifo_errors = s->tx_fifo_errors;
            stats->tx_heartbeat_errors = s->tx_heartbeat_errors;
            stats->tx_window_errors = s->tx_window_errors;
            stats->rx_compressed = s->rx_compressed;
            stats->tx_compressed = s->tx_compressed;
            stats->rx_nohandler = s->rx_nohandler;
            stats->has_stats64 = 0;
            return 1;
        }
    }
    
    return current_priority;
}




int nl_parse_links(response_buffer_t* buf, link_info_t** links, int* count, link_stats_t** stats) {
    if (!buf || !links || !count || !stats) return -1;
    
    *count = 0;
    *links = NULL;
    *stats = NULL;
    
    if (buf->length == 0) {
        return -1;
    }
    
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf->data;
    int max_count = 0;
    size_t remaining = buf->length;
    
    // First pass: count messages with matching sequence number
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        // Only count messages with the correct sequence number
        if (nlh->nlmsg_type == RTM_NEWLINK && nlh->nlmsg_seq == buf->seq) {
            max_count++;
        }
    }
    
    if (max_count == 0) return 0;
    
    *links = calloc(max_count, sizeof(link_info_t));
    if (!*links) {
        return -1;
    }
    
    *stats = calloc(max_count, sizeof(link_stats_t));
    if (!*stats) {
        free(*links);
        *links = NULL;
        return -1;
    }
    
    nlh = (struct nlmsghdr*)buf->data;
    remaining = buf->length;
    
    // Second pass: process messages with matching sequence number
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type != RTM_NEWLINK) continue;
        
        // Skip messages with incorrect sequence number
        if (nlh->nlmsg_seq != buf->seq) continue;
        
        struct ifinfomsg* ifi = NLMSG_DATA(nlh);
        link_info_t* link = &(*links)[*count];
        link_stats_t* stat = &(*stats)[*count];
        
        link->index = ifi->ifi_index;
        link->type = ifi->ifi_type;
        link->flags = ifi->ifi_flags;
        link->has_mac = 0;
        link->has_broadcast = 0;
        link->has_perm_address = 0;
        link->has_txqlen = 0;
        link->has_qdisc = 0;
        link->has_ifalias = 0;
        link->has_kind = 0;
        link->has_master = 0;
        link->has_link = 0;
        link->has_parent_dev_name = 0;
        link->has_vlan_id = 0;
        link->has_vlan_flags = 0;
        link->has_vlan_protocol = 0;
        link->has_veth_peer = 0;
        link->has_bridge_forward_delay = 0;
        link->has_tunnel_local = 0;
        link->has_tunnel_remote = 0;
        link->has_slave_kind = 0;
        link->has_linkmode = 0;
        link->has_min_mtu = 0;
        link->has_max_mtu = 0;
        link->has_group = 0;
        link->has_promiscuity = 0;
        link->has_allmulti = 0;
        link->has_num_tx_queues = 0;
        link->has_num_rx_queues = 0;
        link->has_gso_max_segs = 0;
        link->has_gso_max_size = 0;
        link->has_gro_max_size = 0;
        link->has_gso_ipv4_max_size = 0;
        link->has_gro_ipv4_max_size = 0;
        link->has_tso_max_size = 0;
        link->has_tso_max_segs = 0;
        link->has_carrier = 0;
        link->has_carrier_changes = 0;
        link->has_carrier_up_count = 0;
        link->has_carrier_down_count = 0;
        link->has_proto_down = 0;
        link->has_map = 0;
        link->unknown_ifla_attrs_count = 0;
        link->unknown_linkinfo_attrs_count = 0;
        link->unknown_info_data_attrs_count = 0;
        memset(link->name, 0, IFNAMSIZ);
        memset(link->qdisc, 0, 32);
        memset(link->ifalias, 0, 256);
        memset(link->kind, 0, 32);
        memset(link->slave_kind, 0, 32);
        memset(stat, 0, sizeof(link_stats_t));
        memset(&link->bridge_port, 0, sizeof(bridge_port_info_t));
        memset(&link->bridge_config, 0, sizeof(bridge_config_t));
        memset(&link->wireguard, 0, sizeof(wg_device_info_t));
        memset(&link->dpll_pin, 0, sizeof(dpll_pin_info_t));
        
        int stats_priority = 0;
        
        static const unsigned short known_ifla_attrs[] = {
            IFLA_IFNAME, IFLA_MTU, IFLA_LINK, IFLA_ADDRESS, IFLA_BROADCAST, IFLA_OPERSTATE,
            IFLA_STATS, IFLA_MASTER, IFLA_TXQLEN, IFLA_QDISC, IFLA_IFALIAS,
            IFLA_LINKINFO, IFLA_PROTINFO, IFLA_STATS64,
            IFLA_LINKMODE, IFLA_MIN_MTU, IFLA_MAX_MTU, IFLA_GROUP, IFLA_PROMISCUITY, IFLA_ALLMULTI,
            IFLA_NUM_TX_QUEUES, IFLA_GSO_MAX_SEGS, IFLA_GSO_MAX_SIZE, IFLA_GRO_MAX_SIZE,
            IFLA_GSO_IPV4_MAX_SIZE, IFLA_GRO_IPV4_MAX_SIZE, IFLA_TSO_MAX_SIZE, IFLA_TSO_MAX_SEGS,
            IFLA_NUM_RX_QUEUES, IFLA_CARRIER, IFLA_CARRIER_CHANGES, IFLA_CARRIER_UP_COUNT,
            IFLA_CARRIER_DOWN_COUNT, IFLA_PROTO_DOWN, IFLA_MAP, IFLA_XDP, IFLA_AF_SPEC,
            IFLA_PERM_ADDRESS, IFLA_PARENT_DEV_NAME,
            IFLA_DPLL_PIN
        };
        static const int known_ifla_count = sizeof(known_ifla_attrs) / sizeof(known_ifla_attrs[0]);
        
        struct rtattr* rta = IFLA_RTA(ifi);
        int rta_len = IFLA_PAYLOAD(nlh);
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            track_unknown_attr(link->unknown_ifla_attrs, 
                              &link->unknown_ifla_attrs_count,
                              64, rta->rta_type, known_ifla_attrs, known_ifla_count);
            
            // Strip flags to get base attribute type
            unsigned short attr_type = rta->rta_type & NLA_TYPE_MASK;
            
            switch (attr_type) {
                case IFLA_IFNAME:
                    strncpy(link->name, RTA_DATA(rta), IFNAMSIZ - 1);
                    link->name[IFNAMSIZ - 1] = '\0';
                    break;
                case IFLA_MTU:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->mtu = *(unsigned int*)RTA_DATA(rta);
                    }
                    break;
                case IFLA_ADDRESS:
                    if (RTA_PAYLOAD(rta) == 6) {
                        memcpy(link->mac, RTA_DATA(rta), 6);
                        link->has_mac = 1;
                    }
                    break;
                case IFLA_BROADCAST:
                    if (RTA_PAYLOAD(rta) == 6) {
                        memcpy(link->broadcast, RTA_DATA(rta), 6);
                        link->has_broadcast = 1;
                    }
                    break;
                case IFLA_PERM_ADDRESS:
                    if (RTA_PAYLOAD(rta) == 6) {
                        memcpy(link->perm_address, RTA_DATA(rta), 6);
                        link->has_perm_address = 1;
                    }
                    break;
                case IFLA_OPERSTATE:
                    if (RTA_PAYLOAD(rta) >= 1) {
                        link->operstate = *(unsigned char*)RTA_DATA(rta);
                    }
                    break;
                case IFLA_LINK:
                    if (RTA_PAYLOAD(rta) >= sizeof(int)) {
                        link->link_index = *(int*)RTA_DATA(rta);
                        link->has_link = 1;
                    }
                    break;
                case IFLA_MASTER:
                    if (RTA_PAYLOAD(rta) >= sizeof(int)) {
                        link->master_index = *(int*)RTA_DATA(rta);
                        link->has_master = 1;
                    }
                    break;
                case IFLA_PARENT_DEV_NAME:
                    if (RTA_PAYLOAD(rta) > 0) {
                        strncpy(link->parent_dev_name, RTA_DATA(rta), IFNAMSIZ - 1);
                        link->parent_dev_name[IFNAMSIZ - 1] = '\0';
                        link->has_parent_dev_name = 1;
                    }
                    break;
                case IFLA_TXQLEN:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->txqlen = *(unsigned int*)RTA_DATA(rta);
                        link->has_txqlen = 1;
                    }
                    break;
                case IFLA_QDISC:
                    if (RTA_PAYLOAD(rta) > 0) {
                        strncpy(link->qdisc, RTA_DATA(rta), 31);
                        link->qdisc[31] = '\0';
                        link->has_qdisc = 1;
                    }
                    break;
                case IFLA_IFALIAS:
                    if (RTA_PAYLOAD(rta) > 0) {
                        strncpy(link->ifalias, RTA_DATA(rta), 255);
                        link->ifalias[255] = '\0';
                        link->has_ifalias = 1;
                    }
                    break;
                case IFLA_LINKINFO:
                    nl_parse_linkinfo(rta, link);
                    break;
                case IFLA_PROTINFO:
                    nl_parse_protinfo(rta, link);
                    break;
                case IFLA_STATS:
                case IFLA_STATS64:
                    stats_priority = nl_parse_link_stats(rta, stat, stats_priority);
                    break;
                case IFLA_LINKMODE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->linkmode = *(unsigned char*)RTA_DATA(rta);
                        link->has_linkmode = 1;
                    }
                    break;
                case IFLA_MIN_MTU:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->min_mtu = *(unsigned int*)RTA_DATA(rta);
                        link->has_min_mtu = 1;
                    }
                    break;
                case IFLA_MAX_MTU:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->max_mtu = *(unsigned int*)RTA_DATA(rta);
                        link->has_max_mtu = 1;
                    }
                    break;
                case IFLA_GROUP:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->group = *(unsigned int*)RTA_DATA(rta);
                        link->has_group = 1;
                    }
                    break;
                case IFLA_PROMISCUITY:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->promiscuity = *(unsigned int*)RTA_DATA(rta);
                        link->has_promiscuity = 1;
                    }
                    break;
                case IFLA_ALLMULTI:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->allmulti = *(unsigned int*)RTA_DATA(rta);
                        link->has_allmulti = 1;
                    }
                    break;
                case IFLA_NUM_TX_QUEUES:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->num_tx_queues = *(unsigned int*)RTA_DATA(rta);
                        link->has_num_tx_queues = 1;
                    }
                    break;
                case IFLA_NUM_RX_QUEUES:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->num_rx_queues = *(unsigned int*)RTA_DATA(rta);
                        link->has_num_rx_queues = 1;
                    }
                    break;
                case IFLA_GSO_MAX_SEGS:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->gso_max_segs = *(unsigned int*)RTA_DATA(rta);
                        link->has_gso_max_segs = 1;
                    }
                    break;
                case IFLA_GSO_MAX_SIZE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->gso_max_size = *(unsigned int*)RTA_DATA(rta);
                        link->has_gso_max_size = 1;
                    }
                    break;
                case IFLA_GRO_MAX_SIZE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->gro_max_size = *(unsigned int*)RTA_DATA(rta);
                        link->has_gro_max_size = 1;
                    }
                    break;
                case IFLA_GSO_IPV4_MAX_SIZE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->gso_ipv4_max_size = *(unsigned int*)RTA_DATA(rta);
                        link->has_gso_ipv4_max_size = 1;
                    }
                    break;
                case IFLA_GRO_IPV4_MAX_SIZE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->gro_ipv4_max_size = *(unsigned int*)RTA_DATA(rta);
                        link->has_gro_ipv4_max_size = 1;
                    }
                    break;
                case IFLA_TSO_MAX_SIZE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->tso_max_size = *(unsigned int*)RTA_DATA(rta);
                        link->has_tso_max_size = 1;
                    }
                    break;
                case IFLA_TSO_MAX_SEGS:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->tso_max_segs = *(unsigned int*)RTA_DATA(rta);
                        link->has_tso_max_segs = 1;
                    }
                    break;
                case IFLA_CARRIER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->carrier = *(unsigned char*)RTA_DATA(rta);
                        link->has_carrier = 1;
                    }
                    break;
                case IFLA_CARRIER_CHANGES:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->carrier_changes = *(unsigned int*)RTA_DATA(rta);
                        link->has_carrier_changes = 1;
                    }
                    break;
                case IFLA_CARRIER_UP_COUNT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->carrier_up_count = *(unsigned int*)RTA_DATA(rta);
                        link->has_carrier_up_count = 1;
                    }
                    break;
                case IFLA_CARRIER_DOWN_COUNT:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        link->carrier_down_count = *(unsigned int*)RTA_DATA(rta);
                        link->has_carrier_down_count = 1;
                    }
                    break;
                case IFLA_PROTO_DOWN:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        link->proto_down = *(unsigned char*)RTA_DATA(rta);
                        link->has_proto_down = 1;
                    }
                    break;
                case IFLA_MAP:
                    if (RTA_PAYLOAD(rta) >= 32) {
                        unsigned long long* map_data = (unsigned long long*)RTA_DATA(rta);
                        link->map_mem_start = map_data[0];
                        link->map_mem_end = map_data[1];
                        link->map_base_addr = map_data[2];
                        unsigned short* map_short = (unsigned short*)&map_data[3];
                        link->map_irq = map_short[0];
                        unsigned char* map_byte = (unsigned char*)&map_short[1];
                        link->map_dma = map_byte[0];
                        link->map_port = map_byte[1];
                        link->has_map = 1;
                    }
                    break;
                case IFLA_DPLL_PIN:  // nested DPLL pin information
                    nl_parse_dpll_pin(rta, &link->dpll_pin);
                    break;
                case IFLA_XDP:  // nested, skip for now
                case IFLA_AF_SPEC:  // nested, skip for now
                    break;
            }
        }
        
        (*count)++;
    }
    
    return 0;
}

int nl_parse_addrs(response_buffer_t* buf, addr_info_t** addrs, int* count) {
    if (!buf || !addrs || !count) return -1;
    
    *count = 0;
    *addrs = NULL;
    
    if (buf->length == 0) {
        return -1;
    }
    
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf->data;
    int max_count = 0;
    size_t remaining = buf->length;
    
    // First pass: count messages with matching sequence number
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        // Only count messages with the correct sequence number
        if (nlh->nlmsg_type == RTM_NEWADDR && nlh->nlmsg_seq == buf->seq) {
            max_count++;
        }
    }
    
    if (max_count == 0) return 0;
    
    *addrs = calloc(max_count, sizeof(addr_info_t));
    if (!*addrs) {
        return -1;
    }
    
    nlh = (struct nlmsghdr*)buf->data;
    remaining = buf->length;
    
    // Second pass: process messages with matching sequence number
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type != RTM_NEWADDR) continue;
        
        // Skip messages with incorrect sequence number
        if (nlh->nlmsg_seq != buf->seq) continue;
        
        struct ifaddrmsg* ifa = NLMSG_DATA(nlh);
        addr_info_t* addr = &(*addrs)[*count];
        
        addr->index = ifa->ifa_index;
        addr->family = ifa->ifa_family;
        addr->prefixlen = ifa->ifa_prefixlen;
        addr->flags = ifa->ifa_flags;
        addr->scope = ifa->ifa_scope;
        addr->has_local = 0;
        addr->has_broadcast = 0;
        addr->has_cacheinfo = 0;
        addr->has_extended_flags = 0;
        addr->has_protocol = 0;
        addr->unknown_ifa_attrs_count = 0;
        
        static const unsigned short known_ifa_attrs[] = {
            IFA_ADDRESS, IFA_LOCAL, IFA_BROADCAST, IFA_LABEL, IFA_CACHEINFO, IFA_FLAGS, IFA_PROTO
        };
        static const int known_ifa_count = sizeof(known_ifa_attrs) / sizeof(known_ifa_attrs[0]);
        
        struct rtattr* rta = IFA_RTA(ifa);
        int rta_len = IFA_PAYLOAD(nlh);
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            track_unknown_attr(addr->unknown_ifa_attrs, 
                              &addr->unknown_ifa_attrs_count,
                              64, rta->rta_type, known_ifa_attrs, known_ifa_count);
            
            // Strip flags to get base attribute type
            unsigned short attr_type = rta->rta_type & NLA_TYPE_MASK;
            
            switch (attr_type) {
                case IFA_ADDRESS:
                    if (RTA_PAYLOAD(rta) >= (ifa->ifa_family == AF_INET ? 4 : 16)) {
                        memcpy(addr->address, RTA_DATA(rta), 
                               ifa->ifa_family == AF_INET ? 4 : 16);
                    }
                    break;
                case IFA_LOCAL:
                    if (RTA_PAYLOAD(rta) >= (ifa->ifa_family == AF_INET ? 4 : 16)) {
                        memcpy(addr->local, RTA_DATA(rta), 
                               ifa->ifa_family == AF_INET ? 4 : 16);
                        addr->has_local = 1;
                    }
                    break;
                case IFA_BROADCAST:
                    if (RTA_PAYLOAD(rta) >= (ifa->ifa_family == AF_INET ? 4 : 16)) {
                        memcpy(addr->broadcast, RTA_DATA(rta), 
                               ifa->ifa_family == AF_INET ? 4 : 16);
                        addr->has_broadcast = 1;
                    }
                    break;
                case IFA_LABEL:
                    strncpy(addr->label, RTA_DATA(rta), IFNAMSIZ - 1);
                    addr->label[IFNAMSIZ - 1] = '\0';
                    break;
                case IFA_CACHEINFO:
                    if (RTA_PAYLOAD(rta) >= 16) {
                        unsigned int* cache = (unsigned int*)RTA_DATA(rta);
                        addr->preferred_lft = cache[0];
                        addr->valid_lft = cache[1];
                        addr->created_tstamp = cache[2];
                        addr->updated_tstamp = cache[3];
                        addr->has_cacheinfo = 1;
                    }
                    break;
                case IFA_FLAGS:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        addr->extended_flags = *(unsigned int*)RTA_DATA(rta);
                        addr->has_extended_flags = 1;
                    }
                    break;
                case IFA_PROTO:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned char)) {
                        addr->protocol = *(unsigned char*)RTA_DATA(rta);
                        addr->has_protocol = 1;
                    }
                    break;
            }
        }
        
        (*count)++;
    }
    
    return 0;
}

void nl_free_links(link_info_t* links, int count) {
    if (links) {
        for (int i = 0; i < count; i++) {
            genl_free_wireguard(&links[i].wireguard);
        }
        free(links);
    }
}

void nl_free_stats(link_stats_t* stats) {
    if (stats) free(stats);
}

void nl_free_addrs(addr_info_t* addrs) {
    if (addrs) free(addrs);
}

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif
#ifndef IFF_DORMANT
#define IFF_DORMANT 0x20000
#endif
#ifndef IFF_ECHO
#define IFF_ECHO 0x40000
#endif

// Address flags
#ifndef IFA_F_SECONDARY
#define IFA_F_SECONDARY 0x01
#endif
#ifndef IFA_F_TEMPORARY
#define IFA_F_TEMPORARY 0x01
#endif
#ifndef IFA_F_NODAD
#define IFA_F_NODAD 0x02
#endif
#ifndef IFA_F_OPTIMISTIC
#define IFA_F_OPTIMISTIC 0x04
#endif
#ifndef IFA_F_DADFAILED
#define IFA_F_DADFAILED 0x08
#endif
#ifndef IFA_F_HOMEADDRESS
#define IFA_F_HOMEADDRESS 0x10
#endif
#ifndef IFA_F_DEPRECATED
#define IFA_F_DEPRECATED 0x20
#endif
#ifndef IFA_F_TENTATIVE
#define IFA_F_TENTATIVE 0x40
#endif
#ifndef IFA_F_PERMANENT
#define IFA_F_PERMANENT 0x80
#endif
#ifndef IFA_F_MANAGETEMPADDR
#define IFA_F_MANAGETEMPADDR 0x100
#endif
#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif
#ifndef IFA_F_MCAUTOJOIN
#define IFA_F_MCAUTOJOIN 0x400
#endif
#ifndef IFA_F_STABLE_PRIVACY
#define IFA_F_STABLE_PRIVACY 0x800
#endif

// Ethernet protocol values (from <linux/if_ether.h>)
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

// VLAN flag values (from <linux/if_vlan.h>)
#ifndef VLAN_FLAG_REORDER_HDR
#define VLAN_FLAG_REORDER_HDR 0x1
#endif
#ifndef VLAN_FLAG_GVRP
#define VLAN_FLAG_GVRP 0x2
#endif
#ifndef VLAN_FLAG_LOOSE_BINDING
#define VLAN_FLAG_LOOSE_BINDING 0x4
#endif
#ifndef VLAN_FLAG_MVRP
#define VLAN_FLAG_MVRP 0x8
#endif
#ifndef VLAN_FLAG_BRIDGE_BINDING
#define VLAN_FLAG_BRIDGE_BINDING 0x10
#endif

// DPLL pin type values
#ifndef DPLL_PIN_TYPE_MUX
#define DPLL_PIN_TYPE_MUX 1
#define DPLL_PIN_TYPE_EXT 2
#define DPLL_PIN_TYPE_SYNCE_ETH_PORT 3
#define DPLL_PIN_TYPE_INT_OSCILLATOR 4
#define DPLL_PIN_TYPE_GNSS 5
#endif

// DPLL pin direction values
#ifndef DPLL_PIN_DIRECTION_INPUT
#define DPLL_PIN_DIRECTION_INPUT 1
#define DPLL_PIN_DIRECTION_OUTPUT 2
#endif

// DPLL pin state values
#ifndef DPLL_PIN_STATE_CONNECTED
#define DPLL_PIN_STATE_CONNECTED 1
#define DPLL_PIN_STATE_DISCONNECTED 2
#define DPLL_PIN_STATE_SELECTABLE 3
#endif

// DPLL pin capabilities
#ifndef DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE
#define DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE 0x1
#define DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE 0x2
#define DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE 0x4
#endif

// Multicast router modes
#ifndef MDB_RTR_TYPE_DISABLED
#define MDB_RTR_TYPE_DISABLED 0
#define MDB_RTR_TYPE_TEMP_QUERY 1
#define MDB_RTR_TYPE_PERM 2
#endif

// GENEVE DF (Don't Fragment) modes
#ifndef GENEVE_DF_UNSET
#define GENEVE_DF_UNSET 0
#define GENEVE_DF_SET 1
#define GENEVE_DF_INHERIT 2
#endif

// Netlink attribute type flags
int nl_get_nla_f_nested(void) { return NLA_F_NESTED; }
int nl_get_nla_type_mask(void) { return NLA_TYPE_MASK; }

// Address family constants
int nl_get_af_inet(void) { return AF_INET; }
int nl_get_af_inet6(void) { return AF_INET6; }

// Ethernet protocol constants
int nl_get_eth_p_8021q(void) { return ETH_P_8021Q; }
int nl_get_eth_p_8021ad(void) { return ETH_P_8021AD; }

// VLAN flag constants
int nl_get_vlan_flag_reorder_hdr(void) { return VLAN_FLAG_REORDER_HDR; }
int nl_get_vlan_flag_gvrp(void) { return VLAN_FLAG_GVRP; }
int nl_get_vlan_flag_loose_binding(void) { return VLAN_FLAG_LOOSE_BINDING; }
int nl_get_vlan_flag_mvrp(void) { return VLAN_FLAG_MVRP; }
int nl_get_vlan_flag_bridge_binding(void) { return VLAN_FLAG_BRIDGE_BINDING; }

// DPLL pin type constants
int nl_get_dpll_pin_type_mux(void) { return DPLL_PIN_TYPE_MUX; }
int nl_get_dpll_pin_type_ext(void) { return DPLL_PIN_TYPE_EXT; }
int nl_get_dpll_pin_type_synce_eth_port(void) { return DPLL_PIN_TYPE_SYNCE_ETH_PORT; }
int nl_get_dpll_pin_type_int_oscillator(void) { return DPLL_PIN_TYPE_INT_OSCILLATOR; }
int nl_get_dpll_pin_type_gnss(void) { return DPLL_PIN_TYPE_GNSS; }

// DPLL pin direction constants
int nl_get_dpll_pin_direction_input(void) { return DPLL_PIN_DIRECTION_INPUT; }
int nl_get_dpll_pin_direction_output(void) { return DPLL_PIN_DIRECTION_OUTPUT; }

// DPLL pin state constants
int nl_get_dpll_pin_state_connected(void) { return DPLL_PIN_STATE_CONNECTED; }
int nl_get_dpll_pin_state_disconnected(void) { return DPLL_PIN_STATE_DISCONNECTED; }
int nl_get_dpll_pin_state_selectable(void) { return DPLL_PIN_STATE_SELECTABLE; }

// DPLL pin capability constants
int nl_get_dpll_pin_cap_direction_can_change(void) { return DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE; }
int nl_get_dpll_pin_cap_priority_can_change(void) { return DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE; }
int nl_get_dpll_pin_cap_state_can_change(void) { return DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE; }

// Multicast router mode constants
int nl_get_mdb_rtr_type_disabled(void) { return MDB_RTR_TYPE_DISABLED; }
int nl_get_mdb_rtr_type_temp_query(void) { return MDB_RTR_TYPE_TEMP_QUERY; }
int nl_get_mdb_rtr_type_perm(void) { return MDB_RTR_TYPE_PERM; }

// GENEVE DF mode constants
int nl_get_geneve_df_unset(void) { return GENEVE_DF_UNSET; }
int nl_get_geneve_df_set(void) { return GENEVE_DF_SET; }
int nl_get_geneve_df_inherit(void) { return GENEVE_DF_INHERIT; }

// IFLA_* attribute constants (from <linux/if_link.h>)
int nl_get_ifla_unspec(void) { return IFLA_UNSPEC; }
int nl_get_ifla_address(void) { return IFLA_ADDRESS; }
int nl_get_ifla_broadcast(void) { return IFLA_BROADCAST; }
int nl_get_ifla_ifname(void) { return IFLA_IFNAME; }
int nl_get_ifla_mtu(void) { return IFLA_MTU; }
int nl_get_ifla_link(void) { return IFLA_LINK; }
int nl_get_ifla_qdisc(void) { return IFLA_QDISC; }
int nl_get_ifla_stats(void) { return IFLA_STATS; }
#ifdef IFLA_COST
int nl_get_ifla_cost(void) { return IFLA_COST; }
#else
int nl_get_ifla_cost(void) { return 8; }
#endif
#ifdef IFLA_PRIORITY
int nl_get_ifla_priority(void) { return IFLA_PRIORITY; }
#else
int nl_get_ifla_priority(void) { return 9; }
#endif
int nl_get_ifla_master(void) { return IFLA_MASTER; }
int nl_get_ifla_wireless(void) { return IFLA_WIRELESS; }
int nl_get_ifla_protinfo(void) { return IFLA_PROTINFO; }
int nl_get_ifla_txqlen(void) { return IFLA_TXQLEN; }
int nl_get_ifla_map(void) { return IFLA_MAP; }
int nl_get_ifla_weight(void) { return IFLA_WEIGHT; }
int nl_get_ifla_operstate(void) { return IFLA_OPERSTATE; }
int nl_get_ifla_linkmode(void) { return IFLA_LINKMODE; }
int nl_get_ifla_linkinfo(void) { return IFLA_LINKINFO; }
int nl_get_ifla_net_ns_pid(void) { return IFLA_NET_NS_PID; }
int nl_get_ifla_ifalias(void) { return IFLA_IFALIAS; }
int nl_get_ifla_num_vf(void) { return IFLA_NUM_VF; }
int nl_get_ifla_vfinfo_list(void) { return IFLA_VFINFO_LIST; }
int nl_get_ifla_stats64(void) { return IFLA_STATS64; }
int nl_get_ifla_vf_ports(void) { return IFLA_VF_PORTS; }
int nl_get_ifla_port_self(void) { return IFLA_PORT_SELF; }
int nl_get_ifla_af_spec(void) { return IFLA_AF_SPEC; }
int nl_get_ifla_group(void) { return IFLA_GROUP; }
int nl_get_ifla_net_ns_fd(void) { return IFLA_NET_NS_FD; }
int nl_get_ifla_ext_mask(void) { return IFLA_EXT_MASK; }
int nl_get_ifla_promiscuity(void) { return IFLA_PROMISCUITY; }
int nl_get_ifla_num_tx_queues(void) { return IFLA_NUM_TX_QUEUES; }
int nl_get_ifla_num_rx_queues(void) { return IFLA_NUM_RX_QUEUES; }
int nl_get_ifla_carrier(void) { return IFLA_CARRIER; }
int nl_get_ifla_phys_port_id(void) { return IFLA_PHYS_PORT_ID; }
int nl_get_ifla_carrier_changes(void) { return IFLA_CARRIER_CHANGES; }
int nl_get_ifla_phys_switch_id(void) { return IFLA_PHYS_SWITCH_ID; }
int nl_get_ifla_link_netnsid(void) { return IFLA_LINK_NETNSID; }
int nl_get_ifla_phys_port_name(void) { return IFLA_PHYS_PORT_NAME; }
int nl_get_ifla_proto_down(void) { return IFLA_PROTO_DOWN; }
int nl_get_ifla_gso_max_segs(void) { return IFLA_GSO_MAX_SEGS; }
int nl_get_ifla_gso_max_size(void) { return IFLA_GSO_MAX_SIZE; }
int nl_get_ifla_pad(void) { return IFLA_PAD; }
int nl_get_ifla_xdp(void) { return IFLA_XDP; }
int nl_get_ifla_event(void) { return IFLA_EVENT; }
int nl_get_ifla_new_netnsid(void) { return IFLA_NEW_NETNSID; }
int nl_get_ifla_target_netnsid(void) { return IFLA_TARGET_NETNSID; }
int nl_get_ifla_carrier_up_count(void) { return IFLA_CARRIER_UP_COUNT; }
int nl_get_ifla_carrier_down_count(void) { return IFLA_CARRIER_DOWN_COUNT; }
int nl_get_ifla_new_ifindex(void) { return IFLA_NEW_IFINDEX; }
int nl_get_ifla_min_mtu(void) { return IFLA_MIN_MTU; }
int nl_get_ifla_max_mtu(void) { return IFLA_MAX_MTU; }
#ifdef IFLA_PROP_LIST
int nl_get_ifla_prop_list(void) { return IFLA_PROP_LIST; }
#else
int nl_get_ifla_prop_list(void) { return 52; }
#endif
#ifdef IFLA_ALT_IFNAME
int nl_get_ifla_alt_ifname(void) { return IFLA_ALT_IFNAME; }
#else
int nl_get_ifla_alt_ifname(void) { return 53; }
#endif
#ifdef IFLA_PERM_ADDRESS
int nl_get_ifla_perm_address(void) { return IFLA_PERM_ADDRESS; }
#else
int nl_get_ifla_perm_address(void) { return 54; }
#endif
#ifdef IFLA_PROTO_DOWN_REASON
int nl_get_ifla_proto_down_reason(void) { return IFLA_PROTO_DOWN_REASON; }
#else
int nl_get_ifla_proto_down_reason(void) { return 55; }
#endif
#ifdef IFLA_PARENT_DEV_NAME
int nl_get_ifla_parent_dev_name(void) { return IFLA_PARENT_DEV_NAME; }
#else
int nl_get_ifla_parent_dev_name(void) { return 56; }
#endif
#ifdef IFLA_PARENT_DEV_BUS_NAME
int nl_get_ifla_parent_dev_bus_name(void) { return IFLA_PARENT_DEV_BUS_NAME; }
#else
int nl_get_ifla_parent_dev_bus_name(void) { return 57; }
#endif
#ifdef IFLA_GRO_MAX_SIZE
int nl_get_ifla_gro_max_size(void) { return IFLA_GRO_MAX_SIZE; }
#else
int nl_get_ifla_gro_max_size(void) { return 58; }
#endif
#ifdef IFLA_TSO_MAX_SIZE
int nl_get_ifla_tso_max_size(void) { return IFLA_TSO_MAX_SIZE; }
#else
int nl_get_ifla_tso_max_size(void) { return 59; }
#endif
#ifdef IFLA_TSO_MAX_SEGS
int nl_get_ifla_tso_max_segs(void) { return IFLA_TSO_MAX_SEGS; }
#else
int nl_get_ifla_tso_max_segs(void) { return 60; }
#endif
#ifdef IFLA_ALLMULTI
int nl_get_ifla_allmulti(void) { return IFLA_ALLMULTI; }
#else
int nl_get_ifla_allmulti(void) { return 61; }
#endif
#ifdef IFLA_DEVLINK_PORT
int nl_get_ifla_devlink_port(void) { return IFLA_DEVLINK_PORT; }
#else
int nl_get_ifla_devlink_port(void) { return 62; }
#endif
#ifdef IFLA_GSO_IPV4_MAX_SIZE
int nl_get_ifla_gso_ipv4_max_size(void) { return IFLA_GSO_IPV4_MAX_SIZE; }
#else
int nl_get_ifla_gso_ipv4_max_size(void) { return 63; }
#endif
#ifdef IFLA_GRO_IPV4_MAX_SIZE
int nl_get_ifla_gro_ipv4_max_size(void) { return IFLA_GRO_IPV4_MAX_SIZE; }
#else
int nl_get_ifla_gro_ipv4_max_size(void) { return 64; }
#endif

// IFA_* attribute constants (from <linux/if_addr.h>)
int nl_get_ifa_unspec(void) { return IFA_UNSPEC; }
int nl_get_ifa_address(void) { return IFA_ADDRESS; }
int nl_get_ifa_local(void) { return IFA_LOCAL; }
int nl_get_ifa_label(void) { return IFA_LABEL; }
int nl_get_ifa_broadcast(void) { return IFA_BROADCAST; }
int nl_get_ifa_anycast(void) { return IFA_ANYCAST; }
int nl_get_ifa_cacheinfo(void) { return IFA_CACHEINFO; }
int nl_get_ifa_multicast(void) { return IFA_MULTICAST; }
int nl_get_ifa_flags(void) { return IFA_FLAGS; }
#ifdef IFA_RT_PRIORITY
int nl_get_ifa_rt_priority(void) { return IFA_RT_PRIORITY; }
#else
int nl_get_ifa_rt_priority(void) { return 9; }
#endif
#ifdef IFA_TARGET_NETNSID
int nl_get_ifa_target_netnsid(void) { return IFA_TARGET_NETNSID; }
#else
int nl_get_ifa_target_netnsid(void) { return 10; }
#endif
#ifdef IFA_PROTO
int nl_get_ifa_proto(void) { return IFA_PROTO; }
#else
int nl_get_ifa_proto(void) { return 11; }
#endif

const char* nl_get_stp_state_name(unsigned char state) {
    switch (state) {
        case BR_STATE_DISABLED:   return "disabled";
        case BR_STATE_LISTENING:  return "listening";
        case BR_STATE_LEARNING:   return "learning";
        case BR_STATE_FORWARDING: return "forwarding";
        case BR_STATE_BLOCKING:   return "blocking";
        default: return NULL;
    }
}

const char* nl_get_flag_name(unsigned int flags, int index) {
    static const char* flag_names[] = {
        "UP", "BROADCAST", "DEBUG", "LOOPBACK", "POINTOPOINT",
        "NOTRAILERS", "RUNNING", "NOARP", "PROMISC", "ALLMULTI",
        "MASTER", "SLAVE", "MULTICAST", "PORTSEL", "AUTOMEDIA",
        "DYNAMIC", "LOWER_UP", "DORMANT", "ECHO"
    };
    static const unsigned int flag_values[] = {
        IFF_UP, IFF_BROADCAST, IFF_DEBUG, IFF_LOOPBACK, IFF_POINTOPOINT,
        IFF_NOTRAILERS, IFF_RUNNING, IFF_NOARP, IFF_PROMISC, IFF_ALLMULTI,
        IFF_MASTER, IFF_SLAVE, IFF_MULTICAST, IFF_PORTSEL, IFF_AUTOMEDIA,
        IFF_DYNAMIC, IFF_LOWER_UP, IFF_DORMANT, IFF_ECHO
    };
    
    int count = 0;
    for (int i = 0; i < 19; i++) {
        if (flags & flag_values[i]) {
            if (count == index) return flag_names[i];
            count++;
        }
    }
    return NULL;
}

const char* nl_get_type_name(unsigned short type) {
    switch (type) {
        case ARPHRD_ETHER: return "ether";
        case ARPHRD_PPP: return "ppp";
        case ARPHRD_IPIP: return "ipip";
        case ARPHRD_LOOPBACK: return "loopback";
        case ARPHRD_SIT: return "sit";
        case ARPHRD_IPGRE: return "gre";
        case ARPHRD_IEEE80211: return "ieee80211";
        default: return NULL;
    }
}

const char* nl_get_operstate_name(unsigned char operstate) {
    switch (operstate) {
        case IF_OPER_UNKNOWN: return "unknown";
        case IF_OPER_NOTPRESENT: return "notpresent";
        case IF_OPER_DOWN: return "down";
        case IF_OPER_LOWERLAYERDOWN: return "lowerlayerdown";
        case IF_OPER_TESTING: return "testing";
        case IF_OPER_DORMANT: return "dormant";
        case IFA_CACHEINFO: return "up";
        default: return NULL;
    }
}

const char* nl_get_scope_name(unsigned char scope) {
    switch (scope) {
        case RT_SCOPE_UNIVERSE:   return "universe";
        case RT_SCOPE_SITE: return "site";
        case RT_SCOPE_LINK: return "link";
        case RT_SCOPE_HOST: return "host";
        case RT_SCOPE_NOWHERE: return "nowhere";
        default: return NULL;
    }
}

const char* nl_get_ipv4_flag_name(unsigned char flags, int index) {
    static const char* flag_names[] = {
        "SECONDARY", "NODAD", "OPTIMISTIC", "DADFAILED", 
        "HOMEADDRESS", "DEPRECATED", "TENTATIVE", "PERMANENT"
    };
    static const unsigned char flag_values[] = {
        IFA_F_SECONDARY, IFA_F_NODAD, IFA_F_OPTIMISTIC, IFA_F_DADFAILED,
        IFA_F_HOMEADDRESS, IFA_F_DEPRECATED, IFA_F_TENTATIVE, IFA_F_PERMANENT
    };
    
    int count = 0;
    for (int i = 0; i < 8; i++) {
        if (flags & flag_values[i]) {
            if (count == index) return flag_names[i];
            count++;
        }
    }
    return NULL;
}

const char* nl_get_ipv6_flag_name(unsigned char flags, int index) {
    static const char* flag_names[] = {
        "TEMPORARY", "NODAD", "OPTIMISTIC", "DADFAILED", 
        "HOMEADDRESS", "DEPRECATED", "TENTATIVE", "PERMANENT"
    };
    static const unsigned char flag_values[] = {
        IFA_F_TEMPORARY, IFA_F_NODAD, IFA_F_OPTIMISTIC, IFA_F_DADFAILED,
        IFA_F_HOMEADDRESS, IFA_F_DEPRECATED, IFA_F_TENTATIVE, IFA_F_PERMANENT
    };
    
    int count = 0;
    for (int i = 0; i < 8; i++) {
        if (flags & flag_values[i]) {
            if (count == index) return flag_names[i];
            count++;
        }
    }
    return NULL;
}

const char* nl_get_extended_flag_name(unsigned int flags, int index, int is_ipv6) {
    static const char* ipv4_flag_names[] = {
        "SECONDARY", "NODAD", "OPTIMISTIC", "DADFAILED", 
        "HOMEADDRESS", "DEPRECATED", "TENTATIVE", "PERMANENT",
        "MANAGETEMPADDR", "NOPREFIXROUTE", "MCAUTOJOIN", "STABLE_PRIVACY"
    };
    static const char* ipv6_flag_names[] = {
        "TEMPORARY", "NODAD", "OPTIMISTIC", "DADFAILED", 
        "HOMEADDRESS", "DEPRECATED", "TENTATIVE", "PERMANENT",
        "MANAGETEMPADDR", "NOPREFIXROUTE", "MCAUTOJOIN", "STABLE_PRIVACY"
    };
    static const unsigned int flag_values[] = {
        IFA_F_SECONDARY, IFA_F_NODAD, IFA_F_OPTIMISTIC, IFA_F_DADFAILED,
        IFA_F_HOMEADDRESS, IFA_F_DEPRECATED, IFA_F_TENTATIVE, IFA_F_PERMANENT,
        IFA_F_MANAGETEMPADDR, IFA_F_NOPREFIXROUTE, IFA_F_MCAUTOJOIN, IFA_F_STABLE_PRIVACY
    };
    
    const char** flag_names = is_ipv6 ? ipv6_flag_names : ipv4_flag_names;
    
    int count = 0;
    for (int i = 0; i < 12; i++) {
        if (flags & flag_values[i]) {
            if (count == index) return flag_names[i];
            count++;
        }
    }
    return NULL;
}

int nl_is_ipv4_secondary(unsigned char flags) {
    return (flags & IFA_F_SECONDARY) ? 1 : 0;
}

int nl_is_ipv6_temporary(unsigned char flags) {
    return (flags & IFA_F_TEMPORARY) ? 1 : 0;
}

int nl_is_extended_secondary(unsigned int flags) {
    return (flags & IFA_F_SECONDARY) ? 1 : 0;
}

int nl_is_extended_temporary(unsigned int flags) {
    return (flags & IFA_F_TEMPORARY) ? 1 : 0;
}
""";  #// END OF C_SOURCE

# CFFI definitions
ffi = FFI()
ffi.cdef("""
    typedef struct {
        unsigned char* data;
        size_t length;
        size_t capacity;
        unsigned int seq;
    } response_buffer_t;

    typedef struct {
        int has_bridge_info;
        unsigned char state;
        unsigned short priority;
        unsigned int cost;
        unsigned char mode;
        unsigned char guard;
        unsigned char protect;
        unsigned char fast_leave;
        unsigned char learning;
        unsigned char unicast_flood;
        unsigned char proxyarp;
        unsigned char proxyarp_wifi;
        unsigned char multicast_router;
        unsigned char mcast_to_ucast;
        unsigned char mcast_flood;
        unsigned char bcast_flood;
        unsigned short group_fwd_mask;
        unsigned char neigh_suppress;
        unsigned char isolated;
        unsigned char mrp_ring_open;
        unsigned char mrp_in_open;
        unsigned int mcast_eht_hosts_limit;
        unsigned int mcast_eht_hosts_cnt;
        unsigned char locked;
        unsigned char mab;
        unsigned int mcast_n_groups;
        unsigned int mcast_max_groups;
        unsigned char neigh_vlan_suppress;
        unsigned char root_id[8];
        unsigned char bridge_id[8];
        unsigned short designated_port;
        unsigned int designated_cost;
        unsigned short port_id;
        unsigned short port_no;
        unsigned char topology_change_ack;
        unsigned char config_pending;
        unsigned long long message_age_timer;
        unsigned long long forward_delay_timer;
        unsigned long long hold_timer;
        unsigned char vlan_tunnel;
        int has_priority;
        int has_cost;
        int has_mode;
        int has_guard;
        int has_protect;
        int has_fast_leave;
        int has_learning;
        int has_unicast_flood;
        int has_proxyarp;
        int has_proxyarp_wifi;
        int has_multicast_router;
        int has_mcast_to_ucast;
        int has_mcast_flood;
        int has_bcast_flood;
        int has_group_fwd_mask;
        int has_neigh_suppress;
        int has_isolated;
        int has_mrp_ring_open;
        int has_mrp_in_open;
        int has_mcast_eht_hosts_limit;
        int has_mcast_eht_hosts_cnt;
        int has_locked;
        int has_mab;
        int has_mcast_n_groups;
        int has_mcast_max_groups;
        int has_neigh_vlan_suppress;
        int has_root_id;
        int has_bridge_id;
        int has_designated_port;
        int has_designated_cost;
        int has_port_id;
        int has_port_no;
        int has_topology_change_ack;
        int has_config_pending;
        int has_message_age_timer;
        int has_forward_delay_timer;
        int has_hold_timer;
        int has_vlan_tunnel;
        unsigned short unknown_attrs[64];
        int unknown_attrs_count;
        int data_source_priority;
    } bridge_port_info_t;
    
// Bridge master configuration - WITH ALL NEW FIELDS
    typedef struct {
        int has_bridge_config;
        unsigned int stp_enabled;
        unsigned int forward_delay;
        unsigned int hello_time;
        unsigned int max_age;
        unsigned short priority;
        unsigned char root_id[8];
        unsigned char bridge_id[8];
        unsigned short root_port;
        unsigned int root_path_cost;
        unsigned int ageing_time;
        unsigned char vlan_filtering;
        unsigned short vlan_protocol;
        unsigned short vlan_default_pvid;
        unsigned int fdb_n_learned;
        unsigned int fdb_max_learned;
        unsigned short group_fwd_mask;
        unsigned char topology_change;
        unsigned char topology_change_detected;
        unsigned long long hello_timer;
        unsigned long long tcn_timer;
        unsigned long long topology_change_timer;
        unsigned long long gc_timer;
        unsigned char group_addr[6];
        unsigned char mcast_router;
        unsigned char mcast_snooping;
        unsigned char mcast_query_use_ifaddr;
        unsigned char mcast_querier;
        unsigned int mcast_hash_elasticity;
        unsigned int mcast_hash_max;
        unsigned int mcast_last_member_cnt;
        unsigned int mcast_startup_query_cnt;
        unsigned long long mcast_last_member_intvl;
        unsigned long long mcast_membership_intvl;
        unsigned long long mcast_querier_intvl;
        unsigned long long mcast_query_intvl;
        unsigned long long mcast_query_response_intvl;
        unsigned long long mcast_startup_query_intvl;
        unsigned char nf_call_iptables;
        unsigned char nf_call_ip6tables;
        unsigned char nf_call_arptables;
        unsigned char vlan_stats_enabled;
        unsigned char mcast_stats_enabled;
        unsigned char mcast_igmp_version;
        unsigned char mcast_mld_version;
        unsigned char vlan_stats_per_port;
        unsigned long long multi_boolopt;
        int has_stp_enabled;
        int has_forward_delay;
        int has_hello_time;
        int has_max_age;
        int has_priority;
        int has_root_id;
        int has_bridge_id;
        int has_root_port;
        int has_root_path_cost;
        int has_ageing_time;
        int has_vlan_filtering;
        int has_vlan_protocol;
        int has_vlan_default_pvid;
        int has_fdb_n_learned;
        int has_fdb_max_learned;
        int has_group_fwd_mask;
        int has_topology_change;
        int has_topology_change_detected;
        int has_hello_timer;
        int has_tcn_timer;
        int has_topology_change_timer;
        int has_gc_timer;
        int has_group_addr;
        int has_mcast_router;
        int has_mcast_snooping;
        int has_mcast_query_use_ifaddr;
        int has_mcast_querier;
        int has_mcast_hash_elasticity;
        int has_mcast_hash_max;
        int has_mcast_last_member_cnt;
        int has_mcast_startup_query_cnt;
        int has_mcast_last_member_intvl;
        int has_mcast_membership_intvl;
        int has_mcast_querier_intvl;
        int has_mcast_query_intvl;
        int has_mcast_query_response_intvl;
        int has_mcast_startup_query_intvl;
        int has_nf_call_iptables;
        int has_nf_call_ip6tables;
        int has_nf_call_arptables;
        int has_vlan_stats_enabled;
        int has_mcast_stats_enabled;
        int has_mcast_igmp_version;
        int has_mcast_mld_version;
        int has_vlan_stats_per_port;
        int has_multi_boolopt;
    } bridge_config_t;

    typedef struct {
        unsigned char public_key[32];
        unsigned long long rx_bytes;
        unsigned long long tx_bytes;
        unsigned long long last_handshake_time;
        int has_public_key;
        int has_rx_bytes;
        int has_tx_bytes;
        int has_last_handshake;
    } wg_peer_info_t;

    typedef struct {
        int has_config;
        unsigned char public_key[32];
        unsigned short listen_port;
        unsigned int fwmark;
        int has_public_key;
        int has_listen_port;
        int has_fwmark;
        wg_peer_info_t* peers;
        int peer_count;
    } wg_device_info_t;

typedef struct {
        unsigned int id;
        unsigned int remote;
        unsigned char ttl;
        unsigned char tos;
        unsigned short port;
        unsigned char collect_metadata;
        unsigned char remote6[16];
        unsigned char udp_csum;
        unsigned char udp_zero_csum6_tx;
        unsigned char udp_zero_csum6_rx;
        unsigned int label;
        unsigned char ttl_inherit;
        unsigned char df;
        unsigned char inner_proto_inherit;
        int has_id;
        int has_remote;
        int has_ttl;
        int has_tos;
        int has_port;
        int has_collect_metadata;
        int has_remote6;
        int has_udp_csum;
        int has_udp_zero_csum6_tx;
        int has_udp_zero_csum6_rx;
        int has_label;
        int has_ttl_inherit;
        int has_df;
        int has_inner_proto_inherit;
    } geneve_info_t;    

    typedef struct {
        int has_dpll_pin;
        unsigned long long pin_id;
        unsigned long long parent_id;
        unsigned long long clock_id;
        char module_name[64];
        char board_label[64];
        char panel_label[64];
        char package_label[64];
        unsigned char pin_type;
        unsigned char pin_direction;
        unsigned char pin_state;
        unsigned int pin_capabilities;
        unsigned int pin_priority;
        unsigned long long frequency;
        unsigned long long frequency_min;
        unsigned long long frequency_max;
        long long phase_adjust;
        long long phase_adjust_min;
        long long phase_adjust_max;
        long long phase_offset;
        long long fractional_frequency_offset;
        int has_pin_id;
        int has_parent_id;
        int has_clock_id;
        int has_module_name;
        int has_board_label;
        int has_panel_label;
        int has_package_label;
        int has_pin_type;
        int has_pin_direction;
        int has_pin_state;
        int has_pin_capabilities;
        int has_pin_priority;
        int has_frequency;
        int has_frequency_min;
        int has_frequency_max;
        int has_phase_adjust;
        int has_phase_adjust_min;
        int has_phase_adjust_max;
        int has_phase_offset;
        int has_fractional_frequency_offset;
        unsigned short unknown_attrs[32];
        int unknown_attrs_count;
    } dpll_pin_info_t;

    typedef struct {
        int index;
        int type;
        unsigned int flags;
        unsigned int mtu;
        char name[16];
        unsigned char mac[6];
        int has_mac;
        unsigned char broadcast[6];
        int has_broadcast;
        unsigned char perm_address[6];
        int has_perm_address;
        unsigned char operstate;
        unsigned char _pad_operstate[3];
        unsigned int txqlen;
        char qdisc[32];
        char ifalias[256];
        char kind[32];
        int has_txqlen;
        int has_qdisc;
        int has_ifalias;
        int has_kind;
        int master_index;
        int has_master;
        int link_index;
        int has_link;
        char parent_dev_name[16];
        int has_parent_dev_name;
        int vlan_id;
        int has_vlan_id;
        unsigned int vlan_flags;
        unsigned int vlan_flags_mask;
        int has_vlan_flags;
        unsigned short vlan_protocol;
        unsigned char _pad_vlan_protocol[2];
        int has_vlan_protocol;
        int veth_peer_index;
        int has_veth_peer;
        unsigned int bridge_forward_delay;
        int has_bridge_forward_delay;
        unsigned int tunnel_local;
        unsigned int tunnel_remote;
        int has_tunnel_local;
        int has_tunnel_remote;
        bridge_port_info_t bridge_port;
        bridge_config_t bridge_config;
        wg_device_info_t wireguard;
        geneve_info_t geneve;
        dpll_pin_info_t dpll_pin;
        char slave_kind[32];
        int has_slave_kind;
        unsigned char linkmode;
        unsigned char _pad_linkmode[3];
        int has_linkmode;
        unsigned int min_mtu;
        unsigned int max_mtu;
        int has_min_mtu;
        int has_max_mtu;
        unsigned int group;
        int has_group;
        unsigned int promiscuity;
        int has_promiscuity;
        unsigned int allmulti;
        int has_allmulti;
        unsigned int num_tx_queues;
        unsigned int num_rx_queues;
        int has_num_tx_queues;
        int has_num_rx_queues;
        unsigned int gso_max_segs;
        unsigned int gso_max_size;
        unsigned int gro_max_size;
        unsigned int gso_ipv4_max_size;
        unsigned int gro_ipv4_max_size;
        unsigned int tso_max_size;
        unsigned int tso_max_segs;
        int has_gso_max_segs;
        int has_gso_max_size;
        int has_gro_max_size;
        int has_gso_ipv4_max_size;
        int has_gro_ipv4_max_size;
        int has_tso_max_size;
        int has_tso_max_segs;
        unsigned char carrier;
        unsigned char _pad_carrier[3];
        int has_carrier;
        unsigned int carrier_changes;
        unsigned long long carrier_up_count;
        unsigned long long carrier_down_count;
        int has_carrier_changes;
        int has_carrier_up_count;
        int has_carrier_down_count;
        unsigned char proto_down;
        unsigned char _pad_proto_down[3];
        int has_proto_down;
        unsigned long long map_mem_start;
        unsigned long long map_mem_end;
        unsigned long long map_base_addr;
        unsigned short map_irq;
        unsigned char map_dma;
        unsigned char map_port;
        unsigned char _pad_map[2];
        int has_map;
        unsigned short unknown_ifla_attrs[64];
        int unknown_ifla_attrs_count;
        unsigned short unknown_linkinfo_attrs[64];
        int unknown_linkinfo_attrs_count;
        unsigned short unknown_info_data_attrs[64];
        int unknown_info_data_attrs_count;
    } link_info_t;

    typedef struct {
        unsigned long long rx_packets;
        unsigned long long tx_packets;
        unsigned long long rx_bytes;
        unsigned long long tx_bytes;
        unsigned long long rx_errors;
        unsigned long long tx_errors;
        unsigned long long rx_dropped;
        unsigned long long tx_dropped;
        unsigned long long multicast;
        unsigned long long collisions;
        unsigned long long rx_length_errors;
        unsigned long long rx_over_errors;
        unsigned long long rx_crc_errors;
        unsigned long long rx_frame_errors;
        unsigned long long rx_fifo_errors;
        unsigned long long rx_missed_errors;
        unsigned long long tx_aborted_errors;
        unsigned long long tx_carrier_errors;
        unsigned long long tx_fifo_errors;
        unsigned long long tx_heartbeat_errors;
        unsigned long long tx_window_errors;
        unsigned long long rx_compressed;
        unsigned long long tx_compressed;
        unsigned long long rx_nohandler;
        int has_stats64;
    } link_stats_t;

    typedef struct {
        int index;
        unsigned char family;
        unsigned char prefixlen;
        unsigned char flags;
        unsigned char scope;
        unsigned char address[16];
        unsigned char local[16];
        unsigned char broadcast[16];
        int has_local;
        int has_broadcast;
        char label[16];
        unsigned int preferred_lft;
        unsigned int valid_lft;
        unsigned int created_tstamp;
        unsigned int updated_tstamp;
        int has_cacheinfo;
        unsigned int extended_flags;
        int has_extended_flags;
        unsigned char protocol;
        int has_protocol;
        unsigned short unknown_ifa_attrs[64];
        int unknown_ifa_attrs_count;
    } addr_info_t;

    int nl_create_socket(void);
    int genl_create_socket(void);
    void nl_close_socket(int sock);
    int nl_send_getlink(int sock, unsigned int* seq_out);
    int nl_send_getaddr(int sock, unsigned int* seq_out);
    response_buffer_t* nl_recv_response(int sock, unsigned int expected_seq);
    void nl_free_response(response_buffer_t* buf);
    int nl_parse_links(response_buffer_t* buf, link_info_t** links, int* count, link_stats_t** stats);
    int nl_parse_addrs(response_buffer_t* buf, addr_info_t** addrs, int* count);
    void nl_free_links(link_info_t* links, int count);
    void nl_free_stats(link_stats_t* stats);
    void nl_free_addrs(addr_info_t* addrs);
    int genl_get_family_id(int sock, const char* family_name);
    int genl_query_wireguard(int sock, int family_id, unsigned int ifindex, wg_device_info_t* wg_info);
    void genl_free_wireguard(wg_device_info_t* wg_info);
    const char* nl_get_flag_name(unsigned int flags, int index);
    const char* nl_get_stp_state_name(unsigned char state);
    int nl_get_af_inet(void);
    int nl_get_af_inet6(void);
    int nl_is_ipv4_secondary(unsigned char flags);
    int nl_is_ipv6_temporary(unsigned char flags);
    const char* nl_get_ipv4_flag_name(unsigned char flags, int index);
    const char* nl_get_ipv6_flag_name(unsigned char flags, int index);
    const char* nl_get_extended_flag_name(unsigned int flags, int index, int is_ipv6);
    int nl_is_extended_secondary(unsigned int flags);
    int nl_is_extended_temporary(unsigned int flags);
    const char* nl_get_scope_name(unsigned char scope);
    const char* nl_get_type_name(unsigned short type);
    const char* nl_get_operstate_name(unsigned char operstate);
    
    // Netlink attribute type constants
    int nl_get_nla_f_nested(void);
    int nl_get_nla_type_mask(void);
    
    // Ethernet protocol constants
    int nl_get_eth_p_8021q(void);
    int nl_get_eth_p_8021ad(void);
    
    // VLAN flag constants
    int nl_get_vlan_flag_reorder_hdr(void);
    int nl_get_vlan_flag_gvrp(void);
    int nl_get_vlan_flag_loose_binding(void);
    int nl_get_vlan_flag_mvrp(void);
    int nl_get_vlan_flag_bridge_binding(void);
    
    // DPLL pin type constants
    int nl_get_dpll_pin_type_mux(void);
    int nl_get_dpll_pin_type_ext(void);
    int nl_get_dpll_pin_type_synce_eth_port(void);
    int nl_get_dpll_pin_type_int_oscillator(void);
    int nl_get_dpll_pin_type_gnss(void);
    
    // DPLL pin direction constants
    int nl_get_dpll_pin_direction_input(void);
    int nl_get_dpll_pin_direction_output(void);
    
    // DPLL pin state constants
    int nl_get_dpll_pin_state_connected(void);
    int nl_get_dpll_pin_state_disconnected(void);
    int nl_get_dpll_pin_state_selectable(void);
    
    // DPLL pin capability constants
    int nl_get_dpll_pin_cap_direction_can_change(void);
    int nl_get_dpll_pin_cap_priority_can_change(void);
    int nl_get_dpll_pin_cap_state_can_change(void);
    
    // Multicast router mode constants
    int nl_get_mdb_rtr_type_disabled(void);
    int nl_get_mdb_rtr_type_temp_query(void);
    int nl_get_mdb_rtr_type_perm(void);
    
    // GENEVE DF mode constants
    int nl_get_geneve_df_unset(void);
    int nl_get_geneve_df_set(void);
    int nl_get_geneve_df_inherit(void);
    
    // IFLA_* attribute constant accessors
    int nl_get_ifla_unspec(void);
    int nl_get_ifla_address(void);
    int nl_get_ifla_broadcast(void);
    int nl_get_ifla_ifname(void);
    int nl_get_ifla_mtu(void);
    int nl_get_ifla_link(void);
    int nl_get_ifla_qdisc(void);
    int nl_get_ifla_stats(void);
    int nl_get_ifla_cost(void);
    int nl_get_ifla_priority(void);
    int nl_get_ifla_master(void);
    int nl_get_ifla_wireless(void);
    int nl_get_ifla_protinfo(void);
    int nl_get_ifla_txqlen(void);
    int nl_get_ifla_map(void);
    int nl_get_ifla_weight(void);
    int nl_get_ifla_operstate(void);
    int nl_get_ifla_linkmode(void);
    int nl_get_ifla_linkinfo(void);
    int nl_get_ifla_net_ns_pid(void);
    int nl_get_ifla_ifalias(void);
    int nl_get_ifla_num_vf(void);
    int nl_get_ifla_vfinfo_list(void);
    int nl_get_ifla_stats64(void);
    int nl_get_ifla_vf_ports(void);
    int nl_get_ifla_port_self(void);
    int nl_get_ifla_af_spec(void);
    int nl_get_ifla_group(void);
    int nl_get_ifla_net_ns_fd(void);
    int nl_get_ifla_ext_mask(void);
    int nl_get_ifla_promiscuity(void);
    int nl_get_ifla_num_tx_queues(void);
    int nl_get_ifla_num_rx_queues(void);
    int nl_get_ifla_carrier(void);
    int nl_get_ifla_phys_port_id(void);
    int nl_get_ifla_carrier_changes(void);
    int nl_get_ifla_phys_switch_id(void);
    int nl_get_ifla_link_netnsid(void);
    int nl_get_ifla_phys_port_name(void);
    int nl_get_ifla_proto_down(void);
    int nl_get_ifla_gso_max_segs(void);
    int nl_get_ifla_gso_max_size(void);
    int nl_get_ifla_pad(void);
    int nl_get_ifla_xdp(void);
    int nl_get_ifla_event(void);
    int nl_get_ifla_new_netnsid(void);
    int nl_get_ifla_target_netnsid(void);
    int nl_get_ifla_carrier_up_count(void);
    int nl_get_ifla_carrier_down_count(void);
    int nl_get_ifla_new_ifindex(void);
    int nl_get_ifla_min_mtu(void);
    int nl_get_ifla_max_mtu(void);
    int nl_get_ifla_prop_list(void);
    int nl_get_ifla_alt_ifname(void);
    int nl_get_ifla_perm_address(void);
    int nl_get_ifla_proto_down_reason(void);
    int nl_get_ifla_parent_dev_name(void);
    int nl_get_ifla_parent_dev_bus_name(void);
    int nl_get_ifla_gro_max_size(void);
    int nl_get_ifla_tso_max_size(void);
    int nl_get_ifla_tso_max_segs(void);
    int nl_get_ifla_allmulti(void);
    int nl_get_ifla_devlink_port(void);
    int nl_get_ifla_gso_ipv4_max_size(void);
    int nl_get_ifla_gro_ipv4_max_size(void);
    
    // IFA_* attribute constant accessors
    int nl_get_ifa_unspec(void);
    int nl_get_ifa_address(void);
    int nl_get_ifa_local(void);
    int nl_get_ifa_label(void);
    int nl_get_ifa_broadcast(void);
    int nl_get_ifa_anycast(void);
    int nl_get_ifa_cacheinfo(void);
    int nl_get_ifa_multicast(void);
    int nl_get_ifa_flags(void);
    int nl_get_ifa_rt_priority(void);
    int nl_get_ifa_target_netnsid(void);
    int nl_get_ifa_proto(void);
""")

# Compile the C library
try:
    lib = ffi.verify(C_SOURCE, libraries=[])
except Exception as e:
    if sys.version_info >= (3, 12) and "setuptools" in str(e).lower():
        raise RuntimeError(
            "Failed to compile C extension. Python 3.12+ requires setuptools.\n"
            "Install it with: pip install setuptools"
        ) from e
    raise

AF_INET = lib.nl_get_af_inet()
AF_INET6 = lib.nl_get_af_inet6()

# Netlink attribute type constants
NLA_F_NESTED = lib.nl_get_nla_f_nested()
NLA_TYPE_MASK = lib.nl_get_nla_type_mask()

# Ethernet protocol constants
ETH_P_8021Q = lib.nl_get_eth_p_8021q()
ETH_P_8021AD = lib.nl_get_eth_p_8021ad()

# VLAN flag constants
VLAN_FLAG_REORDER_HDR = lib.nl_get_vlan_flag_reorder_hdr()
VLAN_FLAG_GVRP = lib.nl_get_vlan_flag_gvrp()
VLAN_FLAG_LOOSE_BINDING = lib.nl_get_vlan_flag_loose_binding()
VLAN_FLAG_MVRP = lib.nl_get_vlan_flag_mvrp()
VLAN_FLAG_BRIDGE_BINDING = lib.nl_get_vlan_flag_bridge_binding()

# DPLL pin type constants
DPLL_PIN_TYPE_MUX = lib.nl_get_dpll_pin_type_mux()
DPLL_PIN_TYPE_EXT = lib.nl_get_dpll_pin_type_ext()
DPLL_PIN_TYPE_SYNCE_ETH_PORT = lib.nl_get_dpll_pin_type_synce_eth_port()
DPLL_PIN_TYPE_INT_OSCILLATOR = lib.nl_get_dpll_pin_type_int_oscillator()
DPLL_PIN_TYPE_GNSS = lib.nl_get_dpll_pin_type_gnss()

# DPLL pin direction constants
DPLL_PIN_DIRECTION_INPUT = lib.nl_get_dpll_pin_direction_input()
DPLL_PIN_DIRECTION_OUTPUT = lib.nl_get_dpll_pin_direction_output()

# DPLL pin state constants
DPLL_PIN_STATE_CONNECTED = lib.nl_get_dpll_pin_state_connected()
DPLL_PIN_STATE_DISCONNECTED = lib.nl_get_dpll_pin_state_disconnected()
DPLL_PIN_STATE_SELECTABLE = lib.nl_get_dpll_pin_state_selectable()

# DPLL pin capability constants
DPLL_PIN_CAP_DIRECTION_CAN_CHANGE = lib.nl_get_dpll_pin_cap_direction_can_change()
DPLL_PIN_CAP_PRIORITY_CAN_CHANGE = lib.nl_get_dpll_pin_cap_priority_can_change()
DPLL_PIN_CAP_STATE_CAN_CHANGE = lib.nl_get_dpll_pin_cap_state_can_change()

# Multicast router mode constants
MDB_RTR_TYPE_DISABLED = lib.nl_get_mdb_rtr_type_disabled()
MDB_RTR_TYPE_TEMP_QUERY = lib.nl_get_mdb_rtr_type_temp_query()
MDB_RTR_TYPE_PERM = lib.nl_get_mdb_rtr_type_perm()

# GENEVE DF mode constants
GENEVE_DF_UNSET = lib.nl_get_geneve_df_unset()
GENEVE_DF_SET = lib.nl_get_geneve_df_set()
GENEVE_DF_INHERIT = lib.nl_get_geneve_df_inherit()

# IFLA_* attribute constants
IFLA_UNSPEC = lib.nl_get_ifla_unspec()
IFLA_ADDRESS = lib.nl_get_ifla_address()
IFLA_BROADCAST = lib.nl_get_ifla_broadcast()
IFLA_IFNAME = lib.nl_get_ifla_ifname()
IFLA_MTU = lib.nl_get_ifla_mtu()
IFLA_LINK = lib.nl_get_ifla_link()
IFLA_QDISC = lib.nl_get_ifla_qdisc()
IFLA_STATS = lib.nl_get_ifla_stats()
IFLA_COST = lib.nl_get_ifla_cost()
IFLA_PRIORITY = lib.nl_get_ifla_priority()
IFLA_MASTER = lib.nl_get_ifla_master()
IFLA_WIRELESS = lib.nl_get_ifla_wireless()
IFLA_PROTINFO = lib.nl_get_ifla_protinfo()
IFLA_TXQLEN = lib.nl_get_ifla_txqlen()
IFLA_MAP = lib.nl_get_ifla_map()
IFLA_WEIGHT = lib.nl_get_ifla_weight()
IFLA_OPERSTATE = lib.nl_get_ifla_operstate()
IFLA_LINKMODE = lib.nl_get_ifla_linkmode()
IFLA_LINKINFO = lib.nl_get_ifla_linkinfo()
IFLA_NET_NS_PID = lib.nl_get_ifla_net_ns_pid()
IFLA_IFALIAS = lib.nl_get_ifla_ifalias()
IFLA_NUM_VF = lib.nl_get_ifla_num_vf()
IFLA_VFINFO_LIST = lib.nl_get_ifla_vfinfo_list()
IFLA_STATS64 = lib.nl_get_ifla_stats64()
IFLA_VF_PORTS = lib.nl_get_ifla_vf_ports()
IFLA_PORT_SELF = lib.nl_get_ifla_port_self()
IFLA_AF_SPEC = lib.nl_get_ifla_af_spec()
IFLA_GROUP = lib.nl_get_ifla_group()
IFLA_NET_NS_FD = lib.nl_get_ifla_net_ns_fd()
IFLA_EXT_MASK = lib.nl_get_ifla_ext_mask()
IFLA_PROMISCUITY = lib.nl_get_ifla_promiscuity()
IFLA_NUM_TX_QUEUES = lib.nl_get_ifla_num_tx_queues()
IFLA_NUM_RX_QUEUES = lib.nl_get_ifla_num_rx_queues()
IFLA_CARRIER = lib.nl_get_ifla_carrier()
IFLA_PHYS_PORT_ID = lib.nl_get_ifla_phys_port_id()
IFLA_CARRIER_CHANGES = lib.nl_get_ifla_carrier_changes()
IFLA_PHYS_SWITCH_ID = lib.nl_get_ifla_phys_switch_id()
IFLA_LINK_NETNSID = lib.nl_get_ifla_link_netnsid()
IFLA_PHYS_PORT_NAME = lib.nl_get_ifla_phys_port_name()
IFLA_PROTO_DOWN = lib.nl_get_ifla_proto_down()
IFLA_GSO_MAX_SEGS = lib.nl_get_ifla_gso_max_segs()
IFLA_GSO_MAX_SIZE = lib.nl_get_ifla_gso_max_size()
IFLA_PAD = lib.nl_get_ifla_pad()
IFLA_XDP = lib.nl_get_ifla_xdp()
IFLA_EVENT = lib.nl_get_ifla_event()
IFLA_NEW_NETNSID = lib.nl_get_ifla_new_netnsid()
IFLA_TARGET_NETNSID = lib.nl_get_ifla_target_netnsid()
IFLA_CARRIER_UP_COUNT = lib.nl_get_ifla_carrier_up_count()
IFLA_CARRIER_DOWN_COUNT = lib.nl_get_ifla_carrier_down_count()
IFLA_NEW_IFINDEX = lib.nl_get_ifla_new_ifindex()
IFLA_MIN_MTU = lib.nl_get_ifla_min_mtu()
IFLA_MAX_MTU = lib.nl_get_ifla_max_mtu()
IFLA_PROP_LIST = lib.nl_get_ifla_prop_list()
IFLA_ALT_IFNAME = lib.nl_get_ifla_alt_ifname()
IFLA_PERM_ADDRESS = lib.nl_get_ifla_perm_address()
IFLA_PROTO_DOWN_REASON = lib.nl_get_ifla_proto_down_reason()
IFLA_PARENT_DEV_NAME = lib.nl_get_ifla_parent_dev_name()
IFLA_PARENT_DEV_BUS_NAME = lib.nl_get_ifla_parent_dev_bus_name()
IFLA_GRO_MAX_SIZE = lib.nl_get_ifla_gro_max_size()
IFLA_TSO_MAX_SIZE = lib.nl_get_ifla_tso_max_size()
IFLA_TSO_MAX_SEGS = lib.nl_get_ifla_tso_max_segs()
IFLA_ALLMULTI = lib.nl_get_ifla_allmulti()
IFLA_DEVLINK_PORT = lib.nl_get_ifla_devlink_port()
IFLA_GSO_IPV4_MAX_SIZE = lib.nl_get_ifla_gso_ipv4_max_size()
IFLA_GRO_IPV4_MAX_SIZE = lib.nl_get_ifla_gro_ipv4_max_size()

# IFA_* attribute constants
IFA_UNSPEC = lib.nl_get_ifa_unspec()
IFA_ADDRESS = lib.nl_get_ifa_address()
IFA_LOCAL = lib.nl_get_ifa_local()
IFA_LABEL = lib.nl_get_ifa_label()
IFA_BROADCAST = lib.nl_get_ifa_broadcast()
IFA_ANYCAST = lib.nl_get_ifa_anycast()
IFA_CACHEINFO = lib.nl_get_ifa_cacheinfo()
IFA_MULTICAST = lib.nl_get_ifa_multicast()
IFA_FLAGS = lib.nl_get_ifa_flags()
IFA_RT_PRIORITY = lib.nl_get_ifa_rt_priority()
IFA_TARGET_NETNSID = lib.nl_get_ifa_target_netnsid()
IFA_PROTO = lib.nl_get_ifa_proto()


# Base64 encoding for public keys
def base64_encode(data: bytes) -> str:
    """Encode bytes as base64 string"""
    import base64
    return base64.b64encode(data).decode('ascii')


# IFLA_* Attribute Name Mapping (keys from C header constants)
IFLA_ATTR_NAMES = {
    IFLA_UNSPEC: 'IFLA_UNSPEC',
    IFLA_ADDRESS: 'IFLA_ADDRESS',
    IFLA_BROADCAST: 'IFLA_BROADCAST',
    IFLA_IFNAME: 'IFLA_IFNAME',
    IFLA_MTU: 'IFLA_MTU',
    IFLA_LINK: 'IFLA_LINK',
    IFLA_QDISC: 'IFLA_QDISC',
    IFLA_STATS: 'IFLA_STATS',
    IFLA_COST: 'IFLA_COST',
    IFLA_PRIORITY: 'IFLA_PRIORITY',
    IFLA_MASTER: 'IFLA_MASTER',
    IFLA_WIRELESS: 'IFLA_WIRELESS',
    IFLA_PROTINFO: 'IFLA_PROTINFO',
    IFLA_TXQLEN: 'IFLA_TXQLEN',
    IFLA_MAP: 'IFLA_MAP',
    IFLA_WEIGHT: 'IFLA_WEIGHT',
    IFLA_OPERSTATE: 'IFLA_OPERSTATE',
    IFLA_LINKMODE: 'IFLA_LINKMODE',
    IFLA_LINKINFO: 'IFLA_LINKINFO',
    IFLA_NET_NS_PID: 'IFLA_NET_NS_PID',
    IFLA_IFALIAS: 'IFLA_IFALIAS',
    IFLA_NUM_VF: 'IFLA_NUM_VF',
    IFLA_VFINFO_LIST: 'IFLA_VFINFO_LIST',
    IFLA_STATS64: 'IFLA_STATS64',
    IFLA_VF_PORTS: 'IFLA_VF_PORTS',
    IFLA_PORT_SELF: 'IFLA_PORT_SELF',
    IFLA_AF_SPEC: 'IFLA_AF_SPEC',
    IFLA_GROUP: 'IFLA_GROUP',
    IFLA_NET_NS_FD: 'IFLA_NET_NS_FD',
    IFLA_EXT_MASK: 'IFLA_EXT_MASK',
    IFLA_PROMISCUITY: 'IFLA_PROMISCUITY',
    IFLA_NUM_TX_QUEUES: 'IFLA_NUM_TX_QUEUES',
    IFLA_NUM_RX_QUEUES: 'IFLA_NUM_RX_QUEUES',
    IFLA_CARRIER: 'IFLA_CARRIER',
    IFLA_PHYS_PORT_ID: 'IFLA_PHYS_PORT_ID',
    IFLA_CARRIER_CHANGES: 'IFLA_CARRIER_CHANGES',
    IFLA_PHYS_SWITCH_ID: 'IFLA_PHYS_SWITCH_ID',
    IFLA_LINK_NETNSID: 'IFLA_LINK_NETNSID',
    IFLA_PHYS_PORT_NAME: 'IFLA_PHYS_PORT_NAME',
    IFLA_PROTO_DOWN: 'IFLA_PROTO_DOWN',
    IFLA_GSO_MAX_SEGS: 'IFLA_GSO_MAX_SEGS',
    IFLA_GSO_MAX_SIZE: 'IFLA_GSO_MAX_SIZE',
    IFLA_PAD: 'IFLA_PAD',
    IFLA_XDP: 'IFLA_XDP',
    IFLA_EVENT: 'IFLA_EVENT',
    IFLA_NEW_NETNSID: 'IFLA_NEW_NETNSID',
    IFLA_TARGET_NETNSID: 'IFLA_TARGET_NETNSID',
    IFLA_CARRIER_UP_COUNT: 'IFLA_CARRIER_UP_COUNT',
    IFLA_CARRIER_DOWN_COUNT: 'IFLA_CARRIER_DOWN_COUNT',
    IFLA_NEW_IFINDEX: 'IFLA_NEW_IFINDEX',
    IFLA_MIN_MTU: 'IFLA_MIN_MTU',
    IFLA_MAX_MTU: 'IFLA_MAX_MTU',
    IFLA_PROP_LIST: 'IFLA_PROP_LIST',
    IFLA_ALT_IFNAME: 'IFLA_ALT_IFNAME',
    IFLA_PERM_ADDRESS: 'IFLA_PERM_ADDRESS',
    IFLA_PROTO_DOWN_REASON: 'IFLA_PROTO_DOWN_REASON',
    IFLA_PARENT_DEV_NAME: 'IFLA_PARENT_DEV_NAME',
    IFLA_PARENT_DEV_BUS_NAME: 'IFLA_PARENT_DEV_BUS_NAME',
    IFLA_GRO_MAX_SIZE: 'IFLA_GRO_MAX_SIZE',
    IFLA_TSO_MAX_SIZE: 'IFLA_TSO_MAX_SIZE',
    IFLA_TSO_MAX_SEGS: 'IFLA_TSO_MAX_SEGS',
    IFLA_ALLMULTI: 'IFLA_ALLMULTI',
    IFLA_DEVLINK_PORT: 'IFLA_DEVLINK_PORT',
    IFLA_GSO_IPV4_MAX_SIZE: 'IFLA_GSO_IPV4_MAX_SIZE',
    IFLA_GRO_IPV4_MAX_SIZE: 'IFLA_GRO_IPV4_MAX_SIZE',
}

# IFA_* Attribute Name Mapping (keys from C header constants)
IFA_ATTR_NAMES = {
    IFA_UNSPEC: 'IFA_UNSPEC',
    IFA_ADDRESS: 'IFA_ADDRESS',
    IFA_LOCAL: 'IFA_LOCAL',
    IFA_LABEL: 'IFA_LABEL',
    IFA_BROADCAST: 'IFA_BROADCAST',
    IFA_ANYCAST: 'IFA_ANYCAST',
    IFA_CACHEINFO: 'IFA_CACHEINFO',
    IFA_MULTICAST: 'IFA_MULTICAST',
    IFA_FLAGS: 'IFA_FLAGS',
    IFA_RT_PRIORITY: 'IFA_RT_PRIORITY',
    IFA_TARGET_NETNSID: 'IFA_TARGET_NETNSID',
    IFA_PROTO: 'IFA_PROTO',
}

# IFA_PROTO Protocol Values (for IPv6 address configuration source)
IFA_PROTO_NAMES = {
    0: 'unspecified',
    1: 'kernel_lo',     # Loopback address set by kernel
    2: 'kernel_ra',     # Auto-configured from router advertisement
    3: 'kernel_ll',     # Link-local address set by kernel
}


def decode_unknown_attrs(attr_list: List[int], attr_type: str = 'IFLA') -> List[Dict[str, Any]]:
    """Decode unknown attribute numbers into human-readable information"""
    decoded = []
    for attr_num in attr_list:
        is_nested = bool(attr_num & NLA_F_NESTED)
        base_num = attr_num & NLA_TYPE_MASK
        
        info = {
            'number': attr_num,
            'base_number': base_num,
            'nested': is_nested,
        }
        
        if attr_type == 'IFLA' and base_num in IFLA_ATTR_NAMES:
            info['name'] = IFLA_ATTR_NAMES[base_num]
            if is_nested:
                info['name'] += ' (nested)'
        elif attr_type == 'IFA' and base_num in IFA_ATTR_NAMES:
            info['name'] = IFA_ATTR_NAMES[base_num]
            if is_nested:
                info['name'] += ' (nested)'
        else:
            info['name'] = f'{attr_type}_{base_num}'
        
        decoded.append(info)
    
    return decoded

class RTNetlinkQuery:
    """
    Query network interface information using RTNETLINK protocol via C library.
    Now includes WireGuard support via Generic Netlink and complete bridge configuration.
    """
    
    def __init__(self, capture_unknown_attrs: bool = True):
        self.sock = -1
        self.genl_sock = -1
        self.wg_family_id = -1
        self.capture_unknown_attrs = capture_unknown_attrs
    
    def __enter__(self):
        """Context manager entry - create sockets"""
        self.sock = lib.nl_create_socket()
        if self.sock < 0:
            raise RuntimeError("Failed to create netlink socket")
        
        # Create Generic Netlink socket for WireGuard queries
        self.genl_sock = lib.genl_create_socket()
        if self.genl_sock >= 0:
            # Try to get WireGuard family ID
            self.wg_family_id = lib.genl_get_family_id(self.genl_sock, b"wireguard")
            # It's OK if this fails - just means WireGuard module not loaded
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb): #@UnusedVariable
        """Context manager exit - close sockets"""
        if self.sock >= 0:
            lib.nl_close_socket(self.sock)
            self.sock = -1
        if self.genl_sock >= 0:
            lib.nl_close_socket(self.genl_sock)
            self.genl_sock = -1
        return False
    
    def get_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Query all network interfaces and their addresses"""
        links = self._get_links()
        addrs = self._get_addrs()
        
        interfaces = {}
        
        for link in links:
            if_name = link['name']
            interfaces[if_name] = {
                'index': link['index'],
                'type': link['type'],
                'type_name': link['type_name'],
                'mtu': link['mtu'],
                'mac': link.get('mac'),
                'operstate': link['operstate'],
                'operstate_name': link['operstate_name'],
                'flags': link['flags'],
                'flag_names': link['flag_names'],
                'stats': link['stats'],
                'addresses': []
            }
            
            if 'master_index' in link:
                interfaces[if_name]['master_index'] = link['master_index']
            
            if 'link' in link:
                interfaces[if_name]['link'] = link['link']
            
            if 'txqlen' in link:
                interfaces[if_name]['txqlen'] = link['txqlen']
            if 'qdisc' in link:
                interfaces[if_name]['qdisc'] = link['qdisc']
            if 'ifalias' in link:
                interfaces[if_name]['ifalias'] = link['ifalias']
            if 'kind' in link:
                interfaces[if_name]['kind'] = link['kind']
            if 'slave_kind' in link:
                interfaces[if_name]['slave_kind'] = link['slave_kind']
            if 'vlan' in link:
                interfaces[if_name]['vlan'] = link['vlan']
            if 'veth' in link:
                interfaces[if_name]['veth'] = link['veth']
            if 'tunnel' in link:
                interfaces[if_name]['tunnel'] = link['tunnel']
            if 'wireguard' in link:
                interfaces[if_name]['wireguard'] = link['wireguard']
            if 'geneve' in link:
                interfaces[if_name]['geneve'] = link['geneve']                
            if 'bridge_port' in link:
                interfaces[if_name]['bridge_port'] = link['bridge_port']
            if 'bridge_config' in link:
                interfaces[if_name]['bridge_config'] = link['bridge_config']
            
            if self.capture_unknown_attrs:
                if 'unknown_ifla_attrs' in link:
                    interfaces[if_name]['unknown_ifla_attrs'] = link['unknown_ifla_attrs']
                    interfaces[if_name]['unknown_ifla_attrs_decoded'] = link['unknown_ifla_attrs_decoded']
                if 'unknown_linkinfo_attrs' in link:
                    interfaces[if_name]['unknown_linkinfo_attrs'] = link['unknown_linkinfo_attrs']
                    interfaces[if_name]['unknown_linkinfo_attrs_decoded'] = link['unknown_linkinfo_attrs_decoded']
                if 'unknown_info_data_attrs' in link:
                    interfaces[if_name]['unknown_info_data_attrs'] = link['unknown_info_data_attrs']
                    interfaces[if_name]['unknown_info_data_attrs_decoded'] = link['unknown_info_data_attrs_decoded']
        
        index_to_name = {info['index']: name for name, info in interfaces.items()}
        
        # Resolve master index to master name
        for if_name, if_info in interfaces.items():
            if 'master_index' in if_info:
                master_idx = if_info['master_index']
                if master_idx in index_to_name:
                    if_info['master'] = index_to_name[master_idx]
                else:
                    if_info['master'] = f'unknown_{master_idx}'
            
            # Resolve link index to link name
            if 'link' in if_info:
                link_idx = if_info['link']
                if link_idx in index_to_name:
                    if_info['link_name'] = index_to_name[link_idx]
                else:
                    if_info['link_name'] = f'unknown_{link_idx}'
            
            # Resolve veth peer index to peer name
            if 'veth' in if_info and 'peer_index' in if_info['veth']:
                peer_idx = if_info['veth']['peer_index']
                if peer_idx in index_to_name:
                    if_info['veth']['peer'] = index_to_name[peer_idx]
                else:
                    if_info['veth']['peer'] = f'unknown_{peer_idx}'
        
        for addr in addrs:
            if_idx = addr['index']
            if if_idx in index_to_name:
                if_name = index_to_name[if_idx]
                addr_info = {
                    'family': addr['family'],
                    'address': addr.get('address'),
                    'prefixlen': addr['prefixlen'],
                    'scope': addr['scope'],
                    'scope_name': addr['scope_name'],
                    'flags': addr['flags'],
                    'flag_names': addr['flag_names'],
                }
                
                if 'ipinterface' in addr:
                    addr_info['ipinterface'] = addr['ipinterface']
                    addr_info['network'] = addr['network']
                    addr_info['netmask'] = addr['netmask']
                    addr_info['hostmask'] = addr['hostmask']
                if 'ipinterface_error' in addr:
                    addr_info['ipinterface_error'] = addr['ipinterface_error']
                
                if 'is_secondary' in addr:
                    addr_info['is_secondary'] = addr['is_secondary']
                if 'is_temporary' in addr:
                    addr_info['is_temporary'] = addr['is_temporary']
                
                if 'local' in addr:
                    addr_info['local'] = addr['local']
                if 'broadcast' in addr:
                    addr_info['broadcast'] = addr['broadcast']
                if 'label' in addr:
                    addr_info['label'] = addr['label']
                if 'cacheinfo' in addr:
                    addr_info['cacheinfo'] = addr['cacheinfo']
                if 'extended_flags' in addr:
                    addr_info['extended_flags'] = addr['extended_flags']
                if 'protocol' in addr:
                    addr_info['protocol'] = addr['protocol']
                    addr_info['protocol_name'] = addr['protocol_name']
                
                if self.capture_unknown_attrs and 'unknown_ifa_attrs' in addr:
                    addr_info['unknown_ifa_attrs'] = addr['unknown_ifa_attrs']
                    addr_info['unknown_ifa_attrs_decoded'] = addr['unknown_ifa_attrs_decoded']
                    
                interfaces[if_name]['addresses'].append(addr_info)
        
        # Compute readiness for each address based on interface and address state
        for if_name, if_info in interfaces.items():
            for addr in if_info['addresses']:
                readiness = self._compute_address_readiness(if_info, addr)
                addr['readiness'] = readiness
                
        return interfaces
    
    def _compute_address_readiness(self, if_info: Dict[str, Any], addr: Dict[str, Any]) -> str:
        """
        Compute address readiness based on interface state and address flags.
        
        Returns:
            'ready' - Interface is UP, operstate is up, address is usable
            'pending' - Interface is UP but address is tentative (IPv6 DAD in progress)
            'failed' - Address has failed DAD (IPv6 only)
            'down' - Interface is administratively or operationally down
        """
        # Check if interface is administratively UP
        is_admin_up = 'UP' in if_info['flag_names']
        
        # Check operational state
        operstate = if_info['operstate_name']
        #is_oper_up = operstate in ('up', 'unknown')  # 'unknown' is often used for virtual interfaces
        
        # If interface is down, address is down
        if not is_admin_up:
            return 'down'
        
        # Check if link is operationally down
        if operstate in ('down', 'notpresent', 'lowerlayerdown'):
            return 'down'
        
        # For IPv6, check DAD (Duplicate Address Detection) status
        if addr['family'] == 'ipv6':
            flag_names = addr.get('flag_names', [])
            
            # Check for failed DAD
            if 'DADFAILED' in flag_names:
                return 'failed'
            
            # Check for tentative (DAD in progress)
            if 'TENTATIVE' in flag_names:
                return 'pending'
        
        # If we get here, address should be ready
        # But check for dormant state (waiting for some external event)
        if operstate == 'dormant':
            return 'pending'
        
        # Check for testing state
        if operstate == 'testing':
            return 'pending'
        
        return 'ready'
    
    def _query_wireguard(self, ifindex: int) -> Dict[str, Any]:
        """Query WireGuard configuration for a specific interface"""
        if self.genl_sock < 0 or self.wg_family_id < 0:
            return {}
        
        wg_info_ptr = ffi.new("wg_device_info_t*")
        result = lib.genl_query_wireguard(self.genl_sock, self.wg_family_id, ifindex, wg_info_ptr)
        
        if result < 0 or not wg_info_ptr.has_config:
            return {}
        
        wg_data = {}
        
        if wg_info_ptr.has_public_key:
            public_key_bytes = bytes(wg_info_ptr.public_key[0:32])
            wg_data['public_key'] = base64_encode(public_key_bytes)
        
        if wg_info_ptr.has_listen_port:
            wg_data['listen_port'] = wg_info_ptr.listen_port
        
        if wg_info_ptr.has_fwmark:
            wg_data['fwmark'] = wg_info_ptr.fwmark
        
        # Parse peers
        if wg_info_ptr.peer_count > 0:
            peers = []
            for i in range(wg_info_ptr.peer_count):
                peer = wg_info_ptr.peers[i]
                peer_data = {}
                
                if peer.has_public_key:
                    peer_key_bytes = bytes(peer.public_key[0:32])
                    peer_data['public_key'] = base64_encode(peer_key_bytes)
                
                if peer.has_rx_bytes:
                    peer_data['rx_bytes'] = peer.rx_bytes
                
                if peer.has_tx_bytes:
                    peer_data['tx_bytes'] = peer.tx_bytes
                
                if peer.has_last_handshake:
                    peer_data['last_handshake_time'] = peer.last_handshake_time
                
                if peer_data:
                    peers.append(peer_data)
            
            if peers:
                wg_data['peers'] = peers
        
        return wg_data
    
    def _get_links(self) -> List[Dict[str, Any]]:
        """Get link information for all interfaces"""
        seq_ptr = ffi.new("unsigned int*")
        
        if lib.nl_send_getlink(self.sock, seq_ptr) < 0:
            raise RuntimeError("Failed to send RTM_GETLINK request")
        
        seq = seq_ptr[0]
        response = lib.nl_recv_response(self.sock, seq)
        if not response:
            raise RuntimeError("Failed to receive response for RTM_GETLINK")
            
        try:
            links_ptr = ffi.new("link_info_t**")
            stats_ptr = ffi.new("link_stats_t**")
            count_ptr = ffi.new("int*")
            
            result = lib.nl_parse_links(response, links_ptr, count_ptr, stats_ptr)
            if result < 0:
                raise RuntimeError("Failed to parse link messages")
                
            links = []
            count = count_ptr[0]
            links_array = links_ptr[0]
            stats_array = stats_ptr[0]
            
            for i in range(count):
                link = links_array[i]
                stat = stats_array[i]
                
                flag_names = []
                idx = 0
                while True:
                    flag_name = lib.nl_get_flag_name(link.flags, idx)
                    if not flag_name:
                        break
                    flag_names.append(ffi.string(flag_name).decode('utf-8'))
                    idx += 1
                
                type_name_ptr = lib.nl_get_type_name(link.type)
                if type_name_ptr:
                    type_name = ffi.string(type_name_ptr).decode('utf-8')
                else:
                    type_name = f'unknown_{link.type}'
                
                operstate_name_ptr = lib.nl_get_operstate_name(link.operstate)
                if operstate_name_ptr:
                    operstate_name = ffi.string(operstate_name_ptr).decode('utf-8')
                else:
                    operstate_name = f'unknown_{link.operstate}'
                
                link_info = {
                    'index': link.index,
                    'name': ffi.string(link.name).decode('utf-8'),
                    'type': link.type,
                    'type_name': type_name,
                    'flags': link.flags,
                    'flag_names': flag_names,
                    'mtu': link.mtu,
                    'operstate': link.operstate,
                    'operstate_name': operstate_name,
                }
                
                if link.has_mac:
                    mac = ':'.join(f'{link.mac[j]:02x}' for j in range(6))
                    link_info['mac'] = mac
                
                if link.has_broadcast:
                    broadcast = ':'.join(f'{link.broadcast[j]:02x}' for j in range(6))
                    link_info['broadcast'] = broadcast
                
                if link.has_perm_address:
                    perm_mac = ':'.join(f'{link.perm_address[j]:02x}' for j in range(6))
                    link_info['perm_address'] = perm_mac
                
                if link.has_master:
                    link_info['master_index'] = link.master_index
                
                if link.has_link:
                    link_info['link'] = link.link_index
                
                if link.has_parent_dev_name:
                    link_info['parent_dev_name'] = ffi.string(link.parent_dev_name).decode('utf-8')
                
                if link.has_txqlen:
                    link_info['txqlen'] = link.txqlen
                
                if link.has_qdisc:
                    link_info['qdisc'] = ffi.string(link.qdisc).decode('utf-8')
                
                if link.has_ifalias:
                    link_info['ifalias'] = ffi.string(link.ifalias).decode('utf-8')
                
                if link.has_kind:
                    kind = ffi.string(link.kind).decode('utf-8')
                    link_info['kind'] = kind
                    
                    if link.has_vlan_id:
                        vlan_info = {'id': link.vlan_id}
                        
                        # Add VLAN protocol (ETH_P_8021Q = 802.1Q, ETH_P_8021AD = 802.1ad)
                        if link.has_vlan_protocol:
                            protocol_names = {
                                ETH_P_8021Q: '802.1Q',
                                ETH_P_8021AD: '802.1ad (QinQ)'
                            }
                            vlan_info['protocol'] = {
                                'value': f'0x{link.vlan_protocol:04x}',
                                'name': protocol_names.get(link.vlan_protocol, 'unknown')
                            }
                        
                        # Add VLAN flags
                        if link.has_vlan_flags:
                            flags_decoded = {}
                            if link.vlan_flags & VLAN_FLAG_REORDER_HDR:
                                flags_decoded['reorder_hdr'] = True
                            if link.vlan_flags & VLAN_FLAG_GVRP:
                                flags_decoded['gvrp'] = True
                            if link.vlan_flags & VLAN_FLAG_LOOSE_BINDING:
                                flags_decoded['loose_binding'] = True
                            if link.vlan_flags & VLAN_FLAG_MVRP:
                                flags_decoded['mvrp'] = True
                            if link.vlan_flags & VLAN_FLAG_BRIDGE_BINDING:
                                flags_decoded['bridge_binding'] = True
                            
                            vlan_info['flags'] = {
                                'value': link.vlan_flags,
                                'mask': link.vlan_flags_mask,
                                'decoded': flags_decoded
                            }
                        
                        link_info['vlan'] = vlan_info
                    
                    if link.has_veth_peer:
                        link_info['veth'] = {'peer_index': link.veth_peer_index}
                    
                    if link.has_tunnel_local or link.has_tunnel_remote:
                        tunnel_info = {}
                        if link.has_tunnel_local:
                            local_bytes = link.tunnel_local.to_bytes(4, byteorder='little')
                            tunnel_info['local'] = '.'.join(str(b) for b in local_bytes)
                        if link.has_tunnel_remote:
                            remote_bytes = link.tunnel_remote.to_bytes(4, byteorder='little')
                            tunnel_info['remote'] = '.'.join(str(b) for b in remote_bytes)
                        link_info['tunnel'] = tunnel_info
                    
                    # Query WireGuard via Generic Netlink
                    if kind == 'wireguard':
                        wg_info = self._query_wireguard(link.index)
                        if wg_info:
                            link_info['wireguard'] = wg_info
                            
                    # GENEVE tunnel information
                    if kind == 'geneve':
                        geneve_info = {}
                        
                        if link.geneve.has_id:
                            geneve_info['vni'] = link.geneve.id
                        
                        if link.geneve.has_remote:
                            remote_bytes = link.geneve.remote.to_bytes(4, byteorder='little')
                            geneve_info['remote'] = '.'.join(str(b) for b in remote_bytes)
                        
                        if link.geneve.has_remote6:
                            remote6_bytes = bytes(link.geneve.remote6[0:16])
                            try:
                                #import ipaddress
                                ipv6_addr = ipaddress.IPv6Address(remote6_bytes)
                                geneve_info['remote6'] = str(ipv6_addr)
                            except ValueError:
                                geneve_info['remote6'] = remote6_bytes.hex()
                        
                        if link.geneve.has_ttl:
                            geneve_info['ttl'] = link.geneve.ttl
                        
                        if link.geneve.has_tos:
                            geneve_info['tos'] = link.geneve.tos
                        
                        if link.geneve.has_port:
                            geneve_info['port'] = link.geneve.port
                        
                        if link.geneve.has_collect_metadata:
                            geneve_info['collect_metadata'] = bool(link.geneve.collect_metadata)
                        
                        if link.geneve.has_udp_csum:
                            geneve_info['udp_csum'] = bool(link.geneve.udp_csum)
                        
                        if link.geneve.has_udp_zero_csum6_tx:
                            geneve_info['udp_zero_csum6_tx'] = bool(link.geneve.udp_zero_csum6_tx)
                        
                        if link.geneve.has_udp_zero_csum6_rx:
                            geneve_info['udp_zero_csum6_rx'] = bool(link.geneve.udp_zero_csum6_rx)
                        
                        if link.geneve.has_label:
                            geneve_info['label'] = link.geneve.label
                            geneve_info['label_hex'] = f'0x{link.geneve.label:05x}'
                        
                        if link.geneve.has_ttl_inherit:
                            geneve_info['ttl_inherit'] = bool(link.geneve.ttl_inherit)
                        
                        if link.geneve.has_df:
                            df_modes = {
                                GENEVE_DF_UNSET: 'unset',
                                GENEVE_DF_SET: 'set',
                                GENEVE_DF_INHERIT: 'inherit'
                            }
                            geneve_info['df'] = df_modes.get(link.geneve.df, f'unknown_{link.geneve.df}')
                        
                        if link.geneve.has_inner_proto_inherit:
                            geneve_info['inner_proto_inherit'] = bool(link.geneve.inner_proto_inherit)
                        
                        if geneve_info:
                            link_info['geneve'] = geneve_info
                
                # DPLL Pin information (for NICs with hardware time synchronization)
                if link.dpll_pin.has_dpll_pin:
                    dpll_pin_info = {}
                    
                    if link.dpll_pin.has_pin_id:
                        dpll_pin_info['pin_id'] = link.dpll_pin.pin_id
                    
                    if link.dpll_pin.has_parent_id:
                        dpll_pin_info['parent_id'] = link.dpll_pin.parent_id
                    
                    if link.dpll_pin.has_clock_id:
                        dpll_pin_info['clock_id'] = link.dpll_pin.clock_id
                    
                    if link.dpll_pin.has_module_name:
                        dpll_pin_info['module_name'] = ffi.string(link.dpll_pin.module_name).decode('utf-8')
                    
                    if link.dpll_pin.has_board_label:
                        dpll_pin_info['board_label'] = ffi.string(link.dpll_pin.board_label).decode('utf-8')
                    
                    if link.dpll_pin.has_panel_label:
                        dpll_pin_info['panel_label'] = ffi.string(link.dpll_pin.panel_label).decode('utf-8')
                    
                    if link.dpll_pin.has_package_label:
                        dpll_pin_info['package_label'] = ffi.string(link.dpll_pin.package_label).decode('utf-8')
                    
                    if link.dpll_pin.has_pin_type:
                        pin_type_names = {
                            DPLL_PIN_TYPE_MUX: 'MUX',
                            DPLL_PIN_TYPE_EXT: 'EXT',
                            DPLL_PIN_TYPE_SYNCE_ETH_PORT: 'SYNCE_ETH_PORT',
                            DPLL_PIN_TYPE_INT_OSCILLATOR: 'INT_OSCILLATOR',
                            DPLL_PIN_TYPE_GNSS: 'GNSS'
                        }
                        dpll_pin_info['pin_type'] = {
                            'value': link.dpll_pin.pin_type,
                            'name': pin_type_names.get(link.dpll_pin.pin_type, f'unknown_{link.dpll_pin.pin_type}')
                        }
                    
                    if link.dpll_pin.has_pin_direction:
                        direction_names = {
                            DPLL_PIN_DIRECTION_INPUT: 'INPUT',
                            DPLL_PIN_DIRECTION_OUTPUT: 'OUTPUT'
                        }
                        dpll_pin_info['pin_direction'] = {
                            'value': link.dpll_pin.pin_direction,
                            'name': direction_names.get(link.dpll_pin.pin_direction, f'unknown_{link.dpll_pin.pin_direction}')
                        }
                    
                    if link.dpll_pin.has_pin_state:
                        state_names = {
                            DPLL_PIN_STATE_CONNECTED: 'CONNECTED',
                            DPLL_PIN_STATE_DISCONNECTED: 'DISCONNECTED',
                            DPLL_PIN_STATE_SELECTABLE: 'SELECTABLE'
                        }
                        dpll_pin_info['pin_state'] = {
                            'value': link.dpll_pin.pin_state,
                            'name': state_names.get(link.dpll_pin.pin_state, f'unknown_{link.dpll_pin.pin_state}')
                        }
                    
                    if link.dpll_pin.has_pin_capabilities:
                        capabilities_decoded = {}
                        if link.dpll_pin.pin_capabilities & DPLL_PIN_CAP_DIRECTION_CAN_CHANGE:
                            capabilities_decoded['direction_can_change'] = True
                        if link.dpll_pin.pin_capabilities & DPLL_PIN_CAP_PRIORITY_CAN_CHANGE:
                            capabilities_decoded['priority_can_change'] = True
                        if link.dpll_pin.pin_capabilities & DPLL_PIN_CAP_STATE_CAN_CHANGE:
                            capabilities_decoded['state_can_change'] = True
                        
                        dpll_pin_info['pin_capabilities'] = {
                            'value': link.dpll_pin.pin_capabilities,
                            'decoded': capabilities_decoded
                        }
                    
                    if link.dpll_pin.has_pin_priority:
                        dpll_pin_info['pin_priority'] = link.dpll_pin.pin_priority
                    
                    if link.dpll_pin.has_frequency:
                        dpll_pin_info['frequency'] = link.dpll_pin.frequency
                        # Add human-readable frequency
                        freq = link.dpll_pin.frequency
                        if freq >= 1_000_000_000:
                            dpll_pin_info['frequency_formatted'] = f'{freq / 1_000_000_000:.3f} GHz'
                        elif freq >= 1_000_000:
                            dpll_pin_info['frequency_formatted'] = f'{freq / 1_000_000:.3f} MHz'
                        elif freq >= 1_000:
                            dpll_pin_info['frequency_formatted'] = f'{freq / 1_000:.3f} kHz'
                        else:
                            dpll_pin_info['frequency_formatted'] = f'{freq} Hz'
                    
                    if link.dpll_pin.has_frequency_min:
                        dpll_pin_info['frequency_min'] = link.dpll_pin.frequency_min
                    
                    if link.dpll_pin.has_frequency_max:
                        dpll_pin_info['frequency_max'] = link.dpll_pin.frequency_max
                    
                    if link.dpll_pin.has_phase_adjust:
                        dpll_pin_info['phase_adjust'] = link.dpll_pin.phase_adjust
                        # Phase adjustment is in units of 1/1000th of a picosecond
                        dpll_pin_info['phase_adjust_ps'] = link.dpll_pin.phase_adjust / 1000.0
                    
                    if link.dpll_pin.has_phase_adjust_min:
                        dpll_pin_info['phase_adjust_min'] = link.dpll_pin.phase_adjust_min
                    
                    if link.dpll_pin.has_phase_adjust_max:
                        dpll_pin_info['phase_adjust_max'] = link.dpll_pin.phase_adjust_max
                    
                    if link.dpll_pin.has_phase_offset:
                        dpll_pin_info['phase_offset'] = link.dpll_pin.phase_offset
                        # Phase offset is in units of 1/1000th of a picosecond
                        dpll_pin_info['phase_offset_ps'] = link.dpll_pin.phase_offset / 1000.0
                    
                    if link.dpll_pin.has_fractional_frequency_offset:
                        dpll_pin_info['fractional_frequency_offset'] = link.dpll_pin.fractional_frequency_offset
                    
                    # Add unknown attributes if any
                    if link.dpll_pin.unknown_attrs_count > 0:
                        unknown = [link.dpll_pin.unknown_attrs[i] for i in range(link.dpll_pin.unknown_attrs_count)]
                        dpll_pin_info['unknown_dpll_attrs'] = unknown
                    
                    if dpll_pin_info:
                        link_info['dpll_pin'] = dpll_pin_info
                                                        
                
                if link.has_slave_kind:
                    link_info['slave_kind'] = ffi.string(link.slave_kind).decode('utf-8')
                
                # Additional IFLA attributes
                if link.has_linkmode:
                    link_info['linkmode'] = link.linkmode
                
                if link.has_min_mtu:
                    link_info['min_mtu'] = link.min_mtu
                
                if link.has_max_mtu:
                    link_info['max_mtu'] = link.max_mtu
                
                if link.has_group:
                    link_info['group'] = link.group
                
                if link.has_promiscuity:
                    link_info['promiscuity'] = link.promiscuity
                
                if link.has_allmulti:
                    link_info['allmulti'] = link.allmulti
                
                if link.has_num_tx_queues:
                    link_info['num_tx_queues'] = link.num_tx_queues
                
                if link.has_num_rx_queues:
                    link_info['num_rx_queues'] = link.num_rx_queues
                
                # GSO/GRO/TSO parameters
                offload_info = {}
                if link.has_gso_max_segs:
                    offload_info['gso_max_segs'] = link.gso_max_segs
                if link.has_gso_max_size:
                    offload_info['gso_max_size'] = link.gso_max_size
                if link.has_gro_max_size:
                    offload_info['gro_max_size'] = link.gro_max_size
                if link.has_gso_ipv4_max_size:
                    offload_info['gso_ipv4_max_size'] = link.gso_ipv4_max_size
                if link.has_gro_ipv4_max_size:
                    offload_info['gro_ipv4_max_size'] = link.gro_ipv4_max_size
                if link.has_tso_max_size:
                    offload_info['tso_max_size'] = link.tso_max_size
                if link.has_tso_max_segs:
                    offload_info['tso_max_segs'] = link.tso_max_segs
                
                if offload_info:
                    link_info['offload'] = offload_info
                
                # Carrier information
                if link.has_carrier:
                    link_info['carrier'] = bool(link.carrier)
                
                if link.has_carrier_changes:
                    link_info['carrier_changes'] = link.carrier_changes
                
                if link.has_carrier_up_count:
                    link_info['carrier_up_count'] = link.carrier_up_count
                
                if link.has_carrier_down_count:
                    link_info['carrier_down_count'] = link.carrier_down_count
                
                if link.has_proto_down:
                    link_info['proto_down'] = bool(link.proto_down)
                
                # Memory map (for ISA devices)
                if link.has_map:
                    link_info['map'] = {
                        'mem_start': f'0x{link.map_mem_start:x}',
                        'mem_end': f'0x{link.map_mem_end:x}',
                        'base_addr': f'0x{link.map_base_addr:x}',
                        'irq': link.map_irq,
                        'dma': link.map_dma,
                        'port': link.map_port,
                    }
                
                # ***** BRIDGE CONFIGURATION - WITH ALL NEW 30+ ATTRIBUTES! *****
                if link.bridge_config.has_bridge_config:
                    bridge_config = {}
                    
                    # STP Configuration
                    if link.bridge_config.has_stp_enabled:
                        bridge_config['stp_enabled'] = bool(link.bridge_config.stp_enabled)
                    
                    # STP Timing Parameters (centiseconds -> seconds)
                    if link.bridge_config.has_forward_delay:
                        bridge_config['forward_delay'] = link.bridge_config.forward_delay
                        bridge_config['forward_delay_sec'] = link.bridge_config.forward_delay / 100.0
                    
                    if link.bridge_config.has_hello_time:
                        bridge_config['hello_time'] = link.bridge_config.hello_time
                        bridge_config['hello_time_sec'] = link.bridge_config.hello_time / 100.0
                    
                    if link.bridge_config.has_max_age:
                        bridge_config['max_age'] = link.bridge_config.max_age
                        bridge_config['max_age_sec'] = link.bridge_config.max_age / 100.0
                    
                    # STP Runtime Timers (NEW!)
                    if link.bridge_config.has_hello_timer:
                        bridge_config['hello_timer'] = link.bridge_config.hello_timer
                        bridge_config['hello_timer_sec'] = link.bridge_config.hello_timer / 100.0
                    
                    if link.bridge_config.has_tcn_timer:
                        bridge_config['tcn_timer'] = link.bridge_config.tcn_timer
                        bridge_config['tcn_timer_sec'] = link.bridge_config.tcn_timer / 100.0
                    
                    if link.bridge_config.has_topology_change_timer:
                        bridge_config['topology_change_timer'] = link.bridge_config.topology_change_timer
                        bridge_config['topology_change_timer_sec'] = link.bridge_config.topology_change_timer / 100.0
                    
                    if link.bridge_config.has_gc_timer:
                        bridge_config['gc_timer'] = link.bridge_config.gc_timer
                        bridge_config['gc_timer_sec'] = link.bridge_config.gc_timer / 100.0
                    
                    # STP Status Flags (NEW!)
                    if link.bridge_config.has_topology_change:
                        bridge_config['topology_change'] = bool(link.bridge_config.topology_change)
                    
                    if link.bridge_config.has_topology_change_detected:
                        bridge_config['topology_change_detected'] = bool(link.bridge_config.topology_change_detected)
                    
                    # STP Priority and IDs
                    if link.bridge_config.has_priority:
                        bridge_config['priority'] = link.bridge_config.priority
                    
                    if link.bridge_config.has_root_id:
                        root_id_bytes = bytes(link.bridge_config.root_id[0:8])
                        priority = (root_id_bytes[0] << 8) | root_id_bytes[1]
                        mac = ':'.join(f'{root_id_bytes[i]:02x}' for i in range(2, 8))
                        bridge_config['root_id'] = f'{priority:04x}.{mac}'
                    
                    if link.bridge_config.has_bridge_id:
                        bridge_id_bytes = bytes(link.bridge_config.bridge_id[0:8])
                        priority = (bridge_id_bytes[0] << 8) | bridge_id_bytes[1]
                        mac = ':'.join(f'{bridge_id_bytes[i]:02x}' for i in range(2, 8))
                        bridge_config['bridge_id'] = f'{priority:04x}.{mac}'
                    
                    if link.bridge_config.has_root_port:
                        bridge_config['root_port'] = link.bridge_config.root_port
                    
                    if link.bridge_config.has_root_path_cost:
                        bridge_config['root_path_cost'] = link.bridge_config.root_path_cost
                    
                    # MAC Learning
                    if link.bridge_config.has_ageing_time:
                        bridge_config['ageing_time'] = link.bridge_config.ageing_time
                        bridge_config['ageing_time_sec'] = link.bridge_config.ageing_time / 100.0
                    
                    if link.bridge_config.has_fdb_n_learned:
                        bridge_config['fdb_n_learned'] = link.bridge_config.fdb_n_learned
                    
                    if link.bridge_config.has_fdb_max_learned:
                        bridge_config['fdb_max_learned'] = link.bridge_config.fdb_max_learned
                    
                    # VLAN Configuration
                    if link.bridge_config.has_vlan_filtering:
                        bridge_config['vlan_filtering'] = bool(link.bridge_config.vlan_filtering)
                    
                    if link.bridge_config.has_vlan_protocol:
                        bridge_config['vlan_protocol'] = link.bridge_config.vlan_protocol
                        bridge_config['vlan_protocol_hex'] = f'0x{link.bridge_config.vlan_protocol:04x}'
                        if link.bridge_config.vlan_protocol == ETH_P_8021Q:
                            bridge_config['vlan_protocol_name'] = '802.1Q'
                        elif link.bridge_config.vlan_protocol == ETH_P_8021AD:
                            bridge_config['vlan_protocol_name'] = '802.1ad (QinQ)'
                    
                    if link.bridge_config.has_vlan_default_pvid:
                        bridge_config['vlan_default_pvid'] = link.bridge_config.vlan_default_pvid
                    
                    if link.bridge_config.has_vlan_stats_enabled:
                        bridge_config['vlan_stats_enabled'] = bool(link.bridge_config.vlan_stats_enabled)
                    
                    if link.bridge_config.has_vlan_stats_per_port:
                        bridge_config['vlan_stats_per_port'] = bool(link.bridge_config.vlan_stats_per_port)
                    
                    # Group Forwarding (NEW!)
                    if link.bridge_config.has_group_fwd_mask:
                        bridge_config['group_fwd_mask'] = link.bridge_config.group_fwd_mask
                        bridge_config['group_fwd_mask_hex'] = f'0x{link.bridge_config.group_fwd_mask:04x}'
                    
                    if link.bridge_config.has_group_addr:
                        group_addr = ':'.join(f'{link.bridge_config.group_addr[j]:02x}' for j in range(6))
                        bridge_config['group_addr'] = group_addr
                    
                    # Multicast Snooping (NEW!)
                    if link.bridge_config.has_mcast_snooping:
                        bridge_config['mcast_snooping'] = bool(link.bridge_config.mcast_snooping)
                    
                    if link.bridge_config.has_mcast_router:
                        bridge_config['mcast_router'] = link.bridge_config.mcast_router
                        mcast_router_modes = {
                            MDB_RTR_TYPE_DISABLED: 'disabled',
                            MDB_RTR_TYPE_TEMP_QUERY: 'auto',
                            MDB_RTR_TYPE_PERM: 'enabled'
                        }
                        bridge_config['mcast_router_mode'] = mcast_router_modes.get(
                            link.bridge_config.mcast_router, 'unknown'
                        )
                    
                    if link.bridge_config.has_mcast_querier:
                        bridge_config['mcast_querier'] = bool(link.bridge_config.mcast_querier)
                    
                    if link.bridge_config.has_mcast_query_use_ifaddr:
                        bridge_config['mcast_query_use_ifaddr'] = bool(link.bridge_config.mcast_query_use_ifaddr)
                    
                    if link.bridge_config.has_mcast_stats_enabled:
                        bridge_config['mcast_stats_enabled'] = bool(link.bridge_config.mcast_stats_enabled)
                    
                    if link.bridge_config.has_mcast_igmp_version:
                        bridge_config['mcast_igmp_version'] = link.bridge_config.mcast_igmp_version
                    
                    if link.bridge_config.has_mcast_mld_version:
                        bridge_config['mcast_mld_version'] = link.bridge_config.mcast_mld_version
                    
                    # Multicast Hash Table (NEW!)
                    if link.bridge_config.has_mcast_hash_elasticity:
                        bridge_config['mcast_hash_elasticity'] = link.bridge_config.mcast_hash_elasticity
                    
                    if link.bridge_config.has_mcast_hash_max:
                        bridge_config['mcast_hash_max'] = link.bridge_config.mcast_hash_max
                    
                    # Multicast Timing Parameters (NEW! - centiseconds -> seconds)
                    if link.bridge_config.has_mcast_last_member_cnt:
                        bridge_config['mcast_last_member_cnt'] = link.bridge_config.mcast_last_member_cnt
                    
                    if link.bridge_config.has_mcast_startup_query_cnt:
                        bridge_config['mcast_startup_query_cnt'] = link.bridge_config.mcast_startup_query_cnt
                    
                    if link.bridge_config.has_mcast_last_member_intvl:
                        bridge_config['mcast_last_member_intvl'] = link.bridge_config.mcast_last_member_intvl
                        bridge_config['mcast_last_member_intvl_sec'] = link.bridge_config.mcast_last_member_intvl / 100.0
                    
                    if link.bridge_config.has_mcast_membership_intvl:
                        bridge_config['mcast_membership_intvl'] = link.bridge_config.mcast_membership_intvl
                        bridge_config['mcast_membership_intvl_sec'] = link.bridge_config.mcast_membership_intvl / 100.0
                    
                    if link.bridge_config.has_mcast_querier_intvl:
                        bridge_config['mcast_querier_intvl'] = link.bridge_config.mcast_querier_intvl
                        bridge_config['mcast_querier_intvl_sec'] = link.bridge_config.mcast_querier_intvl / 100.0
                    
                    if link.bridge_config.has_mcast_query_intvl:
                        bridge_config['mcast_query_intvl'] = link.bridge_config.mcast_query_intvl
                        bridge_config['mcast_query_intvl_sec'] = link.bridge_config.mcast_query_intvl / 100.0
                    
                    if link.bridge_config.has_mcast_query_response_intvl:
                        bridge_config['mcast_query_response_intvl'] = link.bridge_config.mcast_query_response_intvl
                        bridge_config['mcast_query_response_intvl_sec'] = link.bridge_config.mcast_query_response_intvl / 100.0
                    
                    if link.bridge_config.has_mcast_startup_query_intvl:
                        bridge_config['mcast_startup_query_intvl'] = link.bridge_config.mcast_startup_query_intvl
                        bridge_config['mcast_startup_query_intvl_sec'] = link.bridge_config.mcast_startup_query_intvl / 100.0
                    
                    # Netfilter Integration (NEW!)
                    if link.bridge_config.has_nf_call_iptables:
                        bridge_config['nf_call_iptables'] = bool(link.bridge_config.nf_call_iptables)
                    
                    if link.bridge_config.has_nf_call_ip6tables:
                        bridge_config['nf_call_ip6tables'] = bool(link.bridge_config.nf_call_ip6tables)
                    
                    if link.bridge_config.has_nf_call_arptables:
                        bridge_config['nf_call_arptables'] = bool(link.bridge_config.nf_call_arptables)
                    
                    # Advanced Options (NEW!)
                    if link.bridge_config.has_multi_boolopt:
                        bridge_config['multi_boolopt'] = link.bridge_config.multi_boolopt
                        bridge_config['multi_boolopt_hex'] = f'0x{link.bridge_config.multi_boolopt:016x}'
                    
                    link_info['bridge_config'] = bridge_config
                    
# Bridge port information
                if link.bridge_port.has_bridge_info:
                    stp_state_ptr = lib.nl_get_stp_state_name(link.bridge_port.state)
                    if stp_state_ptr:
                        stp_state = ffi.string(stp_state_ptr).decode('utf-8')
                    else:
                        stp_state = f'unknown_{link.bridge_port.state}'
                    
                    bridge_port = {
                        'stp_state': stp_state,
                        'stp_state_value': link.bridge_port.state,
                        'data_source': 'new_api' if link.bridge_port.data_source_priority == 2 else 'old_api'
                    }
                    
                    if link.bridge_port.has_priority:
                        bridge_port['priority'] = link.bridge_port.priority
                    if link.bridge_port.has_cost:
                        bridge_port['cost'] = link.bridge_port.cost
                    if link.bridge_port.has_mode:
                        bridge_port['mode'] = bool(link.bridge_port.mode)
                    if link.bridge_port.has_guard:
                        bridge_port['guard'] = bool(link.bridge_port.guard)
                    if link.bridge_port.has_protect:
                        bridge_port['protect'] = bool(link.bridge_port.protect)
                    if link.bridge_port.has_fast_leave:
                        bridge_port['fast_leave'] = bool(link.bridge_port.fast_leave)
                    if link.bridge_port.has_learning:
                        bridge_port['learning'] = bool(link.bridge_port.learning)
                    if link.bridge_port.has_unicast_flood:
                        bridge_port['unicast_flood'] = bool(link.bridge_port.unicast_flood)
                    if link.bridge_port.has_proxyarp:
                        bridge_port['proxyarp'] = bool(link.bridge_port.proxyarp)
                    if link.bridge_port.has_proxyarp_wifi:
                        bridge_port['proxyarp_wifi'] = bool(link.bridge_port.proxyarp_wifi)
                    if link.bridge_port.has_multicast_router:
                        bridge_port['multicast_router'] = link.bridge_port.multicast_router
                    
                    if self.capture_unknown_attrs and link.bridge_port.unknown_attrs_count > 0:
                        unknown_list = []
                        for j in range(link.bridge_port.unknown_attrs_count):
                            unknown_list.append(link.bridge_port.unknown_attrs[j])
                        bridge_port['unknown_attrs'] = unknown_list
                        bridge_port['unknown_attrs_decoded'] = decode_unknown_attrs(
                            unknown_list, 'IFLA_BRPORT'
                        )
                    
                    link_info['bridge_port'] = bridge_port
                
                # Unknown attributes
                if self.capture_unknown_attrs and link.unknown_info_data_attrs_count > 0:
                    unknown_list = []
                    for j in range(link.unknown_info_data_attrs_count):
                        unknown_list.append(link.unknown_info_data_attrs[j])
                    link_info['unknown_info_data_attrs'] = unknown_list
                    kind = link_info.get('kind', 'UNKNOWN')
                    link_info['unknown_info_data_attrs_decoded'] = decode_unknown_attrs(
                        unknown_list, f'IFLA_{kind.upper()}'
                    )
                
                if self.capture_unknown_attrs and link.unknown_linkinfo_attrs_count > 0:
                    unknown_list = []
                    for j in range(link.unknown_linkinfo_attrs_count):
                        unknown_list.append(link.unknown_linkinfo_attrs[j])
                    link_info['unknown_linkinfo_attrs'] = unknown_list
                    link_info['unknown_linkinfo_attrs_decoded'] = decode_unknown_attrs(
                        unknown_list, 'IFLA_INFO'
                    )
                
                if self.capture_unknown_attrs and link.unknown_ifla_attrs_count > 0:
                    unknown_list = []
                    for j in range(link.unknown_ifla_attrs_count):
                        unknown_list.append(link.unknown_ifla_attrs[j])
                    link_info['unknown_ifla_attrs'] = unknown_list
                    link_info['unknown_ifla_attrs_decoded'] = decode_unknown_attrs(
                        unknown_list, 'IFLA'
                    )
                
                link_info['stats'] = {
                    'rx_packets': stat.rx_packets,
                    'tx_packets': stat.tx_packets,
                    'rx_bytes': stat.rx_bytes,
                    'tx_bytes': stat.tx_bytes,
                    'rx_errors': stat.rx_errors,
                    'tx_errors': stat.tx_errors,
                    'rx_dropped': stat.rx_dropped,
                    'tx_dropped': stat.tx_dropped,
                    'multicast': stat.multicast,
                    'collisions': stat.collisions,
                    'rx_length_errors': stat.rx_length_errors,
                    'rx_over_errors': stat.rx_over_errors,
                    'rx_crc_errors': stat.rx_crc_errors,
                    'rx_frame_errors': stat.rx_frame_errors,
                    'rx_fifo_errors': stat.rx_fifo_errors,
                    'rx_missed_errors': stat.rx_missed_errors,
                    'tx_aborted_errors': stat.tx_aborted_errors,
                    'tx_carrier_errors': stat.tx_carrier_errors,
                    'tx_fifo_errors': stat.tx_fifo_errors,
                    'tx_heartbeat_errors': stat.tx_heartbeat_errors,
                    'tx_window_errors': stat.tx_window_errors,
                    'rx_compressed': stat.rx_compressed,
                    'tx_compressed': stat.tx_compressed,
                    'rx_nohandler': stat.rx_nohandler,
                    'is_64bit': bool(stat.has_stats64),
                }
                    
                links.append(link_info)
                
            lib.nl_free_links(links_array, count)
            lib.nl_free_stats(stats_array)
            return links
            
        finally:
            lib.nl_free_response(response)
    
    def _get_addrs(self) -> List[Dict[str, Any]]:
        """Get address information for all interfaces"""
        seq_ptr = ffi.new("unsigned int*")
        
        if lib.nl_send_getaddr(self.sock, seq_ptr) < 0:
            raise RuntimeError("Failed to send RTM_GETADDR request")
        
        seq = seq_ptr[0]
        response = lib.nl_recv_response(self.sock, seq)
        if not response:
            raise RuntimeError("Failed to receive response for RTM_GETADDR")
            
        try:
            addrs_ptr = ffi.new("addr_info_t**")
            count_ptr = ffi.new("int*")
            
            result = lib.nl_parse_addrs(response, addrs_ptr, count_ptr)
            if result < 0:
                raise RuntimeError("Failed to parse address messages")
                
            addrs = []
            count = count_ptr[0]
            addrs_array = addrs_ptr[0]
            
            for i in range(count):
                addr = addrs_array[i]
                
                family_name = 'ipv4' if addr.family == AF_INET else 'ipv6' if addr.family == AF_INET6 else f'af_{addr.family}'
                
                scope_name_ptr = lib.nl_get_scope_name(addr.scope)
                if scope_name_ptr:
                    scope_name = ffi.string(scope_name_ptr).decode('utf-8')
                else:
                    scope_name = f'custom_{addr.scope}'
                
                addr_info = {
                    'index': addr.index,
                    'family': family_name,
                    'prefixlen': addr.prefixlen,
                    'scope': addr.scope,
                    'scope_name': scope_name,
                    'flags': addr.flags,
                }
                
                # Use extended_flags for flag decoding if available (32-bit), otherwise use 8-bit flags
                if addr.has_extended_flags:
                    addr_info['extended_flags'] = addr.extended_flags
                    
                    # Decode extended flags (32-bit) - family aware for SECONDARY vs TEMPORARY
                    is_ipv6 = 1 if addr.family == AF_INET6 else 0
                    flag_names = []
                    idx = 0
                    while True:
                        flag_name = lib.nl_get_extended_flag_name(addr.extended_flags, idx, is_ipv6)
                        if not flag_name:
                            break
                        flag_names.append(ffi.string(flag_name).decode('utf-8'))
                        idx += 1
                    
                    addr_info['flag_names'] = flag_names
                    
                    # Set secondary/temporary based on extended flags
                    if addr.family == AF_INET:
                        addr_info['is_secondary'] = bool(lib.nl_is_extended_secondary(addr.extended_flags))
                    elif addr.family == AF_INET6:
                        addr_info['is_temporary'] = bool(lib.nl_is_extended_temporary(addr.extended_flags))
                else:
                    # Fall back to 8-bit flags
                    flag_names = []
                    idx = 0
                    if addr.family == AF_INET:
                        while True:
                            flag_name = lib.nl_get_ipv4_flag_name(addr.flags, idx)
                            if not flag_name:
                                break
                            flag_names.append(ffi.string(flag_name).decode('utf-8'))
                            idx += 1
                        addr_info['is_secondary'] = bool(lib.nl_is_ipv4_secondary(addr.flags))
                    elif addr.family == AF_INET6:
                        while True:
                            flag_name = lib.nl_get_ipv6_flag_name(addr.flags, idx)
                            if not flag_name:
                                break
                            flag_names.append(ffi.string(flag_name).decode('utf-8'))
                            idx += 1
                        addr_info['is_temporary'] = bool(lib.nl_is_ipv6_temporary(addr.flags))
                    
                    addr_info['flag_names'] = flag_names
                
                # Cache info (address lifetimes)
                if addr.has_cacheinfo:
                    cacheinfo = {
                        'preferred_lft': addr.preferred_lft,
                        'valid_lft': addr.valid_lft,
                        'created_tstamp': addr.created_tstamp,
                        'updated_tstamp': addr.updated_tstamp,
                    }
                    if addr.preferred_lft == 0xFFFFFFFF:
                        cacheinfo['preferred_lft_str'] = 'forever'
                    else:
                        cacheinfo['preferred_lft_str'] = f'{addr.preferred_lft}s'
                    
                    if addr.valid_lft == 0xFFFFFFFF:
                        cacheinfo['valid_lft_str'] = 'forever'
                    else:
                        cacheinfo['valid_lft_str'] = f'{addr.valid_lft}s'
                    
                    addr_info['cacheinfo'] = cacheinfo
                
                # Protocol (IFA_PROTO) - address configuration source
                if addr.has_protocol:
                    addr_info['protocol'] = addr.protocol
                    addr_info['protocol_name'] = IFA_PROTO_NAMES.get(addr.protocol, f'unknown_{addr.protocol}')
                
                if addr.family == AF_INET:
                    addr_bytes = bytes(addr.address[0:4])
                    addr_str = '.'.join(str(b) for b in addr_bytes)
                    addr_info['address'] = addr_str
                    
                    try:
                        ipif = ipaddress.IPv4Interface(f"{addr_str}/{addr.prefixlen}")
                        addr_info['ipinterface'] = str(ipif)
                        addr_info['network'] = str(ipif.network)
                        addr_info['netmask'] = str(ipif.netmask)
                        addr_info['hostmask'] = str(ipif.hostmask)
                    except ValueError as e:
                        addr_info['ipinterface_error'] = str(e)
                    
                    if addr.has_local:
                        local_bytes = bytes(addr.local[0:4])
                        addr_info['local'] = '.'.join(str(b) for b in local_bytes)
                        
                    if addr.has_broadcast:
                        bcast_bytes = bytes(addr.broadcast[0:4])
                        addr_info['broadcast'] = '.'.join(str(b) for b in bcast_bytes)
                        
                elif addr.family == AF_INET6:
                    addr_bytes = bytes(addr.address[0:16])
                    
                    try:
                        ipv6_addr = ipaddress.IPv6Address(addr_bytes)
                        addr_str = str(ipv6_addr)
                        addr_info['address'] = addr_str
                        
                        ipif = ipaddress.IPv6Interface(f"{addr_str}/{addr.prefixlen}")
                        addr_info['ipinterface'] = str(ipif)
                        addr_info['network'] = str(ipif.network)
                        addr_info['netmask'] = str(ipif.netmask)
                        addr_info['hostmask'] = str(ipif.hostmask)
                    except ValueError as e:
                        addr_info['ipinterface_error'] = str(e)
                
                if addr.label[0]:
                    addr_info['label'] = ffi.string(addr.label).decode('utf-8')
                
                if self.capture_unknown_attrs and addr.unknown_ifa_attrs_count > 0:
                    unknown_list = []
                    for j in range(addr.unknown_ifa_attrs_count):
                        unknown_list.append(addr.unknown_ifa_attrs[j])
                    addr_info['unknown_ifa_attrs'] = unknown_list
                    addr_info['unknown_ifa_attrs_decoded'] = decode_unknown_attrs(
                        unknown_list, 'IFA'
                    )
                    
                addrs.append(addr_info)
                
            lib.nl_free_addrs(addrs_array)
            return addrs
            
        finally:
            lib.nl_free_response(response)
                
# Example usage
def main():
        """Main entry point for the netmon-device command."""
        import argparse
    
        parser = argparse.ArgumentParser(description='RTNetlink Query Tool with WireGuard Support')
        parser.add_argument('--no-unknown-attrs', action='store_true',
                            help='Disable unknown attribute tracking for cleaner output')
        parser.add_argument('-d', '--device',
                            type=str,
                            dest='device',
                            metavar='DEVICE',
                            help='Filter output to show only the specified device/interface (e.g., eth0, wlan0)')
        parser.add_argument('--summary', action='store_true',
                            help='Show only a summary of special interfaces')
        parser.add_argument('--wireguard', action='store_true',
                            help='Show only WireGuard interfaces')
        parser.add_argument('--extended','--verbose','-v', action='store_true',
                            help='Show extended interface details (offload, carrier stats, etc.)')
        parser.add_argument('--addresses', action='store_true',
                            help='Show detailed address information with extended flags')
        parser.add_argument("-j","--json",action='store_true',help="Output in pure JSON format (default)")
        parser.add_argument("-t","--text",action='store_true',help="Output in text format")
        
        args = parser.parse_args()
        if args.json and (args.summary or args.wireguard or args.extended or args.addresses):
            parser.error(
                f"Only --no-unknown-attrs is allowed with -j or --json"
            )
            
        try:
            if (not args.json) and (len(sys.argv) != 1):
                print("=" * 70)
                print("RTNetlink Extended + WireGuard + Extended Address Flags")
                print("=" * 70)
                print(f"Unknown attribute tracking: {'DISABLED' if args.no_unknown_attrs else 'ENABLED'}")
                if args.device:
                    print(f"Filtering by device: {args.device}")
                print()

            with RTNetlinkQuery(capture_unknown_attrs=not args.no_unknown_attrs) as rtq:
                interfaces = rtq.get_interfaces()

            # Apply device filter if specified
            if args.device:
                if args.device in interfaces:
                    interfaces = {args.device: interfaces[args.device]}
                else:
                    interfaces = {}
                    if not args.json:
                        print(f"Warning: Device '{args.device}' not found", file=sys.stderr)

            if args.wireguard:
                # Show only WireGuard interfaces
                print("\nWireGuard Interfaces:")
                print("=" * 70)

                wg_found = False
                for if_name, if_info in interfaces.items():
                    if if_info.get('kind') == 'wireguard':
                        wg_found = True
                        print(f"\nInterface: {if_name}")
                        print(f"  Index: {if_info['index']}")
                        print(f"  State: {if_info['operstate_name']}")

                        if 'wireguard' in if_info:
                            wg = if_info['wireguard']
                            if 'listen_port' in wg:
                                print(f"  Listen Port: {wg['listen_port']}")
                            if 'fwmark' in wg:
                                print(f"  Firewall Mark: {wg['fwmark']}")
                            if 'public_key' in wg:
                                print(f"  Public Key: {wg['public_key']}")
                            if 'peers' in wg:
                                print(f"  Peers: {len(wg['peers'])}")
                                for i, peer in enumerate(wg['peers'], 1):
                                    print(f"    Peer {i}:")
                                    if 'public_key' in peer:
                                        print(f"      Public Key: {peer['public_key']}")
                                    if 'rx_bytes' in peer:
                                        print(f"      RX Bytes: {peer['rx_bytes']:,}")
                                    if 'tx_bytes' in peer:
                                        print(f"      TX Bytes: {peer['tx_bytes']:,}")
                                    if 'last_handshake_time' in peer:
                                        import time
                                        secs_ago = int(time.time()) - peer['last_handshake_time']
                                        print(f"      Last Handshake: {secs_ago}s ago")
                        else:
                            print("  (WireGuard kernel module not loaded or no access)")

                if not wg_found:
                    print("\nNo WireGuard interfaces found.")

            elif args.extended:
                # Show extended interface details
                print("\nExtended Interface Details:")
                print("=" * 70)

                for if_name, if_info in interfaces.items():
                    print(f"\n{if_name} (index {if_info['index']}):")
                    print(f"  Type: {if_info['type_name']}")
                    print(f"  MTU: {if_info['mtu']}", end="")
                    if 'min_mtu' in if_info or 'max_mtu' in if_info:
                        print(" (", end="")
                        if 'min_mtu' in if_info:
                            print(f"min:{if_info['min_mtu']}", end="")
                        if 'min_mtu' in if_info and 'max_mtu' in if_info:
                            print(" - ", end="")
                        if 'max_mtu' in if_info:
                            print(f"max:{if_info['max_mtu']}", end="")
                        print(")", end="")
                    print()

                    if 'group' in if_info:
                        print(f"  Group: {if_info['group']}")

                    if 'num_tx_queues' in if_info or 'num_rx_queues' in if_info:
                        print(f"  Queues: ", end="")
                        if 'num_tx_queues' in if_info:
                            print(f"TX={if_info['num_tx_queues']}", end="")
                        if 'num_tx_queues' in if_info and 'num_rx_queues' in if_info:
                            print(", ", end="")
                        if 'num_rx_queues' in if_info:
                            print(f"RX={if_info['num_rx_queues']}", end="")
                        print()

                    if 'promiscuity' in if_info:
                        print(f"  Promiscuity count: {if_info['promiscuity']}")

                    if 'allmulti' in if_info:
                        print(f"  Allmulti count: {if_info['allmulti']}")

                    if 'carrier' in if_info:
                        print(f"  Carrier: {'UP' if if_info['carrier'] else 'DOWN'}")

                    if 'carrier_changes' in if_info:
                        print(f"  Carrier changes: {if_info['carrier_changes']}", end="")
                        if 'carrier_up_count' in if_info and 'carrier_down_count' in if_info:
                            print(f" (up:{if_info['carrier_up_count']}, down:{if_info['carrier_down_count']})", end="")
                        print()

                    if 'proto_down' in if_info:
                        print(f"  Protocol down: {if_info['proto_down']}")

                    if 'linkmode' in if_info:
                        mode_str = "dormant" if if_info['linkmode'] == 1 else "default" if if_info['linkmode'] == 0 else f"unknown({if_info['linkmode']})"
                        print(f"  Link mode: {mode_str}")

                    if 'offload' in if_info:
                        print(f"  Offload capabilities:")
                        off = if_info['offload']
                        if 'gso_max_segs' in off:
                            print(f"    GSO max segments: {off['gso_max_segs']}")
                        if 'gso_max_size' in off:
                            print(f"    GSO max size: {off['gso_max_size']} bytes")
                        if 'gso_ipv4_max_size' in off:
                            print(f"    GSO IPv4 max size: {off['gso_ipv4_max_size']} bytes")
                        if 'gro_max_size' in off:
                            print(f"    GRO max size: {off['gro_max_size']} bytes")
                        if 'gro_ipv4_max_size' in off:
                            print(f"    GRO IPv4 max size: {off['gro_ipv4_max_size']} bytes")
                        if 'tso_max_size' in off:
                            print(f"    TSO max size: {off['tso_max_size']} bytes")
                        if 'tso_max_segs' in off:
                            print(f"    TSO max segments: {off['tso_max_segs']}")

                    if 'map' in if_info:
                        print(f"  Memory map:")
                        m = if_info['map']
                        print(f"    Memory: {m['mem_start']} - {m['mem_end']}")
                        print(f"    Base addr: {m['base_addr']}")
                        print(f"    IRQ: {m['irq']}, DMA: {m['dma']}, Port: {m['port']}")

            elif args.addresses:
                # Show detailed address information
                print("\nDetailed Address Information:")
                print("=" * 70)
                print("Readiness: ✓=ready, ⋯=pending, ✗=failed, ○=down")
                print()

                for if_name, if_info in interfaces.items():
                    if not if_info['addresses']:
                        continue

                    print(f"\n{if_name}:")
                    for addr in if_info['addresses']:
                        # Show readiness status with color coding would be nice, but we'll use symbols
                        readiness_symbol = {
                            'ready': '✓',
                            'pending': '⋯',
                            'failed': '✗',
                            'down': '○'
                        }.get(addr.get('readiness', 'unknown'), '?')

                        print(f"  {addr['family']} [{readiness_symbol} {addr.get('readiness', 'unknown').upper()}]:")
                        if 'address' in addr:
                            print(f"    Address: {addr['address']}/{addr['prefixlen']}")
                        if 'ipinterface' in addr:
                            print(f"    Network: {addr['network']}")
                            print(f"    Netmask: {addr['netmask']}")

                        if 'local' in addr:
                            print(f"    Local: {addr['local']}")
                        if 'broadcast' in addr:
                            print(f"    Broadcast: {addr['broadcast']}")

                        print(f"    Scope: {addr['scope_name']}")

                        # Display flags
                        if 'extended_flags' in addr:
                            print(f"    Flags: 0x{addr['extended_flags']:08x} (extended 32-bit)")
                        else:
                            print(f"    Flags: 0x{addr['flags']:02x} (legacy 8-bit)")

                        if addr['flag_names']:
                            print(f"      {', '.join(addr['flag_names'])}")

                        # Special flag interpretations - family-specific
                        if addr['family'] == 'ipv4' and 'is_secondary' in addr:
                            print(f"      → Secondary/Alias address: {addr['is_secondary']}")
                        elif addr['family'] == 'ipv6' and 'is_temporary' in addr:
                            print(f"      → Temporary/Privacy address: {addr['is_temporary']}")

                        # Readiness explanation
                        readiness_explanation = {
                            'ready': 'Address is fully operational and usable',
                            'pending': 'Address is being configured (IPv6 DAD in progress or link dormant)',
                            'failed': 'Address failed Duplicate Address Detection',
                            'down': 'Interface is administratively or operationally down'
                        }
                        if addr.get('readiness') in readiness_explanation:
                            print(f"    Readiness: {addr['readiness'].upper()}")
                            print(f"      → {readiness_explanation[addr['readiness']]}")
                    
                        # Protocol (address configuration source) - mainly relevant for IPv6
                        if 'protocol' in addr and addr['family'] == 'ipv6':
                            protocol_descriptions = {
                                'unspecified': 'Unspecified (manually configured or unknown source)',
                                'kernel_lo': 'Loopback address configured by kernel',
                                'kernel_ra': 'Auto-configured via IPv6 Router Advertisement (SLAAC)',
                                'kernel_ll': 'Link-local address auto-configured by kernel',
                            }
                            proto_name = addr.get('protocol_name', f"unknown_{addr['protocol']}")
                            print(f"    Protocol: {proto_name} ({addr['protocol']})")
                            if proto_name in protocol_descriptions:
                                print(f"      → {protocol_descriptions[proto_name]}")

                        # Cache info
                        if 'cacheinfo' in addr:
                            cache = addr['cacheinfo']
                            print(f"    Lifetime:")
                            print(f"      Preferred: {cache['preferred_lft_str']}")
                            print(f"      Valid: {cache['valid_lft_str']}")
                            if cache['created_tstamp'] > 0:
                                print(f"      Created: {cache['created_tstamp']}s ago")
                            if cache['updated_tstamp'] > 0:
                                print(f"      Updated: {cache['updated_tstamp']}s ago")

            elif args.summary:
                # Show summary of special interfaces
                print("\nSpecial Interfaces Summary:")
                print("=" * 70)

                for if_name, if_info in interfaces.items():
                    special_info = []

                    if if_info.get('kind') == 'bridge':
                        special_info.append("Bridge")
                        if 'bridge_config' in if_info:
                            bc = if_info['bridge_config']
                            if bc.get('stp_enabled'):
                                special_info.append("STP:enabled")
                            if 'vlan_filtering' in bc:
                                special_info.append(f"VLAN:{'on' if bc['vlan_filtering'] else 'off'}")

                    if if_info.get('kind') == 'wireguard':
                        special_info.append("WireGuard")
                        if 'wireguard' in if_info:
                            wg = if_info['wireguard']
                            if 'listen_port' in wg:
                                special_info.append(f"port:{wg['listen_port']}")
                            if 'peers' in wg:
                                special_info.append(f"peers:{len(wg['peers'])}")

                    if if_info.get('kind') == 'veth':
                        special_info.append("veth")
                        if 'veth' in if_info and 'peer' in if_info['veth']:
                            special_info.append(f"peer:{if_info['veth']['peer']}")

                    if if_info.get('kind') == 'vlan':
                        special_info.append("VLAN")
                        if 'vlan' in if_info:
                            special_info.append(f"id:{if_info['vlan']['id']}")
                        if 'master' in if_info:
                            special_info.append(f"on:{if_info['master']}")
                        

                    if if_info.get('kind') == 'geneve':
                        special_info.append("GENEVE")
                        if 'geneve' in if_info:
                            geneve = if_info['geneve']
                            if 'vni' in geneve:
                                special_info.append(f"vni:{geneve['vni']}")
                            if 'remote' in geneve:
                                special_info.append(f"remote:{geneve['remote']}")
                            elif 'remote6' in geneve:
                                special_info.append(f"remote:{geneve['remote6']}")
                            if 'port' in geneve:
                                special_info.append(f"port:{geneve['port']}")                        

                    if 'bridge_port' in if_info:
                        bp = if_info['bridge_port']
                        special_info.append(f"bridge_port:{bp['stp_state']}")
                        if 'master' in if_info:
                            special_info.append(f"of:{if_info['master']}")

                    if special_info:
                        print(f"\n{if_name}: {', '.join(special_info)}")
            else:
                # Full JSON output
                print(json.dumps(interfaces, indent=2))

            if (not args.json) and (len(sys.argv) != 1):
                print()
                print("=" * 70)
                print("✓ Query complete!")
                print("=" * 70)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)
        
        return 0


if __name__ == '__main__':
    main()
    
