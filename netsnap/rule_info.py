#!/usr/bin/env python3
"""
RTNetlink Routing Rule Query with C Library via CFFI
Complete routing rule (policy routing) inspection including:
- IPv4 and IPv6 rules
- Rule priorities and actions
- Source and destination selectors
- Input/output interface matching
- Firewall mark (fwmark) matching
- Routing table selection
- Rule types and actions

Rule Actions:
- FR_ACT_UNSPEC: Unspecified
- FR_ACT_TO_TBL: Lookup in routing table
- FR_ACT_GOTO: Jump to another rule
- FR_ACT_NOP: No operation
- FR_ACT_BLACKHOLE: Silent discard
- FR_ACT_UNREACHABLE: ICMP unreachable
- FR_ACT_PROHIBIT: ICMP prohibited

Requirements:
    - Python 3.8+
    - cffi>=1.0.0
    - setuptools (required for Python 3.12+)

Install:
    pip install cffi setuptools

Usage:
    sudo python3 net_rule_info.py                    # Full JSON output
    sudo python3 net_rule_info.py --summary          # Human-readable summary
    sudo python3 net_rule_info.py --ipv4             # IPv4 rules only
    sudo python3 net_rule_info.py --ipv6             # IPv6 rules only
    sudo python3 net_rule_info.py --no-unknown-attrs # Disable unknown attrs
"""

from cffi import FFI
import json
import sys
import ipaddress
from typing import Dict, List, Any, Optional

# Check Python version
if sys.version_info < (3, 8):
    raise RuntimeError("Python 3.8 or higher is required")

# For Python 3.12+, verify setuptools is available
if sys.version_info >= (3, 12):
    try:
        import setuptools  # @UnusedImport
    except ImportError:
        raise RuntimeError(
            "Python 3.12+ requires setuptools for CFFI.\n"
            "Install it with: pip install setuptools"
        )

# C library source code - RTM_GETRULE support
C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <errno.h>

// Verify we have minimum required kernel headers
#if !defined(NETLINK_ROUTE) || !defined(RTM_GETRULE)
#error "Kernel headers too old - need Linux 2.6+ with rtnetlink support"
#endif

// Response buffer structure
typedef struct {
    unsigned char* data;
    size_t length;
    size_t capacity;
    unsigned int seq;
} response_buffer_t;

// Rule entry information
typedef struct {
    unsigned char family;
    unsigned char dst_len;
    unsigned char src_len;
    unsigned char tos;
    unsigned char table;
    unsigned char action;
    unsigned int flags;
    
    unsigned char src_addr[16];     // Source prefix
    unsigned char dst_addr[16];     // Destination prefix
    
    int has_src_addr;
    int has_dst_addr;
    
    unsigned int priority;
    unsigned int fwmark;
    unsigned int fwmask;
    unsigned int table_id;
    
    int has_priority;
    int has_fwmark;
    int has_fwmask;
    int has_table_id;
    
    char iifname[IFNAMSIZ];
    char oifname[IFNAMSIZ];
    int has_iifname;
    int has_oifname;
    
    unsigned int goto_target;
    int has_goto_target;
    
    unsigned int suppress_prefixlen;
    int has_suppress_prefixlen;
    
    unsigned char protocol;
    int has_protocol;
    
    unsigned short unknown_fra_attrs[64];
    int unknown_fra_attrs_count;
} rule_entry_t;

// FRA_* Attribute definitions (for older kernels)
#ifndef FRA_DST
#define FRA_DST 1
#define FRA_SRC 2
#define FRA_IIFNAME 3
#define FRA_GOTO 4
#define FRA_PRIORITY 6
#define FRA_FWMARK 10
#define FRA_FLOW 11
#define FRA_TUN_ID 12
#define FRA_SUPPRESS_IFGROUP 13
#define FRA_SUPPRESS_PREFIXLEN 14
#define FRA_TABLE 15
#define FRA_FWMASK 16
#define FRA_OIFNAME 17
#define FRA_PAD 18
#define FRA_L3MDEV 19
#define FRA_UID_RANGE 20
#define FRA_PROTOCOL 21
#define FRA_IP_PROTO 22
#define FRA_SPORT_RANGE 23
#define FRA_DPORT_RANGE 24
#endif

// Rule actions
#ifndef FR_ACT_UNSPEC
#define FR_ACT_UNSPEC 0
#define FR_ACT_TO_TBL 1
#define FR_ACT_GOTO 2
#define FR_ACT_NOP 3
#define FR_ACT_BLACKHOLE 6
#define FR_ACT_UNREACHABLE 7
#define FR_ACT_PROHIBIT 8
#endif

// Create netlink socket for rule queries
int nl_create_socket(void) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_nl addr = {0};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

// Close netlink socket
void nl_close_socket(int sock) {
    if (sock >= 0) {
        close(sock);
    }
}

// Send RTM_GETRULE request
int nl_send_getrule(int sock, unsigned int* seq_out, int family) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req = {0};
    
    static unsigned int seq = 0;
    seq++;
    *seq_out = seq;
    
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETRULE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = seq;
    req.nlh.nlmsg_pid = getpid();
    
    req.rtm.rtm_family = family;  // AF_UNSPEC, AF_INET, or AF_INET6
    
    ssize_t sent = send(sock, &req, req.nlh.nlmsg_len, 0);
    if (sent < 0) {
        return -1;
    }
    
    return 0;
}

// Receive and buffer response
response_buffer_t* nl_receive_response(int sock, unsigned int expected_seq) {
    response_buffer_t* buf = malloc(sizeof(response_buffer_t));
    if (!buf) {
        return NULL;
    }
    
    buf->capacity = 65536;
    buf->data = malloc(buf->capacity);
    buf->length = 0;
    buf->seq = expected_seq;
    
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    unsigned char recv_buf[8192];
    int done = 0;
    
    while (!done) {
        ssize_t len = recv(sock, recv_buf, sizeof(recv_buf), 0);
        if (len < 0) {
            free(buf->data);
            free(buf);
            return NULL;
        }
        
        struct nlmsghdr* nh = (struct nlmsghdr*)recv_buf;
        
        while (NLMSG_OK(nh, len)) {
            if (nh->nlmsg_seq != expected_seq) {
                nh = NLMSG_NEXT(nh, len);
                continue;
            }
            
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            
            if (nh->nlmsg_type == NLMSG_ERROR) {
                free(buf->data);
                free(buf);
                return NULL;
            }
            
            if (nh->nlmsg_type == RTM_NEWRULE) {
                size_t msg_len = nh->nlmsg_len;
                
                if (buf->length + msg_len > buf->capacity) {
                    size_t new_capacity = buf->capacity * 2;
                    unsigned char* new_data = realloc(buf->data, new_capacity);
                    if (!new_data) {
                        free(buf->data);
                        free(buf);
                        return NULL;
                    }
                    buf->data = new_data;
                    buf->capacity = new_capacity;
                }
                
                memcpy(buf->data + buf->length, nh, msg_len);
                buf->length += msg_len;
            }
            
            nh = NLMSG_NEXT(nh, len);
        }
    }
    
    return buf;
}

// Free response buffer
void nl_free_response(response_buffer_t* buf) {
    if (buf) {
        if (buf->data) {
            free(buf->data);
        }
        free(buf);
    }
}

// Parse rules from response buffer
int nl_parse_rules(response_buffer_t* buf, rule_entry_t** rules, int* count) {
    if (!buf || !rules || !count) {
        return -1;
    }
    
    // Count rules first
    int num_rules = 0;
    size_t offset = 0;
    
    while (offset < buf->length) {
        struct nlmsghdr* nh = (struct nlmsghdr*)(buf->data + offset);
        if (nh->nlmsg_type == RTM_NEWRULE) {
            num_rules++;
        }
        offset += nh->nlmsg_len;
    }
    
    if (num_rules == 0) {
        *rules = NULL;
        *count = 0;
        return 0;
    }
    
    // Allocate array
    rule_entry_t* entries = calloc(num_rules, sizeof(rule_entry_t));
    if (!entries) {
        return -1;
    }
    
    // Parse rules
    offset = 0;
    int idx = 0;
    
    while (offset < buf->length && idx < num_rules) {
        struct nlmsghdr* nh = (struct nlmsghdr*)(buf->data + offset);
        
        if (nh->nlmsg_type == RTM_NEWRULE) {
            struct rtmsg* rtm = (struct rtmsg*)NLMSG_DATA(nh);
            rule_entry_t* entry = &entries[idx];
            
            entry->family = rtm->rtm_family;
            entry->dst_len = rtm->rtm_dst_len;
            entry->src_len = rtm->rtm_src_len;
            entry->tos = rtm->rtm_tos;
            entry->table = rtm->rtm_table;
            entry->action = rtm->rtm_type;
            entry->flags = rtm->rtm_flags;
            
            // Parse attributes
            int attrlen = RTM_PAYLOAD(nh);
            struct rtattr* attr = RTM_RTA(rtm);
            
            while (RTA_OK(attr, attrlen)) {
                unsigned short attr_type = attr->rta_type & ~NLA_F_NESTED;
                void* attr_data = RTA_DATA(attr);
                int attr_len = RTA_PAYLOAD(attr);
                
                switch (attr_type) {
                    case FRA_DST:
                        if (attr_len <= 16) {
                            memcpy(entry->dst_addr, attr_data, attr_len);
                            entry->has_dst_addr = 1;
                        }
                        break;
                        
                    case FRA_SRC:
                        if (attr_len <= 16) {
                            memcpy(entry->src_addr, attr_data, attr_len);
                            entry->has_src_addr = 1;
                        }
                        break;
                        
                    case FRA_IIFNAME:
                        if (attr_len < IFNAMSIZ) {
                            memcpy(entry->iifname, attr_data, attr_len);
                            entry->iifname[attr_len] = '\0';
                            entry->has_iifname = 1;
                        }
                        break;
                        
                    case FRA_OIFNAME:
                        if (attr_len < IFNAMSIZ) {
                            memcpy(entry->oifname, attr_data, attr_len);
                            entry->oifname[attr_len] = '\0';
                            entry->has_oifname = 1;
                        }
                        break;
                        
                    case FRA_PRIORITY:
                        if (attr_len == 4) {
                            entry->priority = *(unsigned int*)attr_data;
                            entry->has_priority = 1;
                        }
                        break;
                        
                    case FRA_FWMARK:
                        if (attr_len == 4) {
                            entry->fwmark = *(unsigned int*)attr_data;
                            entry->has_fwmark = 1;
                        }
                        break;
                        
                    case FRA_FWMASK:
                        if (attr_len == 4) {
                            entry->fwmask = *(unsigned int*)attr_data;
                            entry->has_fwmask = 1;
                        }
                        break;
                        
                    case FRA_TABLE:
                        if (attr_len == 4) {
                            entry->table_id = *(unsigned int*)attr_data;
                            entry->has_table_id = 1;
                        }
                        break;
                        
                    case FRA_GOTO:
                        if (attr_len == 4) {
                            entry->goto_target = *(unsigned int*)attr_data;
                            entry->has_goto_target = 1;
                        }
                        break;
                        
                    case FRA_SUPPRESS_PREFIXLEN:
                        if (attr_len == 4) {
                            entry->suppress_prefixlen = *(unsigned int*)attr_data;
                            entry->has_suppress_prefixlen = 1;
                        }
                        break;
                        
                    case FRA_PROTOCOL:
                        if (attr_len == 1) {
                            entry->protocol = *(unsigned char*)attr_data;
                            entry->has_protocol = 1;
                        }
                        break;
                        
                    default:
                        // Track unknown attributes
                        if (entry->unknown_fra_attrs_count < 64) {
                            entry->unknown_fra_attrs[entry->unknown_fra_attrs_count++] = attr_type;
                        }
                        break;
                }
                
                attr = RTA_NEXT(attr, attrlen);
            }
            
            idx++;
        }
        
        offset += nh->nlmsg_len;
    }
    
    *rules = entries;
    *count = num_rules;
    return 0;
}

// Free parsed rules
void nl_free_rules(rule_entry_t* rules) {
    if (rules) {
        free(rules);
    }
}

// Get AF_INET constant
int nl_get_af_inet(void) { return AF_INET; }
int nl_get_af_inet6(void) { return AF_INET6; }
"""

# Define FFI interface
ffi = FFI()
ffi.cdef("""
typedef struct {
    unsigned char* data;
    size_t length;
    size_t capacity;
    unsigned int seq;
} response_buffer_t;

typedef struct {
    unsigned char family;
    unsigned char dst_len;
    unsigned char src_len;
    unsigned char tos;
    unsigned char table;
    unsigned char action;
    unsigned int flags;
    
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    
    int has_src_addr;
    int has_dst_addr;
    
    unsigned int priority;
    unsigned int fwmark;
    unsigned int fwmask;
    unsigned int table_id;
    
    int has_priority;
    int has_fwmark;
    int has_fwmask;
    int has_table_id;
    
    char iifname[16];
    char oifname[16];
    int has_iifname;
    int has_oifname;
    
    unsigned int goto_target;
    int has_goto_target;
    
    unsigned int suppress_prefixlen;
    int has_suppress_prefixlen;
    
    unsigned char protocol;
    int has_protocol;
    
    unsigned short unknown_fra_attrs[64];
    int unknown_fra_attrs_count;
} rule_entry_t;

int nl_create_socket(void);
void nl_close_socket(int sock);
int nl_send_getrule(int sock, unsigned int* seq_out, int family);
response_buffer_t* nl_receive_response(int sock, unsigned int expected_seq);
void nl_free_response(response_buffer_t* buf);
int nl_parse_rules(response_buffer_t* buf, rule_entry_t** rules, int* count);
void nl_free_rules(rule_entry_t* rules);
int nl_get_af_inet(void);
int nl_get_af_inet6(void);
""")

# Compile C code
try:
    lib = ffi.verify(C_SOURCE, modulename="rulesnap_lib_v1")
except Exception as e:
    print(f"Error compiling C library: {e}", file=sys.stderr)
    print("This might be a CFFI caching issue. Try removing the __pycache__ directory.", file=sys.stderr)
    try:
        import setuptools  # @UnusedImport
    except ImportError:
        raise RuntimeError(
            "Python 3.12+ requires setuptools.\n"
            "Install it with: pip install setuptools"
        ) from e
    raise

AF_INET = lib.nl_get_af_inet()
AF_INET6 = lib.nl_get_af_inet6()

# Rule attribute name mapping
FRA_ATTR_NAMES = {
    0: 'FRA_UNSPEC', 1: 'FRA_DST', 2: 'FRA_SRC', 3: 'FRA_IIFNAME',
    4: 'FRA_GOTO', 6: 'FRA_PRIORITY', 10: 'FRA_FWMARK', 11: 'FRA_FLOW',
    12: 'FRA_TUN_ID', 13: 'FRA_SUPPRESS_IFGROUP', 14: 'FRA_SUPPRESS_PREFIXLEN',
    15: 'FRA_TABLE', 16: 'FRA_FWMASK', 17: 'FRA_OIFNAME', 18: 'FRA_PAD',
    19: 'FRA_L3MDEV', 20: 'FRA_UID_RANGE', 21: 'FRA_PROTOCOL',
    22: 'FRA_IP_PROTO', 23: 'FRA_SPORT_RANGE', 24: 'FRA_DPORT_RANGE',
}

# Rule action names
RULE_ACTION_NAMES = {
    0: 'UNSPEC', 1: 'TO_TBL', 2: 'GOTO', 3: 'NOP',
    6: 'BLACKHOLE', 7: 'UNREACHABLE', 8: 'PROHIBIT',
}

# Rule table names (same as routing tables)
RULE_TABLE_NAMES = {
    0: 'UNSPEC', 252: 'COMPAT', 253: 'DEFAULT', 254: 'MAIN', 255: 'LOCAL',
}

# Rule protocol names (who installed the rule)
RULE_PROTOCOL_NAMES = {
    0: 'UNSPEC', 1: 'REDIRECT', 2: 'KERNEL', 3: 'BOOT', 4: 'STATIC',
    8: 'GATED', 9: 'RA', 10: 'MRT', 11: 'ZEBRA', 12: 'BIRD',
    13: 'DNROUTED', 14: 'XORP', 15: 'NTK', 16: 'DHCP', 17: 'MROUTED',
    42: 'BABEL', 186: 'BGP', 187: 'ISIS', 188: 'OSPF', 189: 'RIP', 192: 'EIGRP',
}


def decode_unknown_attrs(attr_list: List[int]) -> List[Dict[str, Any]]:
    """Decode unknown attribute numbers into human-readable information"""
    decoded = []
    for attr_num in attr_list:
        is_nested = bool(attr_num & 0x8000)
        base_num = attr_num & 0x7FFF
        
        info = {
            'number': attr_num,
            'base_number': base_num,
            'nested': is_nested,
        }
        
        if base_num in FRA_ATTR_NAMES:
            info['name'] = FRA_ATTR_NAMES[base_num]
            if is_nested:
                info['name'] += ' (nested)'
        else:
            info['name'] = f'FRA_{base_num}'
        
        decoded.append(info)
    
    return decoded


class RoutingRuleQuery:
    """
    Query routing rule (policy routing) information using RTNETLINK protocol via C library.
    Supports IPv4 and IPv6 rules.
    """
    
    def __init__(self, capture_unknown_attrs: bool = True):
        self.sock = -1
        self.capture_unknown_attrs = capture_unknown_attrs
    
    def __enter__(self):
        """Context manager entry - create socket"""
        self.sock = lib.nl_create_socket()
        if self.sock < 0:
            raise RuntimeError("Failed to create netlink socket")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb): #@UnusedVariable
        """Context manager exit - close socket"""
        if self.sock >= 0:
            lib.nl_close_socket(self.sock)
            self.sock = -1
        return False
    
    def get_rules(self, family: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Query routing rule entries.
        
        Args:
            family: Optional filter - 'ipv4', 'ipv6', or None for all
        
        Returns:
            List of rule entries with full metadata
        """
        family_map = {
            'ipv4': AF_INET,
            'ipv6': AF_INET6,
            None: 0,  # AF_UNSPEC
        }
        
        if family not in family_map:
            raise ValueError(f"Invalid family: {family}. Use 'ipv4', 'ipv6', or None")
        
        af_family = family_map[family]
        seq = ffi.new("unsigned int*")
        
        if lib.nl_send_getrule(self.sock, seq, af_family) < 0:
            raise RuntimeError("Failed to send RTM_GETRULE request")
        
        response = lib.nl_receive_response(self.sock, seq[0])
        if not response:
            raise RuntimeError("Failed to receive response")
        
        try:
            rules_ptr = ffi.new("rule_entry_t**")
            count_ptr = ffi.new("int*")
            
            result = lib.nl_parse_rules(response, rules_ptr, count_ptr)
            if result < 0:
                raise RuntimeError("Failed to parse rule entries")
            
            rules_array = rules_ptr[0]
            num_rules = count_ptr[0]
            
            rules = []
            for i in range(num_rules):
                entry = rules_array[i]
                
                rule_info = {
                    'family': 'ipv4' if entry.family == AF_INET else 'ipv6' if entry.family == AF_INET6 else entry.family,
                    'action': RULE_ACTION_NAMES.get(entry.action, f'ACTION_{entry.action}'),
                    'table': RULE_TABLE_NAMES.get(entry.table, entry.table),
                    'dst_len': entry.dst_len,
                    'src_len': entry.src_len,
                    'tos': entry.tos,
                    'flags': entry.flags,
                }
                
                # Priority
                if entry.has_priority:
                    rule_info['priority'] = entry.priority
                
                # Destination network
                if entry.has_dst_addr:
                    if entry.family == AF_INET:
                        dst_bytes = bytes(entry.dst_addr[0:4])
                        dst_ip = ipaddress.IPv4Address(dst_bytes)
                        rule_info['dst'] = f"{dst_ip}/{entry.dst_len}"
                    elif entry.family == AF_INET6:
                        dst_bytes = bytes(entry.dst_addr[0:16])
                        dst_ip = ipaddress.IPv6Address(dst_bytes)
                        rule_info['dst'] = f"{dst_ip}/{entry.dst_len}"
                
                # Source network
                if entry.has_src_addr:
                    if entry.family == AF_INET:
                        src_bytes = bytes(entry.src_addr[0:4])
                        src_ip = ipaddress.IPv4Address(src_bytes)
                        rule_info['src'] = f"{src_ip}/{entry.src_len}"
                    elif entry.family == AF_INET6:
                        src_bytes = bytes(entry.src_addr[0:16])
                        src_ip = ipaddress.IPv6Address(src_bytes)
                        rule_info['src'] = f"{src_ip}/{entry.src_len}"
                
                # Input interface
                if entry.has_iifname:
                    iifname = ffi.string(entry.iifname).decode('utf-8')
                    if iifname:
                        rule_info['iif'] = iifname
                
                # Output interface
                if entry.has_oifname:
                    oifname = ffi.string(entry.oifname).decode('utf-8')
                    if oifname:
                        rule_info['oif'] = oifname
                
                # Firewall mark
                if entry.has_fwmark:
                    rule_info['fwmark'] = entry.fwmark
                    if entry.has_fwmask:
                        rule_info['fwmask'] = entry.fwmask
                
                # Table ID (for tables > 255)
                if entry.has_table_id:
                    rule_info['table_id'] = entry.table_id
                    rule_info['table'] = RULE_TABLE_NAMES.get(entry.table_id, entry.table_id)
                
                # Goto target
                if entry.has_goto_target:
                    rule_info['goto'] = entry.goto_target
                
                # Suppress prefixlen
                if entry.has_suppress_prefixlen:
                    # Skip sentinel value (0xFFFFFFFF = -1 for unsigned int)
                    if entry.suppress_prefixlen != 4294967295:
                        rule_info['suppress_prefixlen'] = entry.suppress_prefixlen
                
                # Protocol (who installed the rule)
                if entry.has_protocol:
                    rule_info['protocol'] = RULE_PROTOCOL_NAMES.get(entry.protocol, f'PROTO_{entry.protocol}')
                
                # Unknown attributes
                if self.capture_unknown_attrs and entry.unknown_fra_attrs_count > 0:
                    unknown_list = []
                    for j in range(entry.unknown_fra_attrs_count):
                        unknown_list.append(entry.unknown_fra_attrs[j])
                    rule_info['unknown_fra_attrs'] = unknown_list
                    rule_info['unknown_fra_attrs_decoded'] = decode_unknown_attrs(unknown_list)
                
                rules.append(rule_info)
            
            lib.nl_free_rules(rules_array)
            return rules
        
        finally:
            lib.nl_free_response(response)


# Example usage
def main():
        """Main entry point for the command."""
        import argparse
    
        parser = argparse.ArgumentParser(description='Routing Rule Query Tool')
        parser.add_argument('--no-unknown-attrs', action='store_true',
                            help='Disable unknown attribute tracking')
        parser.add_argument('--summary', action='store_true',
                            help='Show human-readable summary')
        parser.add_argument('--ipv4', action='store_true',
                            help='Show only IPv4 rules')
        parser.add_argument('--ipv6', action='store_true',
                            help='Show only IPv6 rules')
        args = parser.parse_args()
    
        try:
            print("=" * 70)
            print("ROUTING RULE QUERY")
            print("=" * 70)
        
            with RoutingRuleQuery(capture_unknown_attrs=not args.no_unknown_attrs) as query:
                # Determine family filter
                family = None
                if args.ipv4:
                    family = 'ipv4'
                elif args.ipv6:
                    family = 'ipv6'
            
                rules = query.get_rules(family=family)
            
                if args.summary:
                    # Human-readable summary
                    print(f"\nTotal rules: {len(rules)}")
                    print(f"\nRule entries:\n")
                
                    # Sort by priority
                    sorted_rules = sorted(rules, key=lambda r: r.get('priority', 0))
                
                    for rule in sorted_rules:
                        parts = []
                    
                        # Priority
                        if 'priority' in rule:
                            parts.append(f"{rule['priority']}:")
                    
                        # From
                        if 'src' in rule:
                            parts.append(f"from {rule['src']}")
                        else:
                            parts.append("from all")
                    
                        # To
                        if 'dst' in rule:
                            parts.append(f"to {rule['dst']}")
                    
                        # TOS
                        if rule['tos'] != 0:
                            parts.append(f"tos {rule['tos']}")
                    
                        # Fwmark
                        if 'fwmark' in rule:
                            if 'fwmask' in rule:
                                parts.append(f"fwmark {rule['fwmark']}/{rule['fwmask']}")
                            else:
                                parts.append(f"fwmark {rule['fwmark']}")
                    
                        # Input interface
                        if 'iif' in rule:
                            parts.append(f"iif {rule['iif']}")
                    
                        # Output interface
                        if 'oif' in rule:
                            parts.append(f"oif {rule['oif']}")
                    
                        # Suppress prefixlen
                        if 'suppress_prefixlen' in rule:
                            suppress = rule['suppress_prefixlen']
                            parts.append(f"suppress_prefixlen {suppress}")
                    
                        # Protocol
                        if 'protocol' in rule:
                            parts.append(f"[{rule['protocol']}]")
                    
                        # Action
                        action = rule['action']
                        if action == 'TO_TBL':
                            parts.append(f"lookup {rule['table']}")
                        elif action == 'GOTO':
                            parts.append(f"goto {rule.get('goto', '?')}")
                        else:
                            parts.append(action.lower())
                    
                        print("  " + " ".join(parts))
                else:
                    # Full JSON output
                    print(json.dumps(rules, indent=2))
                
        except PermissionError:
            print("Error: This tool requires root privileges (sudo)", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == '__main__':
    main()
