#!/usr/bin/env python3
"""
RTNetlink Routing Table Query with C Library via CFFI
Complete routing table inspection including:
- IPv4 and IPv6 routes
- Main, local, and custom routing tables
- Gateway, destination, source addresses
- Route metrics, preferences, and protocols
- Multipath routes (ECMP)
- Route types and scopes

Route Types:
- UNICAST: Normal route
- LOCAL: Local interface address
- BROADCAST: Broadcast address
- MULTICAST: Multicast route
- UNREACHABLE: Destination unreachable
- PROHIBIT: Administratively prohibited
- BLACKHOLE: Silent discard

Requirements:
    - Python 3.8+
    - cffi>=1.0.0
    - setuptools (required for Python 3.12+)

Install:
    pip install cffi setuptools

Usage:
    sudo python3 routesnapshotter.py                    # Full JSON output
    sudo python3 routesnapshotter.py --summary          # Human-readable summary
    sudo python3 routesnapshotter.py --ipv4             # IPv4 routes only
    sudo python3 routesnapshotter.py --ipv6             # IPv6 routes only
    sudo python3 routesnapshotter.py --table main       # Specific table
    sudo python3 routesnapshotter.py --no-unknown-attrs # Disable unknown attrs
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
        import setuptools # @UnusedImport
    except ImportError:
        raise RuntimeError(
            "Python 3.12+ requires setuptools for CFFI.\n"
            "Install it with: pip install setuptools"
        )

# C library source code - RTM_GETROUTE support
C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <errno.h>

// Verify we have minimum required kernel headers
#if !defined(NETLINK_ROUTE) || !defined(RTM_GETROUTE)
#error "Kernel headers too old - need Linux 2.6+ with rtnetlink support"
#endif

// Response buffer structure
typedef struct {
    unsigned char* data;
    size_t length;
    size_t capacity;
    unsigned int seq;
} response_buffer_t;

// Route cache information
typedef struct {
    unsigned int clntref;
    unsigned int last_use;
    unsigned int expires;
    unsigned int error;
    unsigned int used;
    unsigned int id;
    unsigned int ts;
    unsigned int ts_age;
    int has_clntref;
    int has_last_use;
    int has_expires;
    int has_error;
    int has_used;
    int has_id;
    int has_ts;
    int has_ts_age;
} route_cacheinfo_t;

// Multipath nexthop structure
typedef struct {
    unsigned char gateway[16];  // IPv4 or IPv6 gateway
    int ifindex;
    unsigned char weight;
    unsigned char flags;
    int has_gateway;
    int gateway_len;
} route_nexthop_t;

// Route entry information
typedef struct {
    unsigned char family;
    unsigned char dst_len;
    unsigned char src_len;
    unsigned char tos;
    unsigned char table;
    unsigned char protocol;
    unsigned char scope;
    unsigned char type;
    unsigned int flags;
    
    unsigned char dst_addr[16];     // Destination prefix
    unsigned char src_addr[16];     // Source prefix (policy routing)
    unsigned char gateway[16];      // Next hop gateway
    unsigned char prefsrc[16];      // Preferred source
    
    int ifindex;                    // Output interface
    unsigned int priority;          // Route metric/preference
    unsigned int table_id;          // Routing table ID
    
    int has_dst_addr;
    int has_src_addr;
    int has_gateway;
    int has_prefsrc;
    int has_ifindex;
    int has_priority;
    int has_table_id;
    
    route_cacheinfo_t cacheinfo;
    
    // Multipath support
    route_nexthop_t nexthops[32];
    int nexthop_count;
    
    unsigned short unknown_rta_attrs[64];
    int unknown_rta_attrs_count;
} route_entry_t;

// RTA_* Attribute definitions (for older kernels)
#ifndef RTA_DST
#define RTA_DST 1
#define RTA_SRC 2
#define RTA_IIF 3
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PRIORITY 6
#define RTA_PREFSRC 7
#define RTA_METRICS 8
#define RTA_MULTIPATH 9
#define RTA_PROTOINFO 10
#define RTA_FLOW 11
#define RTA_CACHEINFO 12
#define RTA_SESSION 13
#define RTA_MP_ALGO 14
#define RTA_TABLE 15
#define RTA_MARK 16
#define RTA_MFC_STATS 17
#define RTA_VIA 18
#define RTA_NEWDST 19
#define RTA_PREF 20
#define RTA_ENCAP_TYPE 21
#define RTA_ENCAP 22
#define RTA_EXPIRES 23
#define RTA_PAD 24
#define RTA_UID 25
#define RTA_TTL_PROPAGATE 26
#define RTA_IP_PROTO 27
#define RTA_SPORT 28
#define RTA_DPORT 29
#define RTA_NH_ID 30
#endif

// Route types
#ifndef RTN_UNSPEC
#define RTN_UNSPEC 0
#define RTN_UNICAST 1
#define RTN_LOCAL 2
#define RTN_BROADCAST 3
#define RTN_ANYCAST 4
#define RTN_MULTICAST 5
#define RTN_BLACKHOLE 6
#define RTN_UNREACHABLE 7
#define RTN_PROHIBIT 8
#define RTN_THROW 9
#define RTN_NAT 10
#define RTN_XRESOLVE 11
#endif

// Route protocols
#ifndef RTPROT_UNSPEC
#define RTPROT_UNSPEC 0
#define RTPROT_REDIRECT 1
#define RTPROT_KERNEL 2
#define RTPROT_BOOT 3
#define RTPROT_STATIC 4
#define RTPROT_GATED 8
#define RTPROT_RA 9
#define RTPROT_MRT 10
#define RTPROT_ZEBRA 11
#define RTPROT_BIRD 12
#define RTPROT_DNROUTED 13
#define RTPROT_XORP 14
#define RTPROT_NTK 15
#define RTPROT_DHCP 16
#define RTPROT_MROUTED 17
#define RTPROT_BABEL 42
#define RTPROT_BGP 186
#define RTPROT_ISIS 187
#define RTPROT_OSPF 188
#define RTPROT_RIP 189
#define RTPROT_EIGRP 192
#endif

// Route scopes
#ifndef RT_SCOPE_UNIVERSE
#define RT_SCOPE_UNIVERSE 0
#define RT_SCOPE_SITE 200
#define RT_SCOPE_LINK 253
#define RT_SCOPE_HOST 254
#define RT_SCOPE_NOWHERE 255
#endif

// Route tables
#ifndef RT_TABLE_UNSPEC
#define RT_TABLE_UNSPEC 0
#define RT_TABLE_COMPAT 252
#define RT_TABLE_DEFAULT 253
#define RT_TABLE_MAIN 254
#define RT_TABLE_LOCAL 255
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

// Send RTM_GETROUTE request
int nl_send_getroute(int sock, unsigned int* seq_out, int family) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req;
    
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = nl_generate_seq();
    req.nlh.nlmsg_pid = 0;
    
    req.rtm.rtm_family = family;  // AF_UNSPEC, AF_INET, or AF_INET6
    req.rtm.rtm_table = RT_TABLE_UNSPEC;  // Get all tables
    
    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
        return -1;
    }
    
    if (seq_out) {
        *seq_out = req.nlh.nlmsg_seq;
    }
    
    return 0;
}

// Receive netlink response
response_buffer_t* nl_receive_response(int sock, unsigned int expected_seq) {
    response_buffer_t* buf = calloc(1, sizeof(response_buffer_t));
    if (!buf) return NULL;
    
    buf->capacity = 65536;
    buf->data = malloc(buf->capacity);
    buf->length = 0;
    buf->seq = expected_seq;
    
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    while (1) {
        unsigned char temp_buf[8192];
        ssize_t len = recv(sock, temp_buf, sizeof(temp_buf), 0);
        
        if (len < 0) {
            if (errno == EINTR) continue;
            free(buf->data);
            free(buf);
            return NULL;
        }
        
        if (len == 0) break;
        
        if (buf->length + len > buf->capacity) {
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
        
        memcpy(buf->data + buf->length, temp_buf, len);
        buf->length += len;
        
        struct nlmsghdr* nlh = (struct nlmsghdr*)temp_buf;
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
            break;
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

void nl_free_routes(route_entry_t* routes) {
    if (routes) free(routes);
}

int nl_get_af_inet(void) { return AF_INET; }
int nl_get_af_inet6(void) { return AF_INET6; }

// Helper function to get interface name from index using netlink
int nl_get_ifname(unsigned int ifindex, char* ifname, size_t len) {
    if (!ifname || len < 16 || ifindex == 0) return -1;
    
    // Try using if_indextoname first
    char temp[16];
    if (if_indextoname(ifindex, temp) != NULL) {
        strncpy(ifname, temp, len - 1);
        ifname[len - 1] = '\0';
        return 0;
    }
    
    // Fallback: set empty and return error
    ifname[0] = '\0';
    return -1;
}

static void track_unknown_attr(unsigned short* attr_array, int* count, int max_count,
                               unsigned short attr, const unsigned short* known, int known_count) {
    for (int i = 0; i < known_count; i++) {
        if (attr == known[i]) return;
    }
    
    for (int i = 0; i < *count; i++) {
        if (attr_array[i] == attr) return;
    }
    
    if (*count < max_count) {
        attr_array[(*count)++] = attr;
    }
}

int nl_parse_routes(response_buffer_t* buf, route_entry_t** routes, int* count) {
    if (!buf || !routes || !count) return -1;
    
    *count = 0;
    *routes = NULL;
    
    if (buf->length == 0) {
        return -1;
    }
    
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf->data;
    int max_count = 0;
    size_t remaining = buf->length;
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        if (nlh->nlmsg_type == RTM_NEWROUTE) {
            max_count++;
        }
    }
    
    if (max_count == 0) return 0;
    
    *routes = calloc(max_count, sizeof(route_entry_t));
    if (!*routes) return -1;
    
    nlh = (struct nlmsghdr*)buf->data;
    remaining = buf->length;
    
    static const unsigned short known_rta_attrs[] = {
        RTA_DST, RTA_SRC, RTA_IIF, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY,
        RTA_PREFSRC, RTA_METRICS, RTA_MULTIPATH, RTA_PROTOINFO, RTA_FLOW,
        RTA_CACHEINFO, RTA_SESSION, RTA_MP_ALGO, RTA_TABLE, RTA_MARK,
        RTA_MFC_STATS, RTA_VIA, RTA_NEWDST, RTA_PREF, RTA_ENCAP_TYPE,
        RTA_ENCAP, RTA_EXPIRES, RTA_PAD, RTA_UID, RTA_TTL_PROPAGATE,
        RTA_IP_PROTO, RTA_SPORT, RTA_DPORT, RTA_NH_ID
    };
    static const int known_rta_count = sizeof(known_rta_attrs) / sizeof(known_rta_attrs[0]);
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type != RTM_NEWROUTE) continue;
        
        struct rtmsg* rtm = NLMSG_DATA(nlh);
        route_entry_t* entry = &(*routes)[*count];
        
        entry->family = rtm->rtm_family;
        entry->dst_len = rtm->rtm_dst_len;
        entry->src_len = rtm->rtm_src_len;
        entry->tos = rtm->rtm_tos;
        entry->table = rtm->rtm_table;
        entry->protocol = rtm->rtm_protocol;
        entry->scope = rtm->rtm_scope;
        entry->type = rtm->rtm_type;
        entry->flags = rtm->rtm_flags;
        
        entry->has_dst_addr = 0;
        entry->has_src_addr = 0;
        entry->has_gateway = 0;
        entry->has_prefsrc = 0;
        entry->has_ifindex = 0;
        entry->has_priority = 0;
        entry->has_table_id = 0;
        entry->nexthop_count = 0;
        entry->unknown_rta_attrs_count = 0;
        memset(&entry->cacheinfo, 0, sizeof(route_cacheinfo_t));
        
        struct rtattr* rta = (struct rtattr*)((char*)rtm + NLMSG_ALIGN(sizeof(struct rtmsg)));
        int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            track_unknown_attr(entry->unknown_rta_attrs,
                              &entry->unknown_rta_attrs_count,
                              64, rta->rta_type, known_rta_attrs, known_rta_count);
            
            switch (rta->rta_type) {
                case RTA_DST:
                    if (RTA_PAYLOAD(rta) > 0 && RTA_PAYLOAD(rta) <= 16) {
                        memcpy(entry->dst_addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        entry->has_dst_addr = 1;
                    }
                    break;
                    
                case RTA_SRC:
                    if (RTA_PAYLOAD(rta) > 0 && RTA_PAYLOAD(rta) <= 16) {
                        memcpy(entry->src_addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        entry->has_src_addr = 1;
                    }
                    break;
                    
                case RTA_GATEWAY:
                    if (RTA_PAYLOAD(rta) > 0 && RTA_PAYLOAD(rta) <= 16) {
                        memcpy(entry->gateway, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        entry->has_gateway = 1;
                    }
                    break;
                    
                case RTA_PREFSRC:
                    if (RTA_PAYLOAD(rta) > 0 && RTA_PAYLOAD(rta) <= 16) {
                        memcpy(entry->prefsrc, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        entry->has_prefsrc = 1;
                    }
                    break;
                    
                case RTA_OIF:
                    if (RTA_PAYLOAD(rta) >= sizeof(int)) {
                        entry->ifindex = *(int*)RTA_DATA(rta);
                        entry->has_ifindex = 1;
                    }
                    break;
                    
                case RTA_PRIORITY:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        entry->priority = *(unsigned int*)RTA_DATA(rta);
                        entry->has_priority = 1;
                    }
                    break;
                    
                case RTA_TABLE:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        entry->table_id = *(unsigned int*)RTA_DATA(rta);
                        entry->has_table_id = 1;
                    }
                    break;
                    
                case RTA_CACHEINFO: {
                    if (RTA_PAYLOAD(rta) >= 32) {
                        unsigned int* cache = (unsigned int*)RTA_DATA(rta);
                        entry->cacheinfo.clntref = cache[0];
                        entry->cacheinfo.last_use = cache[1];
                        entry->cacheinfo.expires = cache[2];
                        entry->cacheinfo.error = cache[3];
                        entry->cacheinfo.used = cache[4];
                        entry->cacheinfo.id = cache[5];
                        entry->cacheinfo.ts = cache[6];
                        entry->cacheinfo.ts_age = cache[7];
                        entry->cacheinfo.has_clntref = 1;
                        entry->cacheinfo.has_last_use = 1;
                        entry->cacheinfo.has_expires = 1;
                        entry->cacheinfo.has_error = 1;
                        entry->cacheinfo.has_used = 1;
                        entry->cacheinfo.has_id = 1;
                        entry->cacheinfo.has_ts = 1;
                        entry->cacheinfo.has_ts_age = 1;
                    }
                    break;
                }
                    
                case RTA_MULTIPATH: {
                    struct rtnexthop* nh = RTA_DATA(rta);
                    int nh_len = RTA_PAYLOAD(rta);
                    
                    while (RTNH_OK(nh, nh_len) && entry->nexthop_count < 32) {
                        route_nexthop_t* nexthop = &entry->nexthops[entry->nexthop_count];
                        memset(nexthop, 0, sizeof(route_nexthop_t));
                        
                        nexthop->ifindex = nh->rtnh_ifindex;
                        nexthop->weight = nh->rtnh_hops + 1;
                        nexthop->flags = nh->rtnh_flags;
                        nexthop->has_gateway = 0;
                        
                        int attrlen = nh->rtnh_len - sizeof(*nh);
                        if (attrlen > 0) {
                            struct rtattr* nh_rta = RTNH_DATA(nh);
                            
                            for (; RTA_OK(nh_rta, attrlen); nh_rta = RTA_NEXT(nh_rta, attrlen)) {
                                if (nh_rta->rta_type == RTA_GATEWAY) {
                                    int gw_len = RTA_PAYLOAD(nh_rta);
                                    if (gw_len > 0 && gw_len <= 16) {
                                        memcpy(nexthop->gateway, RTA_DATA(nh_rta), gw_len);
                                        nexthop->gateway_len = gw_len;
                                        nexthop->has_gateway = 1;
                                    }
                                }
                            }
                        }
                        
                        entry->nexthop_count++;
                        nh = RTNH_NEXT(nh);
                    }
                    break;
                }
            }
        }
        
        (*count)++;
    }
    
    return 0;
}
"""

ffi = FFI()

# Define C function signatures
ffi.cdef("""
typedef struct {
    unsigned char* data;
    size_t length;
    size_t capacity;
    unsigned int seq;
} response_buffer_t;

typedef struct {
    unsigned int clntref;
    unsigned int last_use;
    unsigned int expires;
    unsigned int error;
    unsigned int used;
    unsigned int id;
    unsigned int ts;
    unsigned int ts_age;
    int has_clntref;
    int has_last_use;
    int has_expires;
    int has_error;
    int has_used;
    int has_id;
    int has_ts;
    int has_ts_age;
} route_cacheinfo_t;

typedef struct {
    unsigned char gateway[16];
    int ifindex;
    unsigned char weight;
    unsigned char flags;
    int has_gateway;
    int gateway_len;
} route_nexthop_t;

typedef struct {
    unsigned char family;
    unsigned char dst_len;
    unsigned char src_len;
    unsigned char tos;
    unsigned char table;
    unsigned char protocol;
    unsigned char scope;
    unsigned char type;
    unsigned int flags;
    
    unsigned char dst_addr[16];
    unsigned char src_addr[16];
    unsigned char gateway[16];
    unsigned char prefsrc[16];
    
    int ifindex;
    unsigned int priority;
    unsigned int table_id;
    
    int has_dst_addr;
    int has_src_addr;
    int has_gateway;
    int has_prefsrc;
    int has_ifindex;
    int has_priority;
    int has_table_id;
    
    route_cacheinfo_t cacheinfo;
    
    route_nexthop_t nexthops[32];
    int nexthop_count;
    
    unsigned short unknown_rta_attrs[64];
    int unknown_rta_attrs_count;
} route_entry_t;

int nl_create_socket(void);
void nl_close_socket(int sock);
int nl_send_getroute(int sock, unsigned int* seq_out, int family);
response_buffer_t* nl_receive_response(int sock, unsigned int expected_seq);
void nl_free_response(response_buffer_t* buf);
int nl_parse_routes(response_buffer_t* buf, route_entry_t** routes, int* count);
void nl_free_routes(route_entry_t* routes);
int nl_get_af_inet(void);
int nl_get_af_inet6(void);
int nl_get_ifname(unsigned int ifindex, char* ifname, size_t len);
""")

# Compile C code
try:
    lib = ffi.verify(C_SOURCE, modulename="routesnap_lib_v2")
except Exception as e:
    print(f"Error compiling C library: {e}", file=sys.stderr)
    print("This might be a CFFI caching issue. Try removing the __pycache__ directory.", file=sys.stderr)
    try:
        import setuptools # @UnusedImport
    except ImportError:
        raise RuntimeError(
            "Python 3.12+ requires setuptools.\n"
            "Install it with: pip install setuptools"
        ) from e
    raise

AF_INET = lib.nl_get_af_inet()
AF_INET6 = lib.nl_get_af_inet6()

# Route attribute name mapping
RTA_ATTR_NAMES = {
    0: 'RTA_UNSPEC', 1: 'RTA_DST', 2: 'RTA_SRC', 3: 'RTA_IIF',
    4: 'RTA_OIF', 5: 'RTA_GATEWAY', 6: 'RTA_PRIORITY', 7: 'RTA_PREFSRC',
    8: 'RTA_METRICS', 9: 'RTA_MULTIPATH', 10: 'RTA_PROTOINFO', 11: 'RTA_FLOW',
    12: 'RTA_CACHEINFO', 13: 'RTA_SESSION', 14: 'RTA_MP_ALGO', 15: 'RTA_TABLE',
    16: 'RTA_MARK', 17: 'RTA_MFC_STATS', 18: 'RTA_VIA', 19: 'RTA_NEWDST',
    20: 'RTA_PREF', 21: 'RTA_ENCAP_TYPE', 22: 'RTA_ENCAP', 23: 'RTA_EXPIRES',
    24: 'RTA_PAD', 25: 'RTA_UID', 26: 'RTA_TTL_PROPAGATE', 27: 'RTA_IP_PROTO',
    28: 'RTA_SPORT', 29: 'RTA_DPORT', 30: 'RTA_NH_ID',
}

# Route type names
ROUTE_TYPE_NAMES = {
    0: 'UNSPEC', 1: 'UNICAST', 2: 'LOCAL', 3: 'BROADCAST',
    4: 'ANYCAST', 5: 'MULTICAST', 6: 'BLACKHOLE', 7: 'UNREACHABLE',
    8: 'PROHIBIT', 9: 'THROW', 10: 'NAT', 11: 'XRESOLVE',
}

# Route protocol names
ROUTE_PROTOCOL_NAMES = {
    0: 'UNSPEC', 1: 'REDIRECT', 2: 'KERNEL', 3: 'BOOT', 4: 'STATIC',
    8: 'GATED', 9: 'RA', 10: 'MRT', 11: 'ZEBRA', 12: 'BIRD',
    13: 'DNROUTED', 14: 'XORP', 15: 'NTK', 16: 'DHCP', 17: 'MROUTED',
    42: 'BABEL', 186: 'BGP', 187: 'ISIS', 188: 'OSPF', 189: 'RIP', 192: 'EIGRP',
}

# Route scope names
ROUTE_SCOPE_NAMES = {
    0: 'UNIVERSE', 200: 'SITE', 253: 'LINK', 254: 'HOST', 255: 'NOWHERE',
}

# Route table names
ROUTE_TABLE_NAMES = {
    0: 'UNSPEC', 252: 'COMPAT', 253: 'DEFAULT', 254: 'MAIN', 255: 'LOCAL',
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
        
        if base_num in RTA_ATTR_NAMES:
            info['name'] = RTA_ATTR_NAMES[base_num]
            if is_nested:
                info['name'] += ' (nested)'
        else:
            info['name'] = f'RTA_{base_num}'
        
        decoded.append(info)
    
    return decoded


class RoutingTableQuery:
    """
    Query routing table information using RTNETLINK protocol via C library.
    Supports IPv4 and IPv6 routes across all routing tables.
    
    Can be used with context manager or direct calls:
        # Option 1: Context manager (socket auto-closed)
        with RoutingTableQuery() as rtq:
            routes = rtq.get_routes()
        
        # Option 2: Direct call (socket managed per-call)
        rtq = RoutingTableQuery()
        routes = rtq.get_routes()
        
        # Option 3: Manual socket management
        rtq = RoutingTableQuery()
        rtq.open()
        ipv4_routes = rtq.get_routes(family='ipv4')
        ipv6_routes = rtq.get_routes(family='ipv6')
        rtq.close()
    """
    
    def __init__(self, capture_unknown_attrs: bool = True):
        """
        Initialize routing table query.
        
        Args:
            capture_unknown_attrs: Whether to capture unknown RTA attributes
        """
        self.sock = -1
        self.capture_unknown_attrs = capture_unknown_attrs
    
    def open(self):
        """Explicitly open the netlink socket"""
        if self.sock >= 0:
            return  # Already open
        
        self.sock = lib.nl_create_socket()
        if self.sock < 0:
            raise RuntimeError("Failed to create netlink socket")
    
    def close(self):
        """Explicitly close the netlink socket"""
        if self.sock >= 0:
            lib.nl_close_socket(self.sock)
            self.sock = -1
    
    def __enter__(self):
        """Context manager entry"""
        self.open()
        return self
    
    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        """Context manager exit"""
        self.close()
        return False
    
    def get_routes(self, family: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Query routing table entries.
        
        If socket is not already open (e.g., via 'with' or explicit open()),
        this method will open and close it automatically for this call.
        
        Args:
            family: Optional filter - 'ipv4', 'ipv6', or None for all
        
        Returns:
            List of route entries with full metadata
        """
        # Check if we need to auto-open the socket
        need_auto_close = False
        if self.sock < 0:
            self.open()
            need_auto_close = True
        
        try:
            family_map = {
                'ipv4': AF_INET,
                'ipv6': AF_INET6,
                None: 0,  # AF_UNSPEC
            }
            
            if family not in family_map:
                raise ValueError(f"Invalid family: {family}. Use 'ipv4', 'ipv6', or None")
            
            af_family = family_map[family]
            seq = ffi.new("unsigned int*")
            
            if lib.nl_send_getroute(self.sock, seq, af_family) < 0:
                raise RuntimeError("Failed to send RTM_GETROUTE request")
            
            response = lib.nl_receive_response(self.sock, seq[0])
            if not response:
                raise RuntimeError("Failed to receive response")
            
            try:
                routes_ptr = ffi.new("route_entry_t**")
                count_ptr = ffi.new("int*")
                
                result = lib.nl_parse_routes(response, routes_ptr, count_ptr)
                if result < 0:
                    raise RuntimeError("Failed to parse route entries")
                
                routes_array = routes_ptr[0]
                num_routes = count_ptr[0]
                
                routes = []
                for i in range(num_routes):
                    entry = routes_array[i]
                    
                    route_info = {
                        'family': 'ipv4' if entry.family == AF_INET else 'ipv6' if entry.family == AF_INET6 else entry.family,
                        'type': ROUTE_TYPE_NAMES.get(entry.type, f'TYPE_{entry.type}'),
                        'protocol': ROUTE_PROTOCOL_NAMES.get(entry.protocol, f'PROTO_{entry.protocol}'),
                        'scope': ROUTE_SCOPE_NAMES.get(entry.scope, f'SCOPE_{entry.scope}'),
                        'table': ROUTE_TABLE_NAMES.get(entry.table, entry.table),
                        'dst_len': entry.dst_len,
                        'src_len': entry.src_len,
                        'tos': entry.tos,
                        'flags': entry.flags,
                    }
                    
                    # Destination network
                    if entry.has_dst_addr:
                        if entry.family == AF_INET:
                            dst_bytes = bytes(entry.dst_addr[0:4])
                            dst_ip = ipaddress.IPv4Address(dst_bytes)
                            route_info['dst'] = f"{dst_ip}/{entry.dst_len}"
                        elif entry.family == AF_INET6:
                            dst_bytes = bytes(entry.dst_addr[0:16])
                            dst_ip = ipaddress.IPv6Address(dst_bytes)
                            route_info['dst'] = f"{dst_ip}/{entry.dst_len}"
                    else:
                        # Default route
                        if entry.family == AF_INET:
                            route_info['dst'] = f"0.0.0.0/{entry.dst_len}"
                        elif entry.family == AF_INET6:
                            route_info['dst'] = f"::/{entry.dst_len}"
                    
                    # Source network (policy routing)
                    if entry.has_src_addr:
                        if entry.family == AF_INET:
                            src_bytes = bytes(entry.src_addr[0:4])
                            src_ip = ipaddress.IPv4Address(src_bytes)
                            route_info['src'] = f"{src_ip}/{entry.src_len}"
                        elif entry.family == AF_INET6:
                            src_bytes = bytes(entry.src_addr[0:16])
                            src_ip = ipaddress.IPv6Address(src_bytes)
                            route_info['src'] = f"{src_ip}/{entry.src_len}"
                    
                    # Gateway
                    if entry.has_gateway:
                        if entry.family == AF_INET:
                            gw_bytes = bytes(entry.gateway[0:4])
                            route_info['gateway'] = str(ipaddress.IPv4Address(gw_bytes))
                        elif entry.family == AF_INET6:
                            gw_bytes = bytes(entry.gateway[0:16])
                            route_info['gateway'] = str(ipaddress.IPv6Address(gw_bytes))
                    
                    # Preferred source
                    if entry.has_prefsrc:
                        if entry.family == AF_INET:
                            pref_bytes = bytes(entry.prefsrc[0:4])
                            route_info['prefsrc'] = str(ipaddress.IPv4Address(pref_bytes))
                        elif entry.family == AF_INET6:
                            pref_bytes = bytes(entry.prefsrc[0:16])
                            route_info['prefsrc'] = str(ipaddress.IPv6Address(pref_bytes))
                    
                    # Output interface
                    if entry.has_ifindex:
                        route_info['dev_index'] = entry.ifindex
                        if entry.ifindex > 0:
                            # Get interface name from index
                            ifname_buf = ffi.new("char[]", 16)
                            if lib.nl_get_ifname(entry.ifindex, ifname_buf, 16) == 0:
                                ifname_str = ffi.string(ifname_buf).decode('utf-8')
                                if ifname_str:  # Only add if non-empty
                                    route_info['dev'] = ifname_str
                    
                    # Priority/metric
                    if entry.has_priority:
                        route_info['metric'] = entry.priority
                    
                    # Table ID (for tables > 255)
                    if entry.has_table_id:
                        route_info['table_id'] = entry.table_id
                        route_info['table'] = ROUTE_TABLE_NAMES.get(entry.table_id, entry.table_id)
                    
                    # Cache info
                    if entry.cacheinfo.has_clntref:
                        route_info['cacheinfo'] = {
                            'clntref': entry.cacheinfo.clntref,
                            'last_use': entry.cacheinfo.last_use,
                            'expires': entry.cacheinfo.expires,
                            'error': entry.cacheinfo.error,
                            'used': entry.cacheinfo.used,
                        }
                    
                    # Multipath nexthops
                    if entry.nexthop_count > 0:
                        nexthops = []
                        for j in range(entry.nexthop_count):
                            nh = entry.nexthops[j]
                            nh_info = {
                                'dev_index': nh.ifindex,
                                'weight': nh.weight,
                                'flags': nh.flags,
                            }
                            # Get interface name for nexthop
                            if nh.ifindex > 0:
                                ifname_buf = ffi.new("char[]", 16)
                                if lib.nl_get_ifname(nh.ifindex, ifname_buf, 16) == 0:
                                    ifname_str = ffi.string(ifname_buf).decode('utf-8')
                                    if ifname_str:  # Only add if non-empty
                                        nh_info['dev'] = ifname_str
                            if nh.has_gateway:
                                if entry.family == AF_INET:
                                    gw_bytes = bytes(nh.gateway[0:4])
                                    nh_info['gateway'] = str(ipaddress.IPv4Address(gw_bytes))
                                elif entry.family == AF_INET6:
                                    gw_bytes = bytes(nh.gateway[0:16])
                                    nh_info['gateway'] = str(ipaddress.IPv6Address(gw_bytes))
                            nexthops.append(nh_info)
                        route_info['multipath'] = nexthops
                    
                    # Unknown attributes
                    if self.capture_unknown_attrs and entry.unknown_rta_attrs_count > 0:
                        unknown_list = []
                        for j in range(entry.unknown_rta_attrs_count):
                            unknown_list.append(entry.unknown_rta_attrs[j])
                        route_info['unknown_rta_attrs'] = unknown_list
                        route_info['unknown_rta_attrs_decoded'] = decode_unknown_attrs(unknown_list)
                    
                    routes.append(route_info)
                
                lib.nl_free_routes(routes_array)
                return routes
            
            finally:
                lib.nl_free_response(response)
        
        finally:
            # Auto-close socket if we auto-opened it
            if need_auto_close:
                self.close()

# Example usage
def main():
        """Main entry point for the command."""
        import argparse
    
        parser = argparse.ArgumentParser(description='Routing Table Query Tool')
        parser.add_argument('--no-unknown-attrs', action='store_true',
                            help='Disable unknown attribute tracking')
        parser.add_argument('--summary', action='store_true',
                            help='Show human-readable summary')
        parser.add_argument('--ipv4', action='store_true',
                            help='Show only IPv4 routes')
        parser.add_argument('--ipv6', action='store_true',
                            help='Show only IPv6 routes')
        parser.add_argument('--table','-t', type=str,
                            help='Filter by table name (main, local, etc.)')
        parser.add_argument("-j","--json",action='store_true',help="Output in pure JSON format (default).")
        parser.add_argument("--verbose",'-v',action='store_true',help="Output in text format.")
        
        args = parser.parse_args()
        if args.verbose: args.summary=True
        if args.json and (args.summary or args.ipv4 or args.ipv6 or args.table or args.verbose):
            parser.error(
                f"Only --no-unknown-attrs is allowed with -j or --json"
            )
            
        try:
            if (not args.json) and (len(sys.argv) != 1):
                print("=" * 70)
                print("ROUTING TABLE QUERY")
                print("=" * 70)
        
            with RoutingTableQuery(capture_unknown_attrs=not args.no_unknown_attrs) as query:
                # Determine family filter
                family = None
                if args.ipv4:
                    family = 'ipv4'
                elif args.ipv6:
                    family = 'ipv6'
            
                routes = query.get_routes(family=family)
            
                # Filter by table if requested
                if args.table:
                    table_lower = args.table.lower()
                    routes = [r for r in routes if str(r.get('table', '')).lower() == table_lower]
            
                if args.summary:
                    # Human-readable summary
                    print(f"\nTotal routes: {len(routes)}")
                    print(f"\nRoute entries:\n")
                
                    for route in routes:
                        print(f"  {route['dst']:40s}", end='')
                        if 'gateway' in route:
                            print(f" via {route['gateway']:20s}", end='')
                        if 'dev' in route:
                            print(f" dev {route['dev']:10s}", end='')
                        if 'metric' in route:
                            print(f" metric {route['metric']}", end='')
                        print(f" [{route['protocol']}]")
                        if 'multipath' in route:
                            for nh in route['multipath']:
                                print(f"    nexthop", end='')
                                if 'gateway' in nh:
                                    print(f" via {nh['gateway']}", end='')
                                if 'dev' in nh:
                                    print(f" dev {nh['dev']}", end='')
                                else:
                                    print(f" dev {nh['dev_index']}", end='')
                                print(f" weight {nh['weight']}")
                else:
                    # Full JSON output
                    print(json.dumps(routes, indent=2))
                
        except PermissionError:
            print("Error: This tool requires root privileges (sudo)", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)
            
        return 0


if __name__ == '__main__':
    main()
