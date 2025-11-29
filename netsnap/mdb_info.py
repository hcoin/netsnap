#!/usr/bin/env python3
"""
RTNetlink Multicast Database (MDB) Query with C Library via CFFI
Complete bridge multicast database inspection including:
- Bridge multicast group memberships
- IPv4 IGMP snooping entries
- IPv6 MLD snooping entries
- Port-based multicast forwarding
- Router port identification
- Multicast querier configuration
- Group timers and state tracking

MDB Entry Types:
- L2 (Ethernet): MAC-based multicast groups (01:00:5e:xx:xx:xx)
- IPv4: IGMP-snooped groups with port memberships
- IPv6: MLD-snooped groups with port memberships

MDB States:
- TEMPORARY: Learned dynamically, will expire
- PERMANENT: Static configuration, never expires
- EXCLUDE: Exclude mode (SSM)
- INCLUDE: Include mode (ASM)

Requirements:
    - Python 3.8+
    - cffi>=1.0.0
    - setuptools (required for Python 3.12+)

Install:
    pip install cffi setuptools

Usage:
    sudo python3 mdbsnapshotter.py                    # Full JSON output
    sudo python3 mdbsnapshotter.py --summary          # Human-readable summary
    sudo python3 mdbsnapshotter.py --bridge br0       # Filter by bridge
    sudo python3 mdbsnapshotter.py --ipv4             # IPv4 groups only
    sudo python3 mdbsnapshotter.py --ipv6             # IPv6 groups only
    sudo python3 mdbsnapshotter.py --routers          # Show router ports only
"""

from cffi import FFI
import json
import sys
#import os
import ipaddress
from typing import Dict, List, Any #, Optional

# Check Python version
if sys.version_info < (3, 8):
    raise RuntimeError("Python 3.8 or higher is required")

# For Python 3.12+, verify setuptools is available
if sys.version_info >= (3, 12):
    try:
        import setuptools #@noqa
    except ImportError:
        raise RuntimeError(
            "Python 3.12+ requires setuptools for CFFI. "
            "Install it with: pip install setuptools"
        )

# C library source code - RTM_GETMDB support (v2 - kernel 6.8 compat)
C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <errno.h>

// Verify we have minimum required kernel headers
#if !defined(NETLINK_ROUTE)
#error "Kernel headers too old - need Linux 2.6+ with rtnetlink support"
#endif

// RTM_GETMDB/RTM_NEWMDB definitions (check kernel version)
#ifndef RTM_GETMDB
#define RTM_GETMDB 86
#endif
#ifndef RTM_NEWMDB  
#define RTM_NEWMDB 86
#endif
#ifndef RTM_DELMDB
#define RTM_DELMDB 87
#endif

// Response buffer structure
typedef struct {
    unsigned char* data;
    size_t length;
    size_t capacity;
    unsigned int seq;
} response_buffer_t;

// MDB entry flags (not states!)
#ifndef MDB_FLAGS_OFFLOAD
#define MDB_FLAGS_OFFLOAD   0x01
#define MDB_FLAGS_FAST_LEAVE 0x02
#define MDB_FLAGS_STAR_EXCL 0x04
#define MDB_FLAGS_BLOCKED   0x08
#endif

// MDB entry states (in ndm_state field)
#ifndef MDB_PERMANENT
#define MDB_PERMANENT   0x02
#define MDB_TEMPORARY   0x00
#endif

// MDB RTR states  
#ifndef MDB_RTR_TYPE_DISABLED
#define MDB_RTR_TYPE_DISABLED     0
#define MDB_RTR_TYPE_TEMP_QUERY   1
#define MDB_RTR_TYPE_PERM         2
#define MDB_RTR_TYPE_TEMP         3
#endif

// MDBA_* Attribute definitions (for older kernels)
#ifndef MDBA_UNSPEC
#define MDBA_UNSPEC      0
#define MDBA_MDB         1
#define MDBA_ROUTER      2
#define MDBA_MDB_ENTRY   1
#define MDBA_MDB_ENTRY_INFO  1
#define MDBA_ROUTER_PORT 1
#define MDBA_ROUTER_PATTR 2
#endif

// MDBA_MDB_EATTR_* definitions
#ifndef MDBA_MDB_EATTR_TIMER
#define MDBA_MDB_EATTR_TIMER     1
#define MDBA_MDB_EATTR_SRC_LIST  2
#define MDBA_MDB_EATTR_GROUP_MODE 3
#define MDBA_MDB_EATTR_SOURCE    4
#define MDBA_MDB_EATTR_RTPROT    5
#define MDBA_MDB_EATTR_PROTO     6
#endif

// MDBA_ROUTER_PATTR_* definitions
#ifndef MDBA_ROUTER_PATTR_TIMER
#define MDBA_ROUTER_PATTR_TIMER  1
#define MDBA_ROUTER_PATTR_TYPE   2
#define MDBA_ROUTER_PATTR_INET_TIMER  3
#define MDBA_ROUTER_PATTR_INET6_TIMER 4
#define MDBA_ROUTER_PATTR_VID    5
#endif

// MDB entry information
typedef struct {
    int ifindex;
    unsigned char state;
    unsigned char flags;
    unsigned short vid;
    int has_vid;
    unsigned char addr[16];      // Group address (IPv4/IPv6)
    int addr_len;
    unsigned short addr_proto;   // ETH_P_IP or ETH_P_IPV6
    int has_addr;
    int port_ifindex;
    int has_port;
    unsigned int timer;
    int has_timer;
    unsigned char group_mode;
    int has_group_mode;
    unsigned char proto;
    int has_proto;
    unsigned char rtprot;
    int has_rtprot;
    unsigned short unknown_mdba_attrs[64];
    int unknown_mdba_attrs_count;
    unsigned short unknown_entry_attrs[64];
    int unknown_entry_attrs_count;
} mdb_entry_t;

// Router port information
typedef struct {
    int ifindex;
    int port_ifindex;
    int has_port;
    unsigned char router_type;
    int has_router_type;
    unsigned int timer;
    int has_timer;
    unsigned int inet_timer;
    int has_inet_timer;
    unsigned int inet6_timer;
    int has_inet6_timer;
    unsigned short vid;
    int has_vid;
    unsigned short unknown_rtr_attrs[64];
    int unknown_rtr_attrs_count;
} mdb_router_t;

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

// Send RTM_GETMDB request
int nl_send_getmdb(int sock, unsigned int* seq_out, int ifindex) {
    struct {
        struct nlmsghdr nlh;
        struct br_port_msg bpm;
    } req;
    
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_port_msg));
    req.nlh.nlmsg_type = RTM_GETMDB;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = nl_generate_seq();
    req.nlh.nlmsg_pid = 0;
    req.bpm.family = AF_BRIDGE;
    req.bpm.ifindex = ifindex;  // 0 for all bridges
    
    if (seq_out) {
        *seq_out = req.nlh.nlmsg_seq;
    }
    
    return send(sock, &req, req.nlh.nlmsg_len, 0);
}

// Receive netlink response
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

// Track unknown attributes
static void track_unknown_attr(unsigned short* unknown_list, int* count, int max_count,
                               unsigned short attr_type, const unsigned short* known_attrs,
                               int known_count) {
    for (int i = 0; i < known_count; i++) {
        if (known_attrs[i] == attr_type) {
            return;
        }
    }
    
    for (int i = 0; i < *count; i++) {
        if (unknown_list[i] == attr_type) {
            return;
        }
    }
    
    if (*count < max_count) {
        unknown_list[*count] = attr_type;
        (*count)++;
    }
}

// Parse MDB entry attributes
static void parse_mdb_entry_attrs(struct rtattr* entry_rta, int entry_len, mdb_entry_t* entry) {
    static const unsigned short known_entry_attrs[] = {
        MDBA_MDB_EATTR_TIMER, MDBA_MDB_EATTR_SRC_LIST, MDBA_MDB_EATTR_GROUP_MODE,
        MDBA_MDB_EATTR_SOURCE, MDBA_MDB_EATTR_RTPROT, MDBA_MDB_EATTR_PROTO
    };
    static const int known_entry_count = sizeof(known_entry_attrs) / sizeof(known_entry_attrs[0]);
    
    for (; RTA_OK(entry_rta, entry_len); entry_rta = RTA_NEXT(entry_rta, entry_len)) {
        track_unknown_attr(entry->unknown_entry_attrs,
                          &entry->unknown_entry_attrs_count,
                          64, entry_rta->rta_type, known_entry_attrs, known_entry_count);
        
        switch (entry_rta->rta_type) {
            case MDBA_MDB_EATTR_TIMER:
                if (RTA_PAYLOAD(entry_rta) >= sizeof(unsigned int)) {
                    entry->timer = *(unsigned int*)RTA_DATA(entry_rta);
                    entry->has_timer = 1;
                }
                break;
            
            case MDBA_MDB_EATTR_GROUP_MODE:
                if (RTA_PAYLOAD(entry_rta) >= sizeof(unsigned char)) {
                    entry->group_mode = *(unsigned char*)RTA_DATA(entry_rta);
                    entry->has_group_mode = 1;
                }
                break;
            
            case MDBA_MDB_EATTR_PROTO:
                if (RTA_PAYLOAD(entry_rta) >= sizeof(unsigned char)) {
                    entry->proto = *(unsigned char*)RTA_DATA(entry_rta);
                    entry->has_proto = 1;
                }
                break;
            
            case MDBA_MDB_EATTR_RTPROT:
                if (RTA_PAYLOAD(entry_rta) >= sizeof(unsigned char)) {
                    entry->rtprot = *(unsigned char*)RTA_DATA(entry_rta);
                    entry->has_rtprot = 1;
                }
                break;
            
            case MDBA_MDB_EATTR_SRC_LIST:
                // Nested - contains source-specific multicast info
                // Skip for now, complex structure
                break;
            
            case MDBA_MDB_EATTR_SOURCE:
                // Source address for (S,G) entries
                // Skip for now
                break;
        }
    }
}

// Parse MDB entries
int nl_parse_mdb_entries(response_buffer_t* buf, mdb_entry_t** entries, int* count) {
    if (!buf || !entries || !count) return -1;
    
    *count = 0;
    *entries = NULL;
    
    if (buf->length == 0) {
        return 0;
    }
    
    // First pass: count entries
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf->data;
    int max_count = 0;
    size_t remaining = buf->length;
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        // Accept both RTM_NEWMDB (84) and actual response type (86)
        if (nlh->nlmsg_type != RTM_NEWMDB && nlh->nlmsg_type != 86) continue;
        
        struct br_port_msg* bpm = NLMSG_DATA(nlh);
        struct rtattr* rta = (struct rtattr*)((char*)bpm + NLMSG_ALIGN(sizeof(struct br_port_msg)));
        int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct br_port_msg));
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == MDBA_MDB) {
                struct rtattr* mdb_rta = RTA_DATA(rta);
                int mdb_len = RTA_PAYLOAD(rta);
                
                for (; RTA_OK(mdb_rta, mdb_len); mdb_rta = RTA_NEXT(mdb_rta, mdb_len)) {
                    if (mdb_rta->rta_type == MDBA_MDB_ENTRY) {
                        struct rtattr* entry_rta = RTA_DATA(mdb_rta);
                        int entry_len = RTA_PAYLOAD(mdb_rta);
                        
                        for (; RTA_OK(entry_rta, entry_len); entry_rta = RTA_NEXT(entry_rta, entry_len)) {
                            if (entry_rta->rta_type == MDBA_MDB_ENTRY_INFO) {
                                max_count++;
                            }
                        }
                    }
                }
            }
        }
    }
    
    if (max_count == 0) {
        return 0;
    }
    
    *entries = calloc(max_count, sizeof(mdb_entry_t));
    if (!*entries) return -1;
    
    // Second pass: parse entries
    nlh = (struct nlmsghdr*)buf->data;
    remaining = buf->length;
    
    static const unsigned short known_mdba_attrs[] = { MDBA_MDB, MDBA_ROUTER };
    static const int known_mdba_count = sizeof(known_mdba_attrs) / sizeof(known_mdba_attrs[0]);
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
        // Accept both RTM_NEWMDB (84) and actual response type (86)
        if (nlh->nlmsg_type != RTM_NEWMDB && nlh->nlmsg_type != 86) continue;
        
        struct br_port_msg* bpm = NLMSG_DATA(nlh);
        struct rtattr* rta = (struct rtattr*)((char*)bpm + NLMSG_ALIGN(sizeof(struct br_port_msg)));
        int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct br_port_msg));
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (*count < max_count) {
                track_unknown_attr((*entries)[*count].unknown_mdba_attrs,
                                  &(*entries)[*count].unknown_mdba_attrs_count,
                                  64, rta->rta_type, known_mdba_attrs, known_mdba_count);
            }
            
            if (rta->rta_type == MDBA_MDB) {
                struct rtattr* mdb_rta = RTA_DATA(rta);
                int mdb_len = RTA_PAYLOAD(rta);
                
                for (; RTA_OK(mdb_rta, mdb_len); mdb_rta = RTA_NEXT(mdb_rta, mdb_len)) {
                    if (mdb_rta->rta_type == MDBA_MDB_ENTRY) {
                        struct rtattr* entry_rta = RTA_DATA(mdb_rta);
                        int entry_len = RTA_PAYLOAD(mdb_rta);
                        
                        for (; RTA_OK(entry_rta, entry_len); entry_rta = RTA_NEXT(entry_rta, entry_len)) {
                            if (entry_rta->rta_type == MDBA_MDB_ENTRY_INFO) {
                                if (*count >= max_count) break;
                                
                                mdb_entry_t* entry = &(*entries)[*count];
                                memset(entry, 0, sizeof(mdb_entry_t));
                                
                                entry->ifindex = bpm->ifindex;
                                
                                // Parse br_mdb_entry structure
                                if (RTA_PAYLOAD(entry_rta) >= sizeof(struct br_mdb_entry)) {
                                    struct br_mdb_entry* mdb = RTA_DATA(entry_rta);
                                    
                                    // br_mdb_entry fields:
                                    // __u32 ifindex
                                    // __u8 state  
                                    // __u8 flags
                                    // __u16 vid
                                    // struct br_mdb_entry_addr addr
                                    
                                    entry->port_ifindex = mdb->ifindex;
                                    entry->has_port = 1;
                                    entry->state = mdb->state;
                                    entry->flags = mdb->flags;  
                                    entry->vid = mdb->vid;
                                    entry->has_vid = (mdb->vid != 0);
                                    
                                    // Decode address based on protocol
                                    entry->addr_proto = ntohs(mdb->addr.proto);
                                    
                                    if (entry->addr_proto == 0x0800) {  // ETH_P_IP
                                        memcpy(entry->addr, &mdb->addr.u.ip4, 4);
                                        entry->addr_len = 4;
                                        entry->has_addr = 1;
                                    } else if (entry->addr_proto == 0x86DD) {  // ETH_P_IPV6
                                        memcpy(entry->addr, &mdb->addr.u.ip6, 16);
                                        entry->addr_len = 16;
                                        entry->has_addr = 1;
                                    } else if (entry->addr_proto == 0x0000) {  // L2 multicast
                                        memcpy(entry->addr, &mdb->addr.u.mac_addr, 6);
                                        entry->addr_len = 6;
                                        entry->has_addr = 1;
                                    } else {
                                        // Unknown protocol - try to capture the raw address anyway
                                        memcpy(entry->addr, &mdb->addr.u, 16);
                                        entry->addr_len = 16;
                                        entry->has_addr = 1;
                                    }
                                    
                                    // Parse extended attributes if present
                                    size_t info_len = RTA_PAYLOAD(entry_rta);
                                    if (info_len > sizeof(struct br_mdb_entry)) {
                                        struct rtattr* info_rta = (struct rtattr*)((char*)mdb + 
                                            NLMSG_ALIGN(sizeof(struct br_mdb_entry)));
                                        size_t remaining_len = info_len - sizeof(struct br_mdb_entry);
                                        parse_mdb_entry_attrs(info_rta, remaining_len, entry);
                                    }
                                }
                                
                                (*count)++;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}

// Parse router ports
int nl_parse_mdb_routers(response_buffer_t* buf, mdb_router_t** routers, int* count) {
    if (!buf || !routers || !count) return -1;
    
    *count = 0;
    *routers = NULL;
    
    if (buf->length == 0) {
        return 0;
    }
    
    // First pass: count router ports
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf->data;
    int max_count = 0;
    size_t remaining = buf->length;
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
        // Accept both RTM_NEWMDB (84) and actual response type (86)
        if (nlh->nlmsg_type != RTM_NEWMDB && nlh->nlmsg_type != 86) continue;
        
        struct br_port_msg* bpm = NLMSG_DATA(nlh);
        struct rtattr* rta = (struct rtattr*)((char*)bpm + NLMSG_ALIGN(sizeof(struct br_port_msg)));
        int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct br_port_msg));
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == MDBA_ROUTER) {
                struct rtattr* rtr_rta = RTA_DATA(rta);
                int rtr_len = RTA_PAYLOAD(rta);
                
                for (; RTA_OK(rtr_rta, rtr_len); rtr_rta = RTA_NEXT(rtr_rta, rtr_len)) {
                    if (rtr_rta->rta_type == MDBA_ROUTER_PORT) {
                        max_count++;
                    }
                }
            }
        }
    }
    
    if (max_count == 0) return 0;
    
    *routers = calloc(max_count, sizeof(mdb_router_t));
    if (!*routers) return -1;
    
    // Second pass: parse router ports
    nlh = (struct nlmsghdr*)buf->data;
    remaining = buf->length;
    
    static const unsigned short known_rtr_attrs[] = {
        MDBA_ROUTER_PATTR_TIMER, MDBA_ROUTER_PATTR_TYPE,
        MDBA_ROUTER_PATTR_INET_TIMER, MDBA_ROUTER_PATTR_INET6_TIMER,
        MDBA_ROUTER_PATTR_VID
    };
    static const int known_rtr_count = sizeof(known_rtr_attrs) / sizeof(known_rtr_attrs[0]);
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type != RTM_NEWMDB) continue;
        
        struct br_port_msg* bpm = NLMSG_DATA(nlh);
        struct rtattr* rta = (struct rtattr*)((char*)bpm + NLMSG_ALIGN(sizeof(struct br_port_msg)));
        int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct br_port_msg));
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == MDBA_ROUTER) {
                struct rtattr* rtr_rta = RTA_DATA(rta);
                int rtr_len = RTA_PAYLOAD(rta);
                
                for (; RTA_OK(rtr_rta, rtr_len); rtr_rta = RTA_NEXT(rtr_rta, rtr_len)) {
                    if (rtr_rta->rta_type == MDBA_ROUTER_PORT) {
                        if (*count >= max_count) break;
                        
                        mdb_router_t* router = &(*routers)[*count];
                        memset(router, 0, sizeof(mdb_router_t));
                        
                        router->ifindex = bpm->ifindex;
                        
                        // Router port is just an ifindex
                        if (RTA_PAYLOAD(rtr_rta) >= sizeof(unsigned int)) {
                            router->port_ifindex = *(unsigned int*)RTA_DATA(rtr_rta);
                            router->has_port = 1;
                        }
                        
                        (*count)++;
                    } else if (rtr_rta->rta_type == MDBA_ROUTER_PATTR) {
                        if (*count == 0) continue;
                        
                        mdb_router_t* router = &(*routers)[*count - 1];
                        struct rtattr* attr_rta = RTA_DATA(rtr_rta);
                        int attr_len = RTA_PAYLOAD(rtr_rta);
                        
                        for (; RTA_OK(attr_rta, attr_len); attr_rta = RTA_NEXT(attr_rta, attr_len)) {
                            track_unknown_attr(router->unknown_rtr_attrs,
                                              &router->unknown_rtr_attrs_count,
                                              64, attr_rta->rta_type, known_rtr_attrs, known_rtr_count);
                            
                            switch (attr_rta->rta_type) {
                                case MDBA_ROUTER_PATTR_TIMER:
                                    if (RTA_PAYLOAD(attr_rta) >= sizeof(unsigned int)) {
                                        router->timer = *(unsigned int*)RTA_DATA(attr_rta);
                                        router->has_timer = 1;
                                    }
                                    break;
                                
                                case MDBA_ROUTER_PATTR_TYPE:
                                    if (RTA_PAYLOAD(attr_rta) >= sizeof(unsigned char)) {
                                        router->router_type = *(unsigned char*)RTA_DATA(attr_rta);
                                        router->has_router_type = 1;
                                    }
                                    break;
                                
                                case MDBA_ROUTER_PATTR_INET_TIMER:
                                    if (RTA_PAYLOAD(attr_rta) >= sizeof(unsigned int)) {
                                        router->inet_timer = *(unsigned int*)RTA_DATA(attr_rta);
                                        router->has_inet_timer = 1;
                                    }
                                    break;
                                
                                case MDBA_ROUTER_PATTR_INET6_TIMER:
                                    if (RTA_PAYLOAD(attr_rta) >= sizeof(unsigned int)) {
                                        router->inet6_timer = *(unsigned int*)RTA_DATA(attr_rta);
                                        router->has_inet6_timer = 1;
                                    }
                                    break;
                                
                                case MDBA_ROUTER_PATTR_VID:
                                    if (RTA_PAYLOAD(attr_rta) >= sizeof(unsigned short)) {
                                        router->vid = *(unsigned short*)RTA_DATA(attr_rta);
                                        router->has_vid = 1;
                                    }
                                    break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}

void nl_free_mdb_entries(mdb_entry_t* entries) {
    if (entries) free(entries);
}

void nl_free_mdb_routers(mdb_router_t* routers) {
    if (routers) free(routers);
}

// Helper functions
int nl_get_af_bridge(void) { return AF_BRIDGE; }
int nl_get_eth_p_ip(void) { return 0x0800; }
int nl_get_eth_p_ipv6(void) { return 0x86DD; }

const char* nl_get_mdb_state_name(unsigned char state) {
    static char buf[64];
    buf[0] = '\0';
    
    // In MDB, state is actually from ndm_state (neighbor states)
    // MDB_TEMPORARY means state == 0
    // MDB_PERMANENT means state has NUD_PERMANENT (0x80)
    
    if (state == 0) {
        return "TEMPORARY";
    }
    
    int first = 1;
    
    if (state & 0x80) {  // NUD_PERMANENT
        if (!first) strcat(buf, "|");
        strcat(buf, "PERMANENT");
        first = 0;
    }
    
    if (state & 0x02) {  // NUD_REACHABLE
        if (!first) strcat(buf, "|");
        strcat(buf, "REACHABLE");
        first = 0;
    }
    
    if (state & 0x01) {  // NUD_INCOMPLETE
        if (!first) strcat(buf, "|");
        strcat(buf, "INCOMPLETE");
        first = 0;
    }
    
    if (state & 0x04) {  // NUD_STALE
        if (!first) strcat(buf, "|");
        strcat(buf, "STALE");
        first = 0;
    }
    
    return buf[0] ? buf : "UNKNOWN";
}

const char* nl_get_router_type_name(unsigned char type) {
    switch (type) {
        case MDB_RTR_TYPE_DISABLED:    return "DISABLED";
        case MDB_RTR_TYPE_TEMP_QUERY:  return "TEMP_QUERY";
        case MDB_RTR_TYPE_PERM:        return "PERMANENT";
        case MDB_RTR_TYPE_TEMP:        return "TEMPORARY";
        default: return "UNKNOWN";
    }
}

const char* nl_get_group_mode_name(unsigned char mode) {
    switch (mode) {
        case 1: return "INCLUDE";
        case 2: return "EXCLUDE";
        default: return "UNKNOWN";
    }
}

const char* nl_get_mdb_flags_name(unsigned char flags) {
    static char buf[128];
    buf[0] = '\0';
    int first = 1;
    
    if (flags & 0x01) {  // MDB_FLAGS_OFFLOAD
        if (!first) strcat(buf, "|");
        strcat(buf, "OFFLOAD");
        first = 0;
    }
    if (flags & 0x02) {  // MDB_FLAGS_FAST_LEAVE
        if (!first) strcat(buf, "|");
        strcat(buf, "FAST_LEAVE");
        first = 0;
    }
    if (flags & 0x04) {  // MDB_FLAGS_STAR_EXCL
        if (!first) strcat(buf, "|");
        strcat(buf, "STAR_EXCL");
        first = 0;
    }
    if (flags & 0x08) {  // MDB_FLAGS_BLOCKED
        if (!first) strcat(buf, "|");
        strcat(buf, "BLOCKED");
        first = 0;
    }
    
    return buf[0] ? buf : "NONE";
}
""";  # END OF C_SOURCE

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
        int ifindex;
        unsigned char state;
        unsigned char flags;
        unsigned short vid;
        int has_vid;
        unsigned char addr[16];
        int addr_len;
        unsigned short addr_proto;
        int has_addr;
        int port_ifindex;
        int has_port;
        unsigned int timer;
        int has_timer;
        unsigned char group_mode;
        int has_group_mode;
        unsigned char proto;
        int has_proto;
        unsigned char rtprot;
        int has_rtprot;
        unsigned short unknown_mdba_attrs[64];
        int unknown_mdba_attrs_count;
        unsigned short unknown_entry_attrs[64];
        int unknown_entry_attrs_count;
    } mdb_entry_t;

    typedef struct {
        int ifindex;
        int port_ifindex;
        int has_port;
        unsigned char router_type;
        int has_router_type;
        unsigned int timer;
        int has_timer;
        unsigned int inet_timer;
        int has_inet_timer;
        unsigned int inet6_timer;
        int has_inet6_timer;
        unsigned short vid;
        int has_vid;
        unsigned short unknown_rtr_attrs[64];
        int unknown_rtr_attrs_count;
    } mdb_router_t;

    int nl_create_socket(void);
    void nl_close_socket(int sock);
    int nl_send_getmdb(int sock, unsigned int* seq_out, int ifindex);
    response_buffer_t* nl_recv_response(int sock, unsigned int expected_seq);
    void nl_free_response(response_buffer_t* buf);
    int nl_parse_mdb_entries(response_buffer_t* buf, mdb_entry_t** entries, int* count);
    int nl_parse_mdb_routers(response_buffer_t* buf, mdb_router_t** routers, int* count);
    void nl_free_mdb_entries(mdb_entry_t* entries);
    void nl_free_mdb_routers(mdb_router_t* routers);
    int nl_get_af_bridge(void);
    int nl_get_eth_p_ip(void);
    int nl_get_eth_p_ipv6(void);
    const char* nl_get_mdb_state_name(unsigned char state);
    const char* nl_get_router_type_name(unsigned char type);
    const char* nl_get_group_mode_name(unsigned char mode);
    const char* nl_get_mdb_flags_name(unsigned char flags);
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

AF_BRIDGE = lib.nl_get_af_bridge()
ETH_P_IP = lib.nl_get_eth_p_ip()
ETH_P_IPV6 = lib.nl_get_eth_p_ipv6()

# MDBA_* Attribute Name Mapping
MDBA_ATTR_NAMES = {
    0: 'MDBA_UNSPEC',
    1: 'MDBA_MDB',
    2: 'MDBA_ROUTER',
}

MDBA_MDB_EATTR_NAMES = {
    0: 'MDBA_MDB_EATTR_UNSPEC',
    1: 'MDBA_MDB_EATTR_TIMER',
    2: 'MDBA_MDB_EATTR_SRC_LIST',
    3: 'MDBA_MDB_EATTR_GROUP_MODE',
    4: 'MDBA_MDB_EATTR_SOURCE',
    5: 'MDBA_MDB_EATTR_RTPROT',
    6: 'MDBA_MDB_EATTR_PROTO',
}


def decode_unknown_attrs(attr_list: List[int], attr_type: str = 'MDBA') -> List[Dict[str, Any]]:
    """Decode unknown attribute numbers into human-readable information"""
    decoded = []
    name_map = MDBA_ATTR_NAMES if attr_type == 'MDBA' else MDBA_MDB_EATTR_NAMES
    
    for attr_num in attr_list:
        is_nested = bool(attr_num & 0x8000)
        base_num = attr_num & 0x7FFF
        
        info = {
            'number': attr_num,
            'base_number': base_num,
            'nested': is_nested,
        }
        
        if base_num in name_map:
            info['name'] = name_map[base_num]
            if is_nested:
                info['name'] += ' (nested)'
        else:
            info['name'] = f'{attr_type}_{base_num}'
        
        decoded.append(info)
    
    return decoded


class MDBQuery:
    """
    Query multicast database information using RTNETLINK protocol via C library.
    Supports bridge MDB entries for IGMP/MLD snooping.
    """
    
    def __init__(self, capture_unknown_attrs: bool = True):
        self.sock = -1
        self.capture_unknown_attrs = capture_unknown_attrs
        
        # Cache for interface names (ifindex -> name string)
        # This prevents issues if interface names change between query and later lookups
        self.ifindex_cache: Dict[int, str] = {}
    
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
    
    def _cache_ifindex_name(self, ifindex: int) -> str:
        """
        Resolve and cache interface name for a given ifindex.
        
        Args:
            ifindex: Interface index to resolve
            
        Returns:
            Interface name string (e.g., "eth0") or "if{ifindex}" if not found
        """
        if ifindex not in self.ifindex_cache:
            try:
                import socket
                self.ifindex_cache[ifindex] = socket.if_indextoname(ifindex)
            except OSError:
                # Interface doesn't exist or can't be resolved
                self.ifindex_cache[ifindex] = f"if{ifindex}"
        
        return self.ifindex_cache[ifindex]
    
    def get_mdb(self, bridge_ifindex: int = 0) -> Dict[str, Any]:
        """
        Query multicast database entries and router ports.
        
        Args:
            bridge_ifindex: Bridge interface index (0 for all bridges)
        
        Returns:
            Dictionary with 'entries' and 'routers' lists
        """
        seq_ptr = ffi.new("unsigned int*")
        
        if lib.nl_send_getmdb(self.sock, seq_ptr, bridge_ifindex) < 0:
            raise RuntimeError("Failed to send RTM_GETMDB request")
        
        seq = seq_ptr[0]
        response = lib.nl_recv_response(self.sock, seq)
        if not response:
            raise RuntimeError("Failed to receive response for RTM_GETMDB")
        
        try:
            # Parse MDB entries
            entries_ptr = ffi.new("mdb_entry_t**")
            entries_count_ptr = ffi.new("int*")
            
            result = lib.nl_parse_mdb_entries(response, entries_ptr, entries_count_ptr)
            if result < 0:
                raise RuntimeError("Failed to parse MDB entries")
            
            entries = []
            entries_count = entries_count_ptr[0]
            entries_array = entries_ptr[0]
            
            for i in range(entries_count):
                entry = entries_array[i]
                
                # Get state name
                state_name_ptr = lib.nl_get_mdb_state_name(entry.state)
                state_name = ffi.string(state_name_ptr).decode('utf-8')
                
                # Get flags name
                flags_name_ptr = lib.nl_get_mdb_flags_name(entry.flags)
                flags_name = ffi.string(flags_name_ptr).decode('utf-8')
                
                entry_info = {
                    'ifindex': entry.ifindex,
                    'ifname': self._cache_ifindex_name(entry.ifindex),
                    'state': entry.state,
                    'state_name': state_name,
                    'flags': entry.flags,
                    'flags_name': flags_name,
                }
                
                # Add port
                if entry.has_port:
                    entry_info['port_ifindex'] = entry.port_ifindex
                    entry_info['port_ifname'] = self._cache_ifindex_name(entry.port_ifindex)
                
                # Add VLAN
                if entry.has_vid:
                    entry_info['vid'] = entry.vid
                
                # Decode group address
                if entry.has_addr:
                    if entry.addr_proto == ETH_P_IP:
                        addr_bytes = bytes(entry.addr[0:4])
                        try:
                            ipv4_addr = ipaddress.IPv4Address(addr_bytes)
                            entry_info['group'] = str(ipv4_addr)
                            entry_info['family'] = 'ipv4'
                        except ValueError:
                            entry_info['group'] = addr_bytes.hex()
                            entry_info['family'] = 'unknown'
                    elif entry.addr_proto == ETH_P_IPV6:
                        addr_bytes = bytes(entry.addr[0:16])
                        try:
                            ipv6_addr = ipaddress.IPv6Address(addr_bytes)
                            entry_info['group'] = str(ipv6_addr)
                            entry_info['family'] = 'ipv6'
                        except ValueError:
                            entry_info['group'] = addr_bytes.hex()
                            entry_info['family'] = 'unknown'
                    elif entry.addr_proto == 0x0000:
                        # L2 multicast (MAC address)
                        addr_bytes = bytes(entry.addr[0:6])
                        entry_info['group'] = ':'.join(f'{b:02x}' for b in addr_bytes)
                        entry_info['family'] = 'l2'
                    else:
                        entry_info['group'] = f'proto_0x{entry.addr_proto:04x}'
                        entry_info['family'] = 'unknown'
                    
                    entry_info['addr_proto'] = entry.addr_proto
                
                # Timer
                if entry.has_timer:
                    entry_info['timer'] = entry.timer
                    entry_info['timer_sec'] = entry.timer / 100.0
                
                # Group mode
                if entry.has_group_mode:
                    mode_name_ptr = lib.nl_get_group_mode_name(entry.group_mode)
                    mode_name = ffi.string(mode_name_ptr).decode('utf-8')
                    entry_info['group_mode'] = mode_name
                
                # Protocol info
                if entry.has_proto:
                    entry_info['proto'] = entry.proto
                
                if entry.has_rtprot:
                    entry_info['rtprot'] = entry.rtprot
                
                # Unknown attributes
                if self.capture_unknown_attrs:
                    if entry.unknown_mdba_attrs_count > 0:
                        unknown_list = []
                        for j in range(entry.unknown_mdba_attrs_count):
                            unknown_list.append(entry.unknown_mdba_attrs[j])
                        entry_info['unknown_mdba_attrs'] = unknown_list
                        entry_info['unknown_mdba_attrs_decoded'] = decode_unknown_attrs(
                            unknown_list, 'MDBA'
                        )
                    
                    if entry.unknown_entry_attrs_count > 0:
                        unknown_list = []
                        for j in range(entry.unknown_entry_attrs_count):
                            unknown_list.append(entry.unknown_entry_attrs[j])
                        entry_info['unknown_entry_attrs'] = unknown_list
                        entry_info['unknown_entry_attrs_decoded'] = decode_unknown_attrs(
                            unknown_list, 'MDBA_MDB_EATTR'
                        )
                
                entries.append(entry_info)
            
            lib.nl_free_mdb_entries(entries_array)
            
            # Parse router ports
            routers_ptr = ffi.new("mdb_router_t**")
            routers_count_ptr = ffi.new("int*")
            
            result = lib.nl_parse_mdb_routers(response, routers_ptr, routers_count_ptr)
            if result < 0:
                raise RuntimeError("Failed to parse MDB routers")
            
            routers = []
            routers_count = routers_count_ptr[0]
            routers_array = routers_ptr[0]
            
            for i in range(routers_count):
                router = routers_array[i]
                
                router_info = {
                    'ifindex': router.ifindex,
                    'ifname': self._cache_ifindex_name(router.ifindex),
                }
                
                if router.has_port:
                    router_info['port_ifindex'] = router.port_ifindex
                    router_info['port_ifname'] = self._cache_ifindex_name(router.port_ifindex)
                
                if router.has_router_type:
                    type_name_ptr = lib.nl_get_router_type_name(router.router_type)
                    type_name = ffi.string(type_name_ptr).decode('utf-8')
                    router_info['type'] = type_name
                    router_info['type_value'] = router.router_type
                
                if router.has_timer:
                    router_info['timer'] = router.timer
                    router_info['timer_sec'] = router.timer / 100.0
                
                if router.has_inet_timer:
                    router_info['inet_timer'] = router.inet_timer
                    router_info['inet_timer_sec'] = router.inet_timer / 100.0
                
                if router.has_inet6_timer:
                    router_info['inet6_timer'] = router.inet6_timer
                    router_info['inet6_timer_sec'] = router.inet6_timer / 100.0
                
                if router.has_vid:
                    router_info['vid'] = router.vid
                
                if self.capture_unknown_attrs and router.unknown_rtr_attrs_count > 0:
                    unknown_list = []
                    for j in range(router.unknown_rtr_attrs_count):
                        unknown_list.append(router.unknown_rtr_attrs[j])
                    router_info['unknown_rtr_attrs'] = unknown_list
                    router_info['unknown_rtr_attrs_decoded'] = decode_unknown_attrs(
                        unknown_list, 'MDBA_ROUTER_PATTR'
                    )
                
                routers.append(router_info)
            
            lib.nl_free_mdb_routers(routers_array)
            
            return {
                'entries': entries,
                'routers': routers
            }
        
        finally:
            lib.nl_free_response(response)


# Example usage
def main():
        """Main entry point for the command."""
        import argparse
        import socket
    
        parser = argparse.ArgumentParser(description='Multicast Database Query Tool (IGMP/MLD Snooping)')
        parser.add_argument('--no-unknown-attrs', action='store_true',
                            help='Disable unknown attribute tracking')
        parser.add_argument('--summary', action='store_true',
                            help='Show human-readable summary')
        parser.add_argument('--bridge', type=str,
                            help='Filter by bridge interface name')
        parser.add_argument('--ipv4', action='store_true',
                            help='Show only IPv4 multicast groups')
        parser.add_argument('--ipv6', action='store_true',
                            help='Show only IPv6 multicast groups')
        parser.add_argument('--routers', action='store_true',
                            help='Show only router ports')
        parser.add_argument('--debug', action='store_true',
                            help='Show debug information about parsing')
        args = parser.parse_args()
    
        try:
            print("=" * 70)
            print("RTNetlink Multicast Database Query (MDB)")
            print("=" * 70)
            print(f"Unknown attribute tracking: {'DISABLED' if args.no_unknown_attrs else 'ENABLED'}")
            print()

            # Determine bridge filter
            bridge_ifindex = 0
            if args.bridge:
                try:
                    bridge_ifindex = socket.if_nametoindex(args.bridge)
                except OSError:
                    print(f"Error: Bridge '{args.bridge}' not found", file=sys.stderr)
                    sys.exit(1)
        
            with MDBQuery(capture_unknown_attrs=not args.no_unknown_attrs) as mdbq:
                mdb_data = mdbq.get_mdb(bridge_ifindex=bridge_ifindex)
        
            entries = mdb_data['entries']
            routers = mdb_data['routers']
        
            # Debug output
            if args.debug:
                print(f"\nDEBUG: Parsed {len(entries)} entries, {len(routers)} router ports")
                for i, entry in enumerate(entries):
                    print(f"\nDEBUG Entry {i}:")
                    print(f"  ifindex: {entry.get('ifindex')}")
                    print(f"  family: {entry.get('family')}")
                    print(f"  state: {entry.get('state')} ({entry.get('state_name')})")
                    print(f"  addr_proto: 0x{entry.get('addr_proto', 0):04x}")
                    print(f"  group: {entry.get('group', 'N/A')}")
                    if 'port_ifindex' in entry:
                        print(f"  port_ifindex: {entry['port_ifindex']}")
                    if 'vid' in entry:
                        print(f"  vid: {entry['vid']}")
        
            # Filter by family if requested
            if args.ipv4:
                entries = [e for e in entries if e.get('family') == 'ipv4']
            elif args.ipv6:
                entries = [e for e in entries if e.get('family') == 'ipv6']
        
            if args.summary:
                # Human-readable summary
                if not args.routers:
                    print(f"\nMulticast Group Entries ({len(entries)}):")
                    print("=" * 70)
                
                    # Group by bridge
                    by_bridge = {}
                    for entry in entries:
                        bridge_idx = entry['ifindex']
                        if bridge_idx not in by_bridge:
                            by_bridge[bridge_idx] = []
                        by_bridge[bridge_idx].append(entry)
                
                    for bridge_idx in sorted(by_bridge.keys()):
                        bridge_entries = by_bridge[bridge_idx]
                        # Use cached name from first entry
                        bridge_name = bridge_entries[0].get('ifname', f"if{bridge_idx}")
                    
                        print(f"\nBridge: {bridge_name} ({len(bridge_entries)} groups)")
                        print("-" * 70)
                    
                        # Group by family
                        by_family = {}
                        for entry in bridge_entries:
                            fam = entry.get('family', 'unknown')
                            if fam not in by_family:
                                by_family[fam] = []
                            by_family[fam].append(entry)
                    
                        for fam in sorted(by_family.keys()):
                            fam_entries = by_family[fam]
                            print(f"\n  {fam.upper()} Groups ({len(fam_entries)}):")
                        
                            for entry in fam_entries:
                                group = entry.get('group', 'N/A')
                                state = entry.get('state_name', 'UNKNOWN')
                            
                                # Use cached port name from entry
                                port_name = entry.get('port_ifname', 'N/A')
                            
                                print(f"    {group:40s} on {port_name:15s} [{state}]")
                            
                                # Show VLAN if present
                                if 'vid' in entry:
                                    print(f"      VLAN: {entry['vid']}")
                            
                                # Show timer if present and temporary
                                if 'timer_sec' in entry and 'TEMPORARY' in state:
                                    print(f"      Expires in: {entry['timer_sec']:.1f}s")
                            
                                # Show group mode if present
                                if 'group_mode' in entry:
                                    print(f"      Mode: {entry['group_mode']}")
            
                # Router ports
                if args.routers or len(entries) == 0:
                    print(f"\nRouter Ports ({len(routers)}):")
                    print("=" * 70)
                
                    if routers:
                        for router in routers:
                            # Use cached names from router dictionary
                            bridge_name = router.get('ifname', f"if{router['ifindex']}")
                            port_name = router.get('port_ifname', 'N/A')
                        
                            router_type = router.get('type', 'UNKNOWN')
                        
                            print(f"\n  Bridge: {bridge_name}")
                            print(f"    Port: {port_name}")
                            print(f"    Type: {router_type}")
                        
                            if 'vid' in router:
                                print(f"    VLAN: {router['vid']}")
                        
                            if 'timer_sec' in router:
                                print(f"    Timer: {router['timer_sec']:.1f}s")
                        
                            if 'inet_timer_sec' in router:
                                print(f"    IPv4 Timer: {router['inet_timer_sec']:.1f}s")
                        
                            if 'inet6_timer_sec' in router:
                                print(f"    IPv6 Timer: {router['inet6_timer_sec']:.1f}s")
                    else:
                        print("\n  No router ports found")
            else:
                # Full JSON output
                print(json.dumps(mdb_data, indent=2))
        
            print()
            print("=" * 70)
            print(f"✓ Query complete! Found {len(entries)} entries, {len(routers)} router ports")
            print("=" * 70)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == '__main__':
    main()
