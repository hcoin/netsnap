#!/usr/bin/env python3
"""
RTNetlink Neighbor Table Query with C Library via CFFI
Complete ARP/NDP neighbor table inspection including:
- IPv4 ARP cache entries
- IPv6 Neighbor Discovery (NDP) cache
- Bridge FDB (Forwarding Database) entries
- All neighbor states (REACHABLE, STALE, DELAY, PROBE, FAILED, etc.)
- Hardware addresses and interface mappings
- Proxy entries and router flags
- Extension attributes (used, confirmed, updated timestamps)
- Hardware type decoding (ETHER, LOOPBACK, TUNNEL, etc.)

Neighbor States Explained:
- INCOMPLETE: Address resolution in progress
- REACHABLE: Valid, recently confirmed entry
- STALE: Valid but needs revalidation
- DELAY: Waiting to send probe
- PROBE: Sending probes to revalidate
- FAILED: Resolution failed
- PERMANENT: Static entry, never expires
- NOARP: No neighbor resolution needed (loopback, p2p links, static entries)
  Note: IPv6 normally uses NDP (not NOARP). NOARP appears for special cases.

Requirements:
    - Python 3.8+
    - cffi>=1.0.0
    - setuptools (required for Python 3.12+)

Install:
    pip install cffi setuptools

Usage:
    sudo python3 neighsnapshotter.py                    # Full JSON output
    sudo python3 neighsnapshotter.py --summary          # Human-readable summary
    sudo python3 neighsnapshotter.py --arp              # IPv4 ARP only
    sudo python3 neighsnapshotter.py --ndp              # IPv6 NDP only
    sudo python3 neighsnapshotter.py --bridge           # Bridge FDB only
    sudo python3 neighsnapshotter.py --interface eth0   # Filter by interface
"""

from cffi import FFI
import json
import sys
#import os
import ipaddress
from typing import Dict, List, Any, Optional

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

# C library source code - RTM_GETNEIGH support
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
#if !defined(NETLINK_ROUTE) || !defined(RTM_GETNEIGH)
#error "Kernel headers too old - need Linux 2.6+ with rtnetlink support"
#endif

// Response buffer structure
typedef struct {
    unsigned char* data;
    size_t length;
    size_t capacity;
    unsigned int seq;
} response_buffer_t;

// Neighbor cache information
typedef struct {
    unsigned char cacheinfo_confirmed;
    unsigned char cacheinfo_used;
    unsigned char cacheinfo_updated;
    unsigned char cacheinfo_refcnt;
    int has_cacheinfo_confirmed;
    int has_cacheinfo_used;
    int has_cacheinfo_updated;
    int has_cacheinfo_refcnt;
} neigh_cacheinfo_t;

// Neighbor entry information
typedef struct {
    int ifindex;
    unsigned char family;
    unsigned char state;
    unsigned char flags;
    unsigned char type;
    unsigned char dst_addr[16];    // IPv4 or IPv6 destination
    unsigned char lladdr[32];      // Link-layer address (MAC)
    int has_dst_addr;
    int has_lladdr;
    int lladdr_len;
    unsigned int probes;
    int has_probes;
    unsigned short vlan;
    int has_vlan;
    unsigned int master;
    int has_master;
    neigh_cacheinfo_t cacheinfo;
    unsigned short unknown_nda_attrs[64];
    int unknown_nda_attrs_count;
} neigh_entry_t;

// NDA_* Attribute definitions (for older kernels)
#ifndef NDA_DST
#define NDA_DST 1
#define NDA_LLADDR 2
#define NDA_CACHEINFO 3
#define NDA_PROBES 4
#define NDA_VLAN 5
#define NDA_PORT 6
#define NDA_VNI 7
#define NDA_IFINDEX 8
#define NDA_MASTER 9
#define NDA_LINK_NETNSID 10
#define NDA_SRC_VNI 11
#define NDA_PROTOCOL 12
#define NDA_NH_ID 13
#define NDA_FDB_EXT_ATTRS 14
#define NDA_FLAGS_EXT 15
#define NDA_NDM_STATE_MASK 16
#define NDA_NDM_FLAGS_MASK 17
#endif

// Neighbor states
#ifndef NUD_INCOMPLETE
#define NUD_INCOMPLETE  0x01
#define NUD_REACHABLE   0x02
#define NUD_STALE       0x04
#define NUD_DELAY       0x08
#define NUD_PROBE       0x10
#define NUD_FAILED      0x20
#define NUD_NOARP       0x40
#define NUD_PERMANENT   0x80
#define NUD_NONE        0x00
#endif

// Neighbor flags
#ifndef NTF_USE
#define NTF_USE         0x01
#define NTF_SELF        0x02
#define NTF_MASTER      0x04
#define NTF_PROXY       0x08
#define NTF_EXT_LEARNED 0x10
#define NTF_OFFLOADED   0x20
#define NTF_STICKY      0x40
#define NTF_ROUTER      0x80
#endif

// Hardware types (from if_arp.h)
#ifndef ARPHRD_NETROM
#define ARPHRD_NETROM   0
#define ARPHRD_ETHER    1
#define ARPHRD_LOOPBACK 772
#define ARPHRD_VOID     0xFFFF
#define ARPHRD_NONE     0xFFFE
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

// Send RTM_GETNEIGH request
int nl_send_getneigh(int sock, unsigned int* seq_out, int family) {
    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
    } req;
    
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = nl_generate_seq();
    req.nlh.nlmsg_pid = 0;
    req.ndm.ndm_family = family;  // AF_UNSPEC for all, AF_INET, AF_INET6, AF_BRIDGE
    
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

// Parse neighbor entries
int nl_parse_neighbors(response_buffer_t* buf, neigh_entry_t** neighbors, int* count) {
    if (!buf || !neighbors || !count) return -1;
    
    *count = 0;
    *neighbors = NULL;
    
    if (buf->length == 0) {
        return -1;
    }
    
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf->data;
    int max_count = 0;
    size_t remaining = buf->length;
    
    // Count entries
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        if (nlh->nlmsg_type == RTM_NEWNEIGH) {
            max_count++;
        }
    }
    
    if (max_count == 0) return 0;
    
    *neighbors = calloc(max_count, sizeof(neigh_entry_t));
    if (!*neighbors) {
        return -1;
    }
    
    nlh = (struct nlmsghdr*)buf->data;
    remaining = buf->length;
    
    static const unsigned short known_nda_attrs[] = {
        NDA_DST, NDA_LLADDR, NDA_CACHEINFO, NDA_PROBES, NDA_VLAN,
        NDA_PORT, NDA_VNI, NDA_IFINDEX, NDA_MASTER, NDA_LINK_NETNSID,
        NDA_SRC_VNI, NDA_PROTOCOL, NDA_NH_ID, NDA_FDB_EXT_ATTRS,
        NDA_FLAGS_EXT, NDA_NDM_STATE_MASK, NDA_NDM_FLAGS_MASK
    };
    static const int known_nda_count = sizeof(known_nda_attrs) / sizeof(known_nda_attrs[0]);
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type != RTM_NEWNEIGH) continue;
        
        struct ndmsg* ndm = NLMSG_DATA(nlh);
        neigh_entry_t* entry = &(*neighbors)[*count];
        
        entry->ifindex = ndm->ndm_ifindex;
        entry->family = ndm->ndm_family;
        entry->state = ndm->ndm_state;
        entry->flags = ndm->ndm_flags;
        entry->type = ndm->ndm_type;
        entry->has_dst_addr = 0;
        entry->has_lladdr = 0;
        entry->lladdr_len = 0;
        entry->has_probes = 0;
        entry->has_vlan = 0;
        entry->has_master = 0;
        entry->unknown_nda_attrs_count = 0;
        memset(&entry->cacheinfo, 0, sizeof(neigh_cacheinfo_t));
        
        struct rtattr* rta = (struct rtattr*)((char*)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
        int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
        
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            track_unknown_attr(entry->unknown_nda_attrs,
                              &entry->unknown_nda_attrs_count,
                              64, rta->rta_type, known_nda_attrs, known_nda_count);
            
            switch (rta->rta_type) {
                case NDA_DST:
                    if (RTA_PAYLOAD(rta) > 0 && RTA_PAYLOAD(rta) <= 16) {
                        memcpy(entry->dst_addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        entry->has_dst_addr = 1;
                    }
                    break;
                    
                case NDA_LLADDR:
                    if (RTA_PAYLOAD(rta) > 0 && RTA_PAYLOAD(rta) <= 32) {
                        memcpy(entry->lladdr, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        entry->lladdr_len = RTA_PAYLOAD(rta);
                        entry->has_lladdr = 1;
                    }
                    break;
                    
                case NDA_CACHEINFO: {
                    if (RTA_PAYLOAD(rta) >= 16) {
                        unsigned int* cache = (unsigned int*)RTA_DATA(rta);
                        // struct nda_cacheinfo has: confirmed, used, updated, refcnt
                        entry->cacheinfo.cacheinfo_confirmed = cache[0];
                        entry->cacheinfo.cacheinfo_used = cache[1];
                        entry->cacheinfo.cacheinfo_updated = cache[2];
                        entry->cacheinfo.cacheinfo_refcnt = cache[3];
                        entry->cacheinfo.has_cacheinfo_confirmed = 1;
                        entry->cacheinfo.has_cacheinfo_used = 1;
                        entry->cacheinfo.has_cacheinfo_updated = 1;
                        entry->cacheinfo.has_cacheinfo_refcnt = 1;
                    }
                    break;
                }
                    
                case NDA_PROBES:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        entry->probes = *(unsigned int*)RTA_DATA(rta);
                        entry->has_probes = 1;
                    }
                    break;
                    
                case NDA_VLAN:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned short)) {
                        entry->vlan = *(unsigned short*)RTA_DATA(rta);
                        entry->has_vlan = 1;
                    }
                    break;
                    
                case NDA_MASTER:
                    if (RTA_PAYLOAD(rta) >= sizeof(unsigned int)) {
                        entry->master = *(unsigned int*)RTA_DATA(rta);
                        entry->has_master = 1;
                    }
                    break;
            }
        }
        
        (*count)++;
    }
    
    return 0;
}

void nl_free_neighbors(neigh_entry_t* neighbors) {
    if (neighbors) free(neighbors);
}

// Helper functions to get string representations
int nl_get_af_inet(void) { return AF_INET; }
int nl_get_af_inet6(void) { return AF_INET6; }
int nl_get_af_bridge(void) { return AF_BRIDGE; }

const char* nl_get_neigh_state_name(unsigned char state) {
    // Can have multiple states set
    // Note: NUD_NOARP indicates entry doesn't use neighbor resolution (ARP/NDP)
    // For IPv6: NOARP can appear for loopback, static entries, or point-to-point links,
    // but most IPv6 entries use NDP and will be REACHABLE/STALE/DELAY/PROBE
    static char buf[256];
    buf[0] = '\0';
    int first = 1;
    
    if (state == NUD_NONE) {
        return "NONE";
    }
    
    if (state & NUD_INCOMPLETE) {
        if (!first) strcat(buf, "|");
        strcat(buf, "INCOMPLETE");
        first = 0;
    }
    if (state & NUD_REACHABLE) {
        if (!first) strcat(buf, "|");
        strcat(buf, "REACHABLE");
        first = 0;
    }
    if (state & NUD_STALE) {
        if (!first) strcat(buf, "|");
        strcat(buf, "STALE");
        first = 0;
    }
    if (state & NUD_DELAY) {
        if (!first) strcat(buf, "|");
        strcat(buf, "DELAY");
        first = 0;
    }
    if (state & NUD_PROBE) {
        if (!first) strcat(buf, "|");
        strcat(buf, "PROBE");
        first = 0;
    }
    if (state & NUD_FAILED) {
        if (!first) strcat(buf, "|");
        strcat(buf, "FAILED");
        first = 0;
    }
    if (state & NUD_NOARP) {
        if (!first) strcat(buf, "|");
        strcat(buf, "NOARP");
        first = 0;
    }
    if (state & NUD_PERMANENT) {
        if (!first) strcat(buf, "|");
        strcat(buf, "PERMANENT");
        first = 0;
    }
    
    return buf[0] ? buf : "UNKNOWN";
}

const char* nl_get_neigh_flag_name(unsigned char flags, int index) {
    static const char* flag_names[] = {
        "USE", "SELF", "MASTER", "PROXY", "EXT_LEARNED", "OFFLOADED", "STICKY", "ROUTER"
    };
    static const unsigned char flag_values[] = {
        NTF_USE, NTF_SELF, NTF_MASTER, NTF_PROXY, NTF_EXT_LEARNED, NTF_OFFLOADED, NTF_STICKY, NTF_ROUTER
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

const char* nl_get_hw_type_name(unsigned short type) {
    switch (type) {
        case 0: return "NETROM";
        case 1: return "ETHER";
        case 6: return "IEEE802";
        case 8: return "ARCNET";
        case 15: return "DLCI";
        case 19: return "ATM";
        case 23: return "METRICOM";
        case 24: return "IEEE1394";
        case 27: return "EUI64";
        case 32: return "INFINIBAND";
        case 256: return "SLIP";
        case 257: return "CSLIP";
        case 258: return "SLIP6";
        case 259: return "CSLIP6";
        case 260: return "RSRVD";
        case 264: return "ADAPT";
        case 270: return "ROSE";
        case 271: return "X25";
        case 272: return "HWX25";
        case 280: return "CAN";
        case 512: return "PPP";
        case 513: return "CISCO";
        case 516: return "LAPB";
        case 517: return "DDCMP";
        case 518: return "RAWHDLC";
        case 519: return "RAWIP";
        case 768: return "TUNNEL";
        case 769: return "TUNNEL6";
        case 770: return "FRAD";
        case 771: return "SKIP";
        case 772: return "LOOPBACK";
        case 773: return "LOCALTLK";
        case 774: return "FDDI";
        case 775: return "BIF";
        case 776: return "SIT";
        case 777: return "IPDDP";
        case 778: return "IPGRE";
        case 779: return "PIMREG";
        case 780: return "HIPPI";
        case 781: return "ASH";
        case 782: return "ECONET";
        case 783: return "IRDA";
        case 784: return "FCPP";
        case 785: return "FCAL";
        case 786: return "FCPL";
        case 787: return "FCFABRIC";
        case 800: return "IEEE802_TR";
        case 801: return "IEEE80211";
        case 802: return "IEEE80211_PRISM";
        case 803: return "IEEE80211_RADIOTAP";
        case 804: return "IEEE802154";
        case 805: return "IEEE802154_MONITOR";
        case 820: return "PHONET";
        case 821: return "PHONET_PIPE";
        case 822: return "CAIF";
        case 823: return "IP6GRE";
        case 824: return "NETLINK";
        case 825: return "6LOWPAN";
        case 826: return "VSOCKMON";
        case 0xFFFE: return "NONE";
        case 0xFFFF: return "VOID";
        default: return NULL;
    }
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
        unsigned char cacheinfo_confirmed;
        unsigned char cacheinfo_used;
        unsigned char cacheinfo_updated;
        unsigned char cacheinfo_refcnt;
        int has_cacheinfo_confirmed;
        int has_cacheinfo_used;
        int has_cacheinfo_updated;
        int has_cacheinfo_refcnt;
    } neigh_cacheinfo_t;

    typedef struct {
        int ifindex;
        unsigned char family;
        unsigned char state;
        unsigned char flags;
        unsigned char type;
        unsigned char dst_addr[16];
        unsigned char lladdr[32];
        int has_dst_addr;
        int has_lladdr;
        int lladdr_len;
        unsigned int probes;
        int has_probes;
        unsigned short vlan;
        int has_vlan;
        unsigned int master;
        int has_master;
        neigh_cacheinfo_t cacheinfo;
        unsigned short unknown_nda_attrs[64];
        int unknown_nda_attrs_count;
    } neigh_entry_t;

    int nl_create_socket(void);
    void nl_close_socket(int sock);
    int nl_send_getneigh(int sock, unsigned int* seq_out, int family);
    response_buffer_t* nl_recv_response(int sock, unsigned int expected_seq);
    void nl_free_response(response_buffer_t* buf);
    int nl_parse_neighbors(response_buffer_t* buf, neigh_entry_t** neighbors, int* count);
    void nl_free_neighbors(neigh_entry_t* neighbors);
    int nl_get_af_inet(void);
    int nl_get_af_inet6(void);
    int nl_get_af_bridge(void);
    const char* nl_get_neigh_state_name(unsigned char state);
    const char* nl_get_neigh_flag_name(unsigned char flags, int index);
    const char* nl_get_hw_type_name(unsigned short type);
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
AF_BRIDGE = lib.nl_get_af_bridge()

# NDA_* Attribute Name Mapping
NDA_ATTR_NAMES = {
    0: 'NDA_UNSPEC', 1: 'NDA_DST', 2: 'NDA_LLADDR', 3: 'NDA_CACHEINFO',
    4: 'NDA_PROBES', 5: 'NDA_VLAN', 6: 'NDA_PORT', 7: 'NDA_VNI',
    8: 'NDA_IFINDEX', 9: 'NDA_MASTER', 10: 'NDA_LINK_NETNSID', 11: 'NDA_SRC_VNI',
    12: 'NDA_PROTOCOL', 13: 'NDA_NH_ID', 14: 'NDA_FDB_EXT_ATTRS', 15: 'NDA_FLAGS_EXT',
    16: 'NDA_NDM_STATE_MASK', 17: 'NDA_NDM_FLAGS_MASK',
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
        
        if base_num in NDA_ATTR_NAMES:
            info['name'] = NDA_ATTR_NAMES[base_num]
            if is_nested:
                info['name'] += ' (nested)'
        else:
            info['name'] = f'NDA_{base_num}'
        
        decoded.append(info)
    
    return decoded


class NeighborTableQuery:
    """
    Query neighbor table information using RTNETLINK protocol via C library.
    Supports ARP (IPv4), NDP (IPv6), and bridge FDB entries.
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
    
    def get_neighbors(self, family: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Query neighbor table entries.
        
        Args:
            family: Optional filter - 'ipv4', 'ipv6', 'bridge', or None for all
        
        Returns:
            List of neighbor entries with full metadata
        """
        # Map family string to AF constant
        family_map = {
            'ipv4': AF_INET,
            'ipv6': AF_INET6,
            'bridge': AF_BRIDGE,
            None: 0,  # AF_UNSPEC
        }
        
        if family not in family_map:
            raise ValueError(f"Invalid family: {family}. Must be 'ipv4', 'ipv6', 'bridge', or None")
        
        af_family = family_map[family]
        
        seq_ptr = ffi.new("unsigned int*")
        
        if lib.nl_send_getneigh(self.sock, seq_ptr, af_family) < 0:
            raise RuntimeError("Failed to send RTM_GETNEIGH request")
        
        seq = seq_ptr[0]
        response = lib.nl_recv_response(self.sock, seq)
        if not response:
            raise RuntimeError("Failed to receive response for RTM_GETNEIGH")
        
        try:
            neighbors_ptr = ffi.new("neigh_entry_t**")
            count_ptr = ffi.new("int*")
            
            result = lib.nl_parse_neighbors(response, neighbors_ptr, count_ptr)
            if result < 0:
                raise RuntimeError("Failed to parse neighbor messages")
            
            neighbors = []
            count = count_ptr[0]
            neighbors_array = neighbors_ptr[0]
            
            for i in range(count):
                entry = neighbors_array[i]
                
                # Determine family name
                if entry.family == AF_INET:
                    family_name = 'ipv4'
                elif entry.family == AF_INET6:
                    family_name = 'ipv6'
                elif entry.family == AF_BRIDGE:
                    family_name = 'bridge'
                else:
                    family_name = f'af_{entry.family}'
                
                # Get state name
                state_name_ptr = lib.nl_get_neigh_state_name(entry.state)
                state_name = ffi.string(state_name_ptr).decode('utf-8')
                
                # Get flag names
                flag_names = []
                idx = 0
                while True:
                    flag_name = lib.nl_get_neigh_flag_name(entry.flags, idx)
                    if not flag_name:
                        break
                    flag_names.append(ffi.string(flag_name).decode('utf-8'))
                    idx += 1
                
                # Get hardware type name
                hw_type_ptr = lib.nl_get_hw_type_name(entry.type)
                if hw_type_ptr:
                    hw_type_name = ffi.string(hw_type_ptr).decode('utf-8')
                else:
                    hw_type_name = f'type_{entry.type}'
                
                neigh_info = {
                    'ifindex': entry.ifindex,
                    'family': family_name,
                    'state': entry.state,
                    'state_name': state_name,
                    'flags': entry.flags,
                    'flag_names': flag_names,
                    'type': entry.type,
                    'type_name': hw_type_name,
                }
                
                # Decode destination address
                if entry.has_dst_addr:
                    if entry.family == AF_INET:
                        dst_bytes = bytes(entry.dst_addr[0:4])
                        dst_str = '.'.join(str(b) for b in dst_bytes)
                        neigh_info['dst'] = dst_str
                        
                        try:
                            ipv4_addr = ipaddress.IPv4Address(dst_bytes)
                            neigh_info['dst_canonical'] = str(ipv4_addr)
                        except ValueError:
                            pass
                    elif entry.family == AF_INET6:
                        dst_bytes = bytes(entry.dst_addr[0:16])
                        try:
                            ipv6_addr = ipaddress.IPv6Address(dst_bytes)
                            neigh_info['dst'] = str(ipv6_addr)
                        except ValueError:
                            neigh_info['dst'] = dst_bytes.hex()
                    elif entry.family == AF_BRIDGE:
                        # Bridge FDB entry - dst is MAC address
                        if entry.has_lladdr and entry.lladdr_len == 6:
                            # For bridge, the "destination" is often in lladdr
                            pass
                        else:
                            # Sometimes dst contains MAC for bridge entries
                            dst_bytes = bytes(entry.dst_addr[0:6])
                            neigh_info['dst'] = ':'.join(f'{b:02x}' for b in dst_bytes)
                
                # Decode link-layer address (MAC address)
                if entry.has_lladdr:
                    if entry.lladdr_len == 6:
                        # Standard Ethernet MAC
                        mac = ':'.join(f'{entry.lladdr[j]:02x}' for j in range(6))
                        neigh_info['lladdr'] = mac
                    elif entry.lladdr_len == 4:
                        # IPv4 address (for some proxy entries)
                        lladdr_bytes = bytes(entry.lladdr[0:4])
                        neigh_info['lladdr'] = '.'.join(str(b) for b in lladdr_bytes)
                    else:
                        # Other address types
                        lladdr_bytes = bytes(entry.lladdr[0:entry.lladdr_len])
                        neigh_info['lladdr'] = lladdr_bytes.hex()
                        neigh_info['lladdr_len'] = entry.lladdr_len
                
                # Additional attributes
                if entry.has_probes:
                    neigh_info['probes'] = entry.probes
                
                if entry.has_vlan:
                    neigh_info['vlan'] = entry.vlan
                
                if entry.has_master:
                    neigh_info['master'] = entry.master
                
                # Cache info
                if (entry.cacheinfo.has_cacheinfo_confirmed or 
                    entry.cacheinfo.has_cacheinfo_used or 
                    entry.cacheinfo.has_cacheinfo_updated):
                    cacheinfo = {}
                    
                    if entry.cacheinfo.has_cacheinfo_confirmed:
                        cacheinfo['confirmed'] = entry.cacheinfo.cacheinfo_confirmed
                    if entry.cacheinfo.has_cacheinfo_used:
                        cacheinfo['used'] = entry.cacheinfo.cacheinfo_used
                    if entry.cacheinfo.has_cacheinfo_updated:
                        cacheinfo['updated'] = entry.cacheinfo.cacheinfo_updated
                    if entry.cacheinfo.has_cacheinfo_refcnt:
                        cacheinfo['refcnt'] = entry.cacheinfo.cacheinfo_refcnt
                    
                    neigh_info['cacheinfo'] = cacheinfo
                
                # Unknown attributes
                if self.capture_unknown_attrs and entry.unknown_nda_attrs_count > 0:
                    unknown_list = []
                    for j in range(entry.unknown_nda_attrs_count):
                        unknown_list.append(entry.unknown_nda_attrs[j])
                    neigh_info['unknown_nda_attrs'] = unknown_list
                    neigh_info['unknown_nda_attrs_decoded'] = decode_unknown_attrs(unknown_list)
                
                neighbors.append(neigh_info)
            
            lib.nl_free_neighbors(neighbors_array)
            return neighbors
        
        finally:
            lib.nl_free_response(response)


# Example usage
def main():
        """Main entry point for the command."""
        import argparse
    
        parser = argparse.ArgumentParser(description='Neighbor Table Query Tool (ARP/NDP/FDB)')
        parser.add_argument('--no-unknown-attrs', action='store_true',
                            help='Disable unknown attribute tracking')
        parser.add_argument('--summary', action='store_true',
                            help='Show human-readable summary')
        parser.add_argument('--arp', action='store_true',
                            help='Show only IPv4 ARP entries')
        parser.add_argument('--ndp', action='store_true',
                            help='Show only IPv6 NDP entries')
        parser.add_argument('--bridge', action='store_true',
                            help='Show only bridge FDB entries')
        parser.add_argument('--interface', type=str,
                            help='Filter by interface name')
        args = parser.parse_args()
    
        try:
            print("=" * 70)
            print("RTNetlink Neighbor Table Query (ARP/NDP/FDB)")
            print("=" * 70)
            print(f"Unknown attribute tracking: {'DISABLED' if args.no_unknown_attrs else 'ENABLED'}")
            print()

            # Determine family filter
            family = None
            if args.arp:
                family = 'ipv4'
            elif args.ndp:
                family = 'ipv6'
            elif args.bridge:
                family = 'bridge'
        
            with NeighborTableQuery(capture_unknown_attrs=not args.no_unknown_attrs) as ntq:
                neighbors = ntq.get_neighbors(family=family)
        
            # Filter by interface if requested
            if args.interface:
                # Need to resolve interface name to index
                import socket
                try:
                    if_index = socket.if_nametoindex(args.interface)
                    neighbors = [n for n in neighbors if n['ifindex'] == if_index]
                except OSError:
                    print(f"Warning: Interface '{args.interface}' not found", file=sys.stderr)
                    neighbors = []
        
            if args.summary:
                # Human-readable summary
                print(f"\nFound {len(neighbors)} neighbor entries:")
                print("=" * 70)
            
                # Group by family
                by_family = {}
                for entry in neighbors:
                    fam = entry['family']
                    if fam not in by_family:
                        by_family[fam] = []
                    by_family[fam].append(entry)
            
                for fam in sorted(by_family.keys()):
                    entries = by_family[fam]
                    print(f"\n{fam.upper()} Entries ({len(entries)}):")
                    print("-" * 70)
                
                    for entry in entries:
                        # Resolve interface name
                        try:
                            #import socket
                            if_name = socket.if_indextoname(entry['ifindex'])
                        except OSError:
                            if_name = f"if{entry['ifindex']}"
                    
                        dst = entry.get('dst', 'N/A')
                        lladdr = entry.get('lladdr', 'N/A')
                        state = entry['state_name']
                        hw_type = entry.get('type_name', 'unknown')
                    
                        print(f"  {dst:40s} -> {lladdr:17s}  [{state:20s}] on {if_name}")
                        print(f"    Type: {hw_type}")
                    
                        # Show flags if present
                        if entry['flag_names']:
                            print(f"    Flags: {', '.join(entry['flag_names'])}")
                    
                        # Show VLAN if present
                        if 'vlan' in entry:
                            print(f"    VLAN: {entry['vlan']}")
                    
                        # Show cache info if interesting
                        if 'cacheinfo' in entry:
                            cache = entry['cacheinfo']
                            if 'used' in cache and cache['used'] < 60:
                                print(f"    Last used: {cache['used']}s ago")
            else:
                # Full JSON output
                print(json.dumps(neighbors, indent=2))
        
            print()
            print("=" * 70)
            print(f"✓ Query complete! Found {len(neighbors)} entries.")
            print("=" * 70)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == '__main__':
    main()
