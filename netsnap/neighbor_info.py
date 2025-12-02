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
    sudo python3 neighbor_info.py                    # Full JSON output
    sudo python3 neighbor_info.py --summary          # Human-readable summary
    sudo python3 neighbor_info.py --arp              # IPv4 ARP only
    sudo python3 neighbor_info.py --ndp              # IPv6 NDP only
    sudo python3 neighbor_info.py --bridge           # Bridge FDB only
    sudo python3 neighbor_info.py -d eth0            # Filter by device/interface
    sudo python3 neighbor_info.py --device wlan0     # Filter by device name
"""

from cffi import FFI
import json
import sys
#import socket
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

# C library source code - RTM_GETNEIGH support with ifname lookup
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
    char ifname[IFNAMSIZ];     // Interface name (NEW - looked up in C)
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
    
    unsigned int seq = nl_generate_seq();
    if (seq_out) *seq_out = seq;
    
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = seq;
    req.nlh.nlmsg_pid = 0;
    
    req.ndm.ndm_family = family;
    req.ndm.ndm_state = 0xFF;
    
    ssize_t sent = send(sock, &req, req.nlh.nlmsg_len, 0);
    return (sent == req.nlh.nlmsg_len) ? 0 : -1;
}

// Receive netlink response
response_buffer_t* nl_recv_response(int sock, unsigned int expected_seq) {
    response_buffer_t* resp = calloc(1, sizeof(response_buffer_t));
    if (!resp) return NULL;
    
    resp->capacity = 8192;
    resp->data = malloc(resp->capacity);
    resp->seq = expected_seq;
    if (!resp->data) {
        free(resp);
        return NULL;
    }
    
    int done = 0;
    while (!done) {
        unsigned char buf[8192];
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        
        if (len < 0) {
            if (errno == EINTR) continue;
            free(resp->data);
            free(resp);
            return NULL;
        }
        
        if (len == 0) break;
        
        // Expand buffer if needed
        if (resp->length + len > resp->capacity) {
            size_t new_capacity = resp->capacity * 2;
            while (new_capacity < resp->length + len) {
                new_capacity *= 2;
            }
            unsigned char* new_data = realloc(resp->data, new_capacity);
            if (!new_data) {
                free(resp->data);
                free(resp);
                return NULL;
            }
            resp->data = new_data;
            resp->capacity = new_capacity;
        }
        
        memcpy(resp->data + resp->length, buf, len);
        resp->length += len;
        
        // Check for NLMSG_DONE
        struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_seq != expected_seq) continue;
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                free(resp->data);
                free(resp);
                return NULL;
            }
        }
    }
    
    return resp;
}

void nl_free_response(response_buffer_t* resp) {
    if (resp) {
        if (resp->data) free(resp->data);
        free(resp);
    }
}

// Parse neighbor entries from response
neigh_entry_t* nl_parse_neighbors(response_buffer_t* resp, int* count_out, int capture_unknown) {
    if (!resp || !count_out) return NULL;
    
    *count_out = 0;
    
    // Count entries first
    int count = 0;
    struct nlmsghdr* nlh = (struct nlmsghdr*)resp->data;
    size_t remaining = resp->length;
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_seq != resp->seq) continue;
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) break;
        if (nlh->nlmsg_type == RTM_NEWNEIGH) count++;
    }
    
    if (count == 0) return NULL;
    
    // Allocate array
    neigh_entry_t* entries = calloc(count, sizeof(neigh_entry_t));
    if (!entries) return NULL;
    
    // Parse entries
    int idx = 0;
    nlh = (struct nlmsghdr*)resp->data;
    remaining = resp->length;
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_seq != resp->seq) continue;
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) break;
        if (nlh->nlmsg_type != RTM_NEWNEIGH) continue;
        
        struct ndmsg* ndm = NLMSG_DATA(nlh);
        neigh_entry_t* entry = &entries[idx];
        
        // Basic info from ndmsg
        entry->ifindex = ndm->ndm_ifindex;
        entry->family = ndm->ndm_family;
        entry->state = ndm->ndm_state;
        entry->flags = ndm->ndm_flags;
        entry->type = ndm->ndm_type;
        
        // Lookup interface name in C (NEW!)
        if (if_indextoname(entry->ifindex, entry->ifname) == NULL) {
            // If lookup fails, use fallback format
            snprintf(entry->ifname, IFNAMSIZ, "if%d", entry->ifindex);
        }
        
        // Parse attributes
        struct rtattr* rta = (struct rtattr*)((char*)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
        int rtalen = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct ndmsg));
        
        for (; RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
            switch (rta->rta_type) {
                case NDA_DST:
                    entry->has_dst_addr = 1;
                    memcpy(entry->dst_addr, RTA_DATA(rta), 
                           (RTA_PAYLOAD(rta) < 16) ? RTA_PAYLOAD(rta) : 16);
                    break;
                    
                case NDA_LLADDR:
                    entry->has_lladdr = 1;
                    entry->lladdr_len = RTA_PAYLOAD(rta);
                    if (entry->lladdr_len > 32) entry->lladdr_len = 32;
                    memcpy(entry->lladdr, RTA_DATA(rta), entry->lladdr_len);
                    break;
                    
                case NDA_CACHEINFO: {
                    struct nda_cacheinfo* ci = RTA_DATA(rta);
                    entry->cacheinfo.cacheinfo_confirmed = ci->ndm_confirmed;
                    entry->cacheinfo.cacheinfo_used = ci->ndm_used;
                    entry->cacheinfo.cacheinfo_updated = ci->ndm_updated;
                    entry->cacheinfo.cacheinfo_refcnt = ci->ndm_refcnt;
                    entry->cacheinfo.has_cacheinfo_confirmed = 1;
                    entry->cacheinfo.has_cacheinfo_used = 1;
                    entry->cacheinfo.has_cacheinfo_updated = 1;
                    entry->cacheinfo.has_cacheinfo_refcnt = 1;
                    break;
                }
                    
                case NDA_PROBES:
                    entry->has_probes = 1;
                    entry->probes = *(unsigned int*)RTA_DATA(rta);
                    break;
                    
                case NDA_VLAN:
                    entry->has_vlan = 1;
                    entry->vlan = *(unsigned short*)RTA_DATA(rta);
                    break;
                    
                case NDA_MASTER:
                    entry->has_master = 1;
                    entry->master = *(unsigned int*)RTA_DATA(rta);
                    break;
                    
                default:
                    // Unknown attribute
                    if (capture_unknown && 
                        entry->unknown_nda_attrs_count < 64) {
                        entry->unknown_nda_attrs[entry->unknown_nda_attrs_count++] = 
                            rta->rta_type;
                    }
                    break;
            }
        }
        
        idx++;
    }
    
    *count_out = idx;
    return entries;
}

void nl_free_neighbors(neigh_entry_t* entries) {
    if (entries) free(entries);
}

// Get neighbor count from response
int nl_get_neighbor_count(response_buffer_t* resp) {
    if (!resp) return 0;
    
    int count = 0;
    struct nlmsghdr* nlh = (struct nlmsghdr*)resp->data;
    size_t remaining = resp->length;
    
    for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_seq != resp->seq) continue;
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) break;
        if (nlh->nlmsg_type == RTM_NEWNEIGH) count++;
    }
    
    return count;
}
"""

# FFI C definitions
ffi = FFI()
ffi.cdef("""
    // Socket operations
    int nl_create_socket(void);
    void nl_close_socket(int sock);
    
    // Request/Response
    int nl_send_getneigh(int sock, unsigned int* seq_out, int family);
    
    typedef struct {
        unsigned char* data;
        size_t length;
        size_t capacity;
        unsigned int seq;
    } response_buffer_t;
    
    response_buffer_t* nl_recv_response(int sock, unsigned int expected_seq);
    void nl_free_response(response_buffer_t* resp);
    int nl_get_neighbor_count(response_buffer_t* resp);
    
    // Neighbor cache info
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
    
    // Neighbor entry (with ifname!)
    typedef struct {
        int ifindex;
        char ifname[16];
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
    
    neigh_entry_t* nl_parse_neighbors(response_buffer_t* resp, int* count_out, int capture_unknown);
    void nl_free_neighbors(neigh_entry_t* entries);
""")

# Compile C library
lib = ffi.verify(C_SOURCE, extra_compile_args=['-std=c99'])


# Constants
AF_INET = 2
AF_INET6 = 10
AF_BRIDGE = 7
AF_UNSPEC = 0

# Neighbor states
NUD_INCOMPLETE = 0x01
NUD_REACHABLE = 0x02
NUD_STALE = 0x04
NUD_DELAY = 0x08
NUD_PROBE = 0x10
NUD_FAILED = 0x20
NUD_NOARP = 0x40
NUD_PERMANENT = 0x80
NUD_NONE = 0x00

# Neighbor flags
NTF_USE = 0x01
NTF_SELF = 0x02
NTF_MASTER = 0x04
NTF_PROXY = 0x08
NTF_EXT_LEARNED = 0x10
NTF_OFFLOADED = 0x20
NTF_STICKY = 0x40
NTF_ROUTER = 0x80

# Hardware types
ARPHRD_NETROM = 0
ARPHRD_ETHER = 1
ARPHRD_EETHER = 2
ARPHRD_AX25 = 3
ARPHRD_PRONET = 4
ARPHRD_CHAOS = 5
ARPHRD_IEEE802 = 6
ARPHRD_ARCNET = 7
ARPHRD_APPLETLK = 8
ARPHRD_DLCI = 15
ARPHRD_ATM = 19
ARPHRD_METRICOM = 23
ARPHRD_IEEE1394 = 24
ARPHRD_EUI64 = 27
ARPHRD_INFINIBAND = 32
ARPHRD_SLIP = 256
ARPHRD_CSLIP = 257
ARPHRD_SLIP6 = 258
ARPHRD_CSLIP6 = 259
ARPHRD_RSRVD = 260
ARPHRD_ADAPT = 264
ARPHRD_ROSE = 270
ARPHRD_X25 = 271
ARPHRD_HWX25 = 272
ARPHRD_CAN = 280
ARPHRD_PPP = 512
ARPHRD_CISCO = 513
ARPHRD_HDLC = 513
ARPHRD_LAPB = 516
ARPHRD_DDCMP = 517
ARPHRD_RAWHDLC = 518
ARPHRD_TUNNEL = 768
ARPHRD_TUNNEL6 = 769
ARPHRD_FRAD = 770
ARPHRD_SKIP = 771
ARPHRD_LOOPBACK = 772
ARPHRD_LOCALTLK = 773
ARPHRD_FDDI = 774
ARPHRD_BIF = 775
ARPHRD_SIT = 776
ARPHRD_IPDDP = 777
ARPHRD_IPGRE = 778
ARPHRD_PIMREG = 779
ARPHRD_HIPPI = 780
ARPHRD_ASH = 781
ARPHRD_ECONET = 782
ARPHRD_IRDA = 783
ARPHRD_FCPP = 784
ARPHRD_FCAL = 785
ARPHRD_FCPL = 786
ARPHRD_FCFABRIC = 787
ARPHRD_IEEE802_TR = 800
ARPHRD_IEEE80211 = 801
ARPHRD_IEEE80211_PRISM = 802
ARPHRD_IEEE80211_RADIOTAP = 803
ARPHRD_IEEE802154 = 804
ARPHRD_IEEE802154_MONITOR = 805
ARPHRD_PHONET = 820
ARPHRD_PHONET_PIPE = 821
ARPHRD_CAIF = 822
ARPHRD_IP6GRE = 823
ARPHRD_NETLINK = 824
ARPHRD_6LOWPAN = 825
ARPHRD_VSOCKMON = 826
ARPHRD_VOID = 0xFFFF
ARPHRD_NONE = 0xFFFE

HW_TYPES = {
    ARPHRD_NETROM: 'NETROM',
    ARPHRD_ETHER: 'ETHER',
    ARPHRD_EETHER: 'EETHER',
    ARPHRD_AX25: 'AX25',
    ARPHRD_PRONET: 'PRONET',
    ARPHRD_CHAOS: 'CHAOS',
    ARPHRD_IEEE802: 'IEEE802',
    ARPHRD_ARCNET: 'ARCNET',
    ARPHRD_APPLETLK: 'APPLETLK',
    ARPHRD_DLCI: 'DLCI',
    ARPHRD_ATM: 'ATM',
    ARPHRD_METRICOM: 'METRICOM',
    ARPHRD_IEEE1394: 'IEEE1394',
    ARPHRD_EUI64: 'EUI64',
    ARPHRD_INFINIBAND: 'INFINIBAND',
    ARPHRD_SLIP: 'SLIP',
    ARPHRD_CSLIP: 'CSLIP',
    ARPHRD_SLIP6: 'SLIP6',
    ARPHRD_CSLIP6: 'CSLIP6',
    ARPHRD_RSRVD: 'RSRVD',
    ARPHRD_ADAPT: 'ADAPT',
    ARPHRD_ROSE: 'ROSE',
    ARPHRD_X25: 'X25',
    ARPHRD_HWX25: 'HWX25',
    ARPHRD_CAN: 'CAN',
    ARPHRD_PPP: 'PPP',
    ARPHRD_HDLC: 'HDLC',
    ARPHRD_LAPB: 'LAPB',
    ARPHRD_DDCMP: 'DDCMP',
    ARPHRD_RAWHDLC: 'RAWHDLC',
    ARPHRD_TUNNEL: 'TUNNEL',
    ARPHRD_TUNNEL6: 'TUNNEL6',
    ARPHRD_FRAD: 'FRAD',
    ARPHRD_SKIP: 'SKIP',
    ARPHRD_LOOPBACK: 'LOOPBACK',
    ARPHRD_LOCALTLK: 'LOCALTLK',
    ARPHRD_FDDI: 'FDDI',
    ARPHRD_BIF: 'BIF',
    ARPHRD_SIT: 'SIT',
    ARPHRD_IPDDP: 'IPDDP',
    ARPHRD_IPGRE: 'IPGRE',
    ARPHRD_PIMREG: 'PIMREG',
    ARPHRD_HIPPI: 'HIPPI',
    ARPHRD_ASH: 'ASH',
    ARPHRD_ECONET: 'ECONET',
    ARPHRD_IRDA: 'IRDA',
    ARPHRD_FCPP: 'FCPP',
    ARPHRD_FCAL: 'FCAL',
    ARPHRD_FCPL: 'FCPL',
    ARPHRD_FCFABRIC: 'FCFABRIC',
    ARPHRD_IEEE802_TR: 'IEEE802_TR',
    ARPHRD_IEEE80211: 'IEEE80211',
    ARPHRD_IEEE80211_PRISM: 'IEEE80211_PRISM',
    ARPHRD_IEEE80211_RADIOTAP: 'IEEE80211_RADIOTAP',
    ARPHRD_IEEE802154: 'IEEE802154',
    ARPHRD_IEEE802154_MONITOR: 'IEEE802154_MONITOR',
    ARPHRD_PHONET: 'PHONET',
    ARPHRD_PHONET_PIPE: 'PHONET_PIPE',
    ARPHRD_CAIF: 'CAIF',
    ARPHRD_IP6GRE: 'IP6GRE',
    ARPHRD_NETLINK: 'NETLINK',
    ARPHRD_6LOWPAN: '6LOWPAN',
    ARPHRD_VSOCKMON: 'VSOCKMON',
    ARPHRD_VOID: 'VOID',
    ARPHRD_NONE: 'NONE',
}


def decode_state(state: int) -> str:
    """Decode neighbor state flags to string"""
    states = []
    if state & NUD_INCOMPLETE:
        states.append('INCOMPLETE')
    if state & NUD_REACHABLE:
        states.append('REACHABLE')
    if state & NUD_STALE:
        states.append('STALE')
    if state & NUD_DELAY:
        states.append('DELAY')
    if state & NUD_PROBE:
        states.append('PROBE')
    if state & NUD_FAILED:
        states.append('FAILED')
    if state & NUD_NOARP:
        states.append('NOARP')
    if state & NUD_PERMANENT:
        states.append('PERMANENT')
    if state == NUD_NONE:
        states.append('NONE')
    
    return '|'.join(states) if states else 'UNKNOWN'


def decode_flags(flags: int) -> List[str]:
    """Decode neighbor flags to list of strings"""
    flag_list = []
    if flags & NTF_USE:
        flag_list.append('USE')
    if flags & NTF_SELF:
        flag_list.append('SELF')
    if flags & NTF_MASTER:
        flag_list.append('MASTER')
    if flags & NTF_PROXY:
        flag_list.append('PROXY')
    if flags & NTF_EXT_LEARNED:
        flag_list.append('EXT_LEARNED')
    if flags & NTF_OFFLOADED:
        flag_list.append('OFFLOADED')
    if flags & NTF_STICKY:
        flag_list.append('STICKY')
    if flags & NTF_ROUTER:
        flag_list.append('ROUTER')
    
    return flag_list


def decode_unknown_attrs(unknown_list: List[int]) -> Dict[str, Any]:
    """Decode unknown NDA attributes"""
    nda_names = {
        1: 'NDA_DST',
        2: 'NDA_LLADDR',
        3: 'NDA_CACHEINFO',
        4: 'NDA_PROBES',
        5: 'NDA_VLAN',
        6: 'NDA_PORT',
        7: 'NDA_VNI',
        8: 'NDA_IFINDEX',
        9: 'NDA_MASTER',
        10: 'NDA_LINK_NETNSID',
        11: 'NDA_SRC_VNI',
        12: 'NDA_PROTOCOL',
        13: 'NDA_NH_ID',
        14: 'NDA_FDB_EXT_ATTRS',
        15: 'NDA_FLAGS_EXT',
        16: 'NDA_NDM_STATE_MASK',
        17: 'NDA_NDM_FLAGS_MASK',
    }
    
    decoded = {}
    for attr_type in unknown_list:
        name = nda_names.get(attr_type, f'UNKNOWN_{attr_type}')
        if name in decoded:
            decoded[name] += 1
        else:
            decoded[name] = 1
    
    return decoded


class NeighborTableQuery:
    """
    Query neighbor table via RTNetlink.
    
    Can be used with context manager or direct calls:
        # Option 1: Context manager (socket auto-closed)
        with NeighborTableQuery() as ntq:
            neighbors = ntq.get_neighbors()
        
        # Option 2: Direct call (socket managed per-call)
        ntq = NeighborTableQuery()
        neighbors = ntq.get_neighbors()
        
        # Option 3: Manual socket management
        ntq = NeighborTableQuery()
        ntq.open()
        ipv4_neighbors = ntq.get_neighbors(family='ipv4')
        ipv6_neighbors = ntq.get_neighbors(family='ipv6')
        ntq.close()
    """
    
    def __init__(self, capture_unknown_attrs: bool = True):
        """
        Initialize neighbor table query.
        
        Args:
            capture_unknown_attrs: Whether to capture unknown NDA attributes
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
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False
    
    def get_neighbors(self, family: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get neighbor table entries.
        
        If socket is not already open (e.g., via 'with' or explicit open()),
        this method will open and close it automatically for this call.
        
        Args:
            family: Filter by family ('ipv4', 'ipv6', 'bridge', or None for all)
        
        Returns:
            List of neighbor entry dictionaries
        """
        # Check if we need to auto-open the socket
        need_auto_close = False
        if self.sock < 0:
            self.open()
            need_auto_close = True
        
        try:
            # Determine netlink family
            nl_family = AF_UNSPEC
            if family == 'ipv4':
                nl_family = AF_INET
            elif family == 'ipv6':
                nl_family = AF_INET6
            elif family == 'bridge':
                nl_family = AF_BRIDGE
            
            # Send request
            seq = ffi.new("unsigned int*")
            if lib.nl_send_getneigh(self.sock, seq, nl_family) < 0:
                raise RuntimeError("Failed to send RTM_GETNEIGH request")
            
            # Receive response
            response = lib.nl_recv_response(self.sock, seq[0])
            if response == ffi.NULL:
                raise RuntimeError("Failed to receive netlink response")
            
            try:
                # Get neighbor count
                count = lib.nl_get_neighbor_count(response)
                if count == 0:
                    return []
                
                # Parse neighbors
                count_out = ffi.new("int*")
                neighbors_array = lib.nl_parse_neighbors(
                    response, 
                    count_out, 
                    1 if self.capture_unknown_attrs else 0
                )
                
                if neighbors_array == ffi.NULL:
                    return []
                
                # Convert to Python list
                neighbors = []
                for i in range(count_out[0]):
                    entry = neighbors_array[i]
                    
                    # Decode family
                    family_name = {
                        AF_INET: 'ipv4',
                        AF_INET6: 'ipv6',
                        AF_BRIDGE: 'bridge',
                    }.get(entry.family, f'family_{entry.family}')
                    
                    # Decode state
                    state_name = decode_state(entry.state)
                    
                    # Decode flags
                    flag_names = decode_flags(entry.flags)
                    
                    # Decode hardware type
                    hw_type_name = HW_TYPES.get(entry.type, f'TYPE_{entry.type}')
                    
                    # Build neighbor info dict
                    neigh_info = {
                        'ifindex': entry.ifindex,
                        'ifname': ffi.string(entry.ifname).decode('utf-8'),  # ALWAYS INCLUDED!
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
        
        finally:
            # Auto-close socket if we auto-opened it
            if need_auto_close:
                self.close()

# Example usage
def main():
    """Main entry point for the command."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Neighbor Table Query Tool (ARP/NDP/FDB)')
    parser.add_argument('--no-unknown-attrs', action='store_true',
                        help='Disable unknown attribute tracking')
    parser.add_argument('--summary', '-v', '--verbose', action='store_true',
                        help='Show human-readable summary')
    parser.add_argument('--arp', action='store_true',
                        help='Show only IPv4 ARP entries')
    parser.add_argument('--ndp', action='store_true',
                        help='Show only IPv6 NDP entries')
    parser.add_argument('--bridge', action='store_true',
                        help='Show only bridge FDB entries')
    parser.add_argument('-d', '--device', '--interface', 
                        type=str,
                        dest='device',
                        metavar='DEVICE',
                        help='Filter by device/interface name (e.g., eth0, wlan0)')
    parser.add_argument('-j', '--json', action='store_true', 
                        help='Output in pure JSON format (default)')
    parser.add_argument('-t', '--text', action='store_true', 
                        help='Output in text format')
    
    args = parser.parse_args()
    if args.json and args.summary:
        parser.error('Only --summary is not allowed with -j or --json')
    
    try:
        if (not args.json) and (len(sys.argv) != 1):
            print('=' * 70)
            print('RTNetlink Neighbor Table Query (ARP/NDP/FDB)')
            print('=' * 70)
            print(f"Unknown attribute tracking: {'DISABLED' if args.no_unknown_attrs else 'ENABLED'}")
            if args.device:
                print(f"Filtering by device: {args.device}")
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
        
        # Filter by device/interface if requested
        if args.device:
            # Filter by interface name (now available in JSON!)
            neighbors = [n for n in neighbors if n['ifname'] == args.device]
        
        if args.summary:
            # Human-readable summary
            print(f'\nFound {len(neighbors)} neighbor entries:')
            print('=' * 70)
            
            # Group by family
            by_family = {}
            for entry in neighbors:
                fam = entry['family']
                if fam not in by_family:
                    by_family[fam] = []
                by_family[fam].append(entry)
            
            for fam in sorted(by_family.keys()):
                entries = by_family[fam]
                print(f'\n{fam.upper()} Entries ({len(entries)}):')
                print('-' * 70)
                
                for entry in entries:
                    # Interface name is now in the entry!
                    if_name = entry['ifname']
                    
                    dst = entry.get('dst', 'N/A')
                    lladdr = entry.get('lladdr', 'N/A')
                    state = entry['state_name']
                    hw_type = entry.get('type_name', 'unknown')
                    
                    print(f'  {dst:40s} -> {lladdr:17s}  [{state:20s}] on {if_name}')
                    print(f'    Type: {hw_type}')
                    
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
            # Full JSON output (ifname is ALWAYS included!)
            print(json.dumps(neighbors, indent=2))
        
        if (not args.json) and (len(sys.argv) != 1):
            print()
            print('=' * 70)
            print(f'✓ Query complete! Found {len(neighbors)} entries.')
            print('=' * 70)
    
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    return 0


if __name__ == '__main__':
    main()