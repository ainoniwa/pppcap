#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Reference:
#    WpcapSrc_4_1_3
#
# TODO:
#    Remote capture
#    AirPcap
#

from ctypes import *
from ctypes.util import find_library
import sys

WIN32 = True if sys.platform.startswith('win') else False

if WIN32:
    MSDOS, WPCAP, HAVE_REMOTE = True, True, True
    _libpath = find_library('wpcap')
else:
    MSDOS, WPCAP, HAVE_REMOTE = False, False, False
    _libpath = find_library('pcap')

if not _libpath:
    raise PcapException("Can't find pcap library")

_pcap = CDLL(_libpath)

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

PCAP_ERRBUF_SIZE = 256

if WIN32:
    bpf_int32 = c_long
    bpf_u_int32 = c_ulong
else:
    bpf_int32 = c_int
    bpf_u_int32 = c_uint


class bpf_insn(Structure):
    _fields_ = [("code", c_ushort),
                ("jt", c_ubyte),
                ("jf", c_ubyte),
                ("k", bpf_u_int32),
    ]


class bpf_program(Structure):
    pass
bpf_program._fields_ = [('bf_len', c_uint),
                        ('bf_insns', POINTER(bpf_insn)),
]


class timeval(Structure):
    _fields_ = [('tv_sec', c_long),
                ('tv_usec', c_long),
    ]


class pcap_file_header(Structure):
    _fields_ = [('magic', bpf_u_int32),
                ('version_major', c_ushort),
                ('version_minor', c_ushort),
                ('thiszone', bpf_int32),
                ('sigfigs', bpf_u_int32),
                ('snaplen', bpf_u_int32),
                ('linktype', bpf_u_int32),
    ]


class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
                ('caplen', bpf_u_int32),
                ('len', bpf_u_int32),
    ]


class pcap_stat(Structure):
    _fields_ = [("ps_recv", c_uint),
                ("ps_drop", c_uint),
                ("ps_ifdrop", c_uint),
    ]

if HAVE_REMOTE:
    pcap_stat._fields_.extend([
        ("ps_capt", c_uint),
        ("ps_sent", c_uint),
        ("ps_netdrop", c_uint),
    ])


class pcap_stat_ex(Structure):
    _fields_ = [("rx_packets", c_ulong), # total packets received
                ("tx_packets", c_ulong), # total packets transmitted
                ("rx_bytes", c_ulong), # total bytes received
                ("tx_bytes", c_ulong), # total bytes transmitted
                ("rx_errors", c_ulong), # bad packets received
                ("tx_errors", c_ulong), # packet transmit problems
                ("rx_dropped", c_ulong), # no space in Rx buffers
                ("tx_dropped", c_ulong), # no space available for Tx
                ("multicast", c_ulong), # multicast packets received
                ("collisions", c_ulong),

                ## detailed rx_errors
                ("rx_length_errors", c_ulong),
                ("rx_over_errors", c_ulong), # receiver ring buff overflow
                ("rx_crc_errors", c_ulong), # recv'd pkt with crc error
                ("rx_frame_errors", c_ulong), # recv'd frame alignment error
                ("rx_fifo_errors", c_ulong), # recv'r fifo overrun
                ("rx_missed_errors", c_ulong), # recv'r missed packet

                ## detailed tx_errors
                ("tx_aborted_errors", c_ulong), # recv'r missed packet
                ("tx_carrier_errors", c_ulong), # recv'r missed packet
                ("tx_fifo_errors", c_ulong), # recv'r missed packet
                ("tx_heartbeat_errors", c_ulong), # recv'r missed packet
                ("tx_window_errors", c_ulong), # recv'r missed packet
    ]


class pcap(Structure):
    pass


class pcap_dumper(Structure):
    pass


class sockaddr(Structure):
    _fields_ = [("sa_family", c_ushort),
                ("sa_data", c_char*14),
    ]


class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
                      ('addr', POINTER(sockaddr)),
                      ('netmask', POINTER(sockaddr)),
                      ('broadaddr', POINTER(sockaddr)),
                      ('dstaddr', POINTER(sockaddr)),
    ]


class pcap_if(Structure):
    pass
pcap_if._fields_ = [('next', POINTER(pcap_if)),
                    ('name', c_char_p),
                    ('description', c_char_p),
                    ('addresses', POINTER(pcap_addr)),
                    ('flags', bpf_u_int32),
]


pcap_handler = CFUNCTYPE(None, POINTER(c_ubyte), POINTER(pcap_pkthdr), POINTER(c_ubyte))

pcap_t = pcap
pcap_dumper_t = pcap_dumper
pcap_if_t = pcap_if
pcap_addr_t = pcap_addr
u_char = c_ubyte
FILE = c_void_p

## Error codes for the pcap API.
#generic error code
PCAP_ERROR = -1
#loop terminated by pcap_breakloop
PCAP_ERROR_BREAK = -2
#the capture needs to be activated
PCAP_ERROR_NOT_ACTIVATED = -3
#the operation can't be performed on already activated captures
PCAP_ERROR_ACTIVATED = -4
#no such device exists
PCAP_ERROR_NO_SUCH_DEVICE = -5
#this device doesn't support rfmon (monitor) mode
PCAP_ERROR_RFMON_NOTSUP = -6
#operation supported only in monitor mode
PCAP_ERROR_NOT_RFMON = -7
#no permission to open the device
PCAP_ERROR_PERM_DENIED = -8
#interface isn't up
PCAP_ERROR_IFACE_NOT_UP = -9

## Warning codes for the pcap API.
#generic warning code
PCAP_WARNING = 1
#this device doesn't support
PCAP_WARNING_PROMISC_NOTSUP = 2

# char *pcap_lookupdev(char *);
pcap_lookupdev = _pcap.pcap_lookupdev
pcap_lookupdev.restype = c_char_p
pcap_lookupdev.argtypes = [c_char_p]

# int pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);
pcap_lookupnet = _pcap.pcap_lookupnet
pcap_lookupnet.restype = c_int
pcap_lookupnet.argtypes = [c_char_p, POINTER(bpf_u_int32), POINTER(bpf_u_int32), c_char_p]

# pcap_t *pcap_create(const char *, char *);
pcap_create = _pcap.pcap_create
pcap_create.restype = POINTER(pcap_t)
pcap_create.argtypes = [c_char_p, c_char_p]

# int pcap_set_snaplen(pcap_t *, int);
pcap_set_snaplen = _pcap.pcap_set_snaplen
pcap_set_snaplen.restype = c_int
pcap_set_snaplen.argtypes = [POINTER(pcap_t), c_int]

# int pcap_set_promisc(pcap_t *, int);
pcap_set_promisc = _pcap.pcap_set_promisc
pcap_set_promisc.restype = c_int
pcap_set_promisc.argtypes = [POINTER(pcap_t), c_int]

# int pcap_can_set_rfmon(pcap_t *);
#pcap_can_set_rfmon = _pcap.pcap_can_set_rfmon
#pcap_can_set_rfmon.restype = c_int
#pcap_can_set_rfmon.argtypes = [POINTER(pcap_t)]

# int pcap_set_rfmon(pcap_t *, int);
#pcap_set_rfmon = _pcap.pcap_set_rfmon
#pcap_set_rfmon.restype = c_int
#pcap_set_rfmon.argtypes = [POINTER(pcap_t), c_int]

# int pcap_set_timeout(pcap_t *, int);
pcap_set_timeout = _pcap.pcap_set_timeout
pcap_set_timeout.restype = c_int
pcap_set_timeout.argtypes = [POINTER(pcap_t), c_int]

# int pcap_set_buffer_size(pcap_t *, int);
pcap_set_buffer_size = _pcap.pcap_set_buffer_size
pcap_set_buffer_size.restype = c_int
pcap_set_buffer_size.argtypes = [POINTER(pcap_t), c_int]

# int pcap_activate(pcap_t *);
pcap_activate = _pcap.pcap_activate
pcap_activate.restype = c_int
pcap_activate.argtypes = [POINTER(pcap_t)]

# pcap_t *pcap_open_live(const char *, int, int, int, char *);
pcap_open_live = _pcap.pcap_open_live
pcap_open_live.restype = POINTER(pcap_t)
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]

# pcap_t *pcap_open_dead(int, int);
pcap_open_dead = _pcap.pcap_open_dead
pcap_open_dead.restype = POINTER(pcap_t)
pcap_open_dead.argtypes = [c_int, c_int]

# pcap_t *pcap_open_offline(const char *, char *);
pcap_open_offline = _pcap.pcap_open_offline
pcap_open_offline.restype = POINTER(pcap_t)
pcap_open_offline.argtypes = [c_char_p, c_char_p]

"""
if WIN32:
    # pcap_t *pcap_hopen_offline(intptr_t, char *);

    if not LIBPCAP_EXPORTS:
        #define pcap_fopen_offline(f,b) pcap_hopen_offline(_get_osfhandle(_fileno(f)), b)
        pass
    else:
        #static pcap_t *pcap_fopen_offline(FILE *, char *);
        pass

else:
    # pcap_t *pcap_fopen_offline(FILE *, char *);
    pass
"""

# void pcap_close(pcap_t *);
pcap_close = _pcap.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(pcap_t)]

# int pcap_loop(pcap_t *, int, pcap_handler, u_char *);
pcap_loop = _pcap.pcap_loop
pcap_loop.restype = c_int
pcap_loop.argtypes = [POINTER(pcap_t), c_int, pcap_handler, POINTER(u_char)]

# int pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);
pcap_dispatch = _pcap.pcap_dispatch
pcap_dispatch.restype = c_int
pcap_dispatch.argtypes = [POINTER(pcap_t), c_int, pcap_handler, POINTER(u_char)]

# const u_char* pcap_next(pcap_t *, struct pcap_pkthdr *);
pcap_next = _pcap.pcap_next
pcap_next.restype = POINTER(u_char)
pcap_next.argtypes = [POINTER(pcap_t), POINTER(pcap_pkthdr)]

# int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
pcap_next_ex = _pcap.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [POINTER(pcap_t), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(u_char))]

# void pcap_breakloop(pcap_t *);
pcap_breakloop = _pcap.pcap_next
pcap_breakloop.restype = None
pcap_breakloop.argtypes = [POINTER(pcap_t)]

# int pcap_stats(pcap_t *, struct pcap_stat *);
pcap_stats = _pcap.pcap_stats
pcap_stats.restype = c_int
pcap_stats.argtypes = [POINTER(pcap_t), POINTER(pcap_stat)]

# int pcap_setfilter(pcap_t *, struct bpf_program *);
pcap_setfilter = _pcap.pcap_setfilter
pcap_setfilter.restype = c_int
pcap_setfilter.argtypes = [POINTER(pcap_t), POINTER(bpf_program)]

# int pcap_setdirection(pcap_t *, pcap_direction_t);
#pcap_setdirection = _pcap.pcap_setdirection
#pcap_setdirection.restype = c_int
#pcap_setdirection.argtypes = [POINTER(pcap_t), pcap_direction_t]

# int pcap_getnonblock(pcap_t *, char *);
pcap_getnonblock = _pcap.pcap_getnonblock
pcap_getnonblock.restype = c_int
pcap_getnonblock.argtypes = [POINTER(pcap_t), c_char_p]

# int pcap_setnonblock(pcap_t *, int, char *);
pcap_setnonblock = _pcap.pcap_setnonblock
pcap_setnonblock.restype = c_int
pcap_setnonblock.argtypes = [POINTER(pcap_t), c_int, c_char_p]

# int pcap_inject(pcap_t *, const void *, size_t);
pcap_sendpacket = _pcap.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(pcap_t), c_void_p, c_uint]

# int pcap_sendpacket(pcap_t *, const u_char *, int);
pcap_sendpacket = _pcap.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(pcap_t), POINTER(u_char), c_int]

# const char *pcap_statustostr(int);
#pcap_statustostr = _pcap.pcap_statustostr
#pcap_statustostr.restype = c_char_p
#pcap_statustostr.argtypes = [c_int]

# const char *pcap_strerror(int);
pcap_strerror = _pcap.pcap_strerror
pcap_strerror.restype = c_char_p
pcap_strerror.argtypes = [c_int]

# char *pcap_geterr(pcap_t *);
pcap_geterr = _pcap.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [POINTER(pcap_t)]

# void pcap_perror(pcap_t *, char *);
pcap_perror = _pcap.pcap_perror
pcap_perror.restype = None
pcap_perror.argtypes = [POINTER(pcap_t), c_char_p]

# int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
pcap_compile = _pcap.pcap_compile
pcap_compile.restype = c_int
pcap_compile.argtypes = [POINTER(pcap_t), POINTER(bpf_program), c_char_p, c_int, bpf_u_int32]

# int pcap_compile_nopcap(int, int, struct bpf_program *, const char *, int, bpf_u_int32);
pcap_compile_nopcap = _pcap.pcap_compile_nopcap
pcap_compile_nopcap.restype = c_int
pcap_compile_nopcap.argtypes = [c_int, c_int, POINTER(bpf_program), c_char_p, bpf_u_int32]

# void pcap_freecode(struct bpf_program *);
pcap_freecode = _pcap.pcap_freecode
pcap_freecode.restype = None
pcap_freecode.argtypes = [POINTER(bpf_program)]

# int pcap_offline_filter(struct bpf_program *, const struct pcap_pkthdr * const u_char *);
pcap_offline_filter = _pcap.pcap_offline_filter
pcap_offline_filter.restype = c_int
pcap_offline_filter.argtypes = [POINTER(bpf_program), POINTER(pcap_pkthdr), u_char]

# int pcap_datalink(pcap_t *);
pcap_datalink = _pcap.pcap_datalink
pcap_datalink.restype = c_int
pcap_datalink.argtypes = [POINTER(pcap_t)]

# int pcap_datalink_ext(pcap_t *);
#pcap_datalink_ext = _pcap.pcap_datalink_ext
#pcap_datalink_ext.restype = c_int
#pcap_datalink_ext.argtypes = [POINTER(pcap_t)]

# int pcap_list_datalinks(pcap_t *, int **);
pcap_list_datalinks = _pcap.pcap_list_datalinks
pcap_list_datalinks.restype = c_int
pcap_list_datalinks.argtypes = [POINTER(pcap_t), POINTER(POINTER(c_int))]

# int pcap_set_datalink(pcap_t *, int);
pcap_set_datalink = _pcap.pcap_set_datalink
pcap_set_datalink.restype = c_int
pcap_set_datalink.argtypes = [POINTER(pcap_t), c_int]

# void pcap_free_datalinks(int *);
pcap_free_datalinks = _pcap.pcap_free_datalinks
pcap_free_datalinks.restype = None
pcap_free_datalinks.argtypes = [POINTER(c_int)]

# int pcap_datalink_name_to_val(const char *);
pcap_datalink_name_to_val = _pcap.pcap_datalink_name_to_val
pcap_datalink_name_to_val.restype = c_int
pcap_datalink_name_to_val.argtypes = [c_char_p]

# const char *pcap_datalink_val_to_name(int);
pcap_datalink_val_to_name = _pcap.pcap_datalink_val_to_name
pcap_datalink_val_to_name.restype = c_char_p
pcap_datalink_val_to_name.argtypes = [c_int]

# const char *pcap_datalink_val_to_description(int);
pcap_datalink_val_to_description = _pcap.pcap_datalink_val_to_description
pcap_datalink_val_to_description.restype = c_char_p
pcap_datalink_val_to_description.argtypes = [c_int]

# int pcap_snapshot(pcap_t *);
pcap_snapshot = _pcap.pcap_snapshot
pcap_snapshot.restype = c_int
pcap_snapshot.argtypes = [POINTER(pcap_t)]

# int pcap_is_swapped(pcap_t *);
pcap_is_swapped = _pcap.pcap_is_swapped
pcap_is_swapped.restype = c_int
pcap_is_swapped.argtypes = [POINTER(pcap_t)]

# int pcap_major_version(pcap_t *);
pcap_major_version = _pcap.pcap_major_version
pcap_major_version.restype = c_int
pcap_major_version.argtypes = [POINTER(pcap_t)]

# int pcap_minor_version(pcap_t *);
pcap_minor_version = _pcap.pcap_minor_version
pcap_minor_version.restype = c_int
pcap_minor_version.argtypes = [POINTER(pcap_t)]

# /* XXX */
# FILE *pcap_file(pcap_t *);
pcap_file = _pcap.pcap_file
pcap_file.restype = FILE
pcap_file.argtypes = [POINTER(pcap_t)]

# int pcap_fileno(pcap_t *);
pcap_fileno = _pcap.pcap_fileno
pcap_fileno.restype = c_int
pcap_fileno.argtypes = [POINTER(pcap_t)]

# pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
pcap_dump_open = _pcap.pcap_dump_open
pcap_dump_open.restype = POINTER(pcap_dumper_t)
pcap_dump_open.argtypes = [POINTER(pcap_t), c_char_p]

# pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *fp);
#pcap_dump_fopen = _pcap.pcap_dump_fopen
#pcap_dump_fopen.restype = POINTER(pcap_dumper_t)
#pcap_dump_fopen.argtypes= [POINTER(pcap_t), POINTER(FILE)]

# FILE *pcap_dump_file(pcap_dumper_t *);
pcap_dump_file = _pcap.pcap_dump_file
pcap_dump_file.restype = FILE
pcap_dump_file.argtypes= [POINTER(pcap_dumper_t)]

# long pcap_dump_ftell(pcap_dumper_t *);
pcap_dump_ftell = _pcap.pcap_dump_ftell
pcap_dump_ftell.restype = c_long
pcap_dump_ftell.argtypes = [POINTER(pcap_dumper_t)]

# int pcap_dump_flush(pcap_dumper_t *);
pcap_dump_flush = _pcap.pcap_dump_flush
pcap_dump_flush.restype = c_int
pcap_dump_flush.argtypes = [POINTER(pcap_dumper_t)]

# void pcap_dump_close(pcap_dumper_t *);
pcap_dump_close = _pcap.pcap_dump_close
pcap_dump_close.restype = None
pcap_dump_close.argtypes = [POINTER(pcap_dumper_t)]

# void pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);
pcap_dump = _pcap.pcap_dump
pcap_dump.restype = None
pcap_dump.argtypes = [POINTER(pcap_dumper_t), POINTER(pcap_pkthdr), POINTER(u_char)]

# int pcap_findalldevs(pcap_if_t **, char *);
pcap_findalldevs = _pcap.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if_t)), c_char_p]

# void pcap_freealldevs(pcap_if_t *);
pcap_freealldevs = _pcap.pcap_freealldevs
pcap_freealldevs.restype = None
pcap_freealldevs.argtypes = [POINTER(pcap_if_t)]

# const char *pcap_lib_version(void);
pcap_lib_version = _pcap.pcap_lib_version
pcap_lib_version.restype = c_char_p
pcap_lib_version.argtypes = []

# /* XXX this guy lives in the bpf tree */
# u_int bpf_filter(const struct bpf_insn *, const u_char *, u_int, u_int);
bpf_filter = _pcap.bpf_filter
bpf_filter.restype = c_uint
bpf_filter.argtypes = [POINTER(bpf_insn), u_char, c_uint, c_uint]

# int bpf_validate(const struct bpf_insn *f, int len);
bpf_validate = _pcap.bpf_validate
bpf_validate.restype = c_int
bpf_validate.argtypes = [POINTER(bpf_insn), c_int]

# char *bpf_image(const struct bpf_insn *, int);
bpf_image = _pcap.bpf_image
bpf_image.restype = c_char_p
bpf_image.argtypes = [POINTER(bpf_insn), c_int]

# void bpf_dump(const struct bpf_program *, int);
bpf_dump = _pcap.bpf_dump
bpf_dump.restype = None
bpf_dump.argtypes = [POINTER(bpf_program), c_int]

if WIN32:
    """
    Win32 definitions
    """

    # int pcap_setbuff(pcap_t *p, int dim);
    pcap_setbuff = _pcap.pcap_setbuff
    pcap_setbuff.restype = c_int
    pcap_setbuff.argtypes = [POINTER(pcap_t), c_int]
    
    # int pcap_setmode(pcap_t *p, int mode);
    pcap_setmode = _pcap.pcap_setmode
    pcap_setmode.restype = c_int
    pcap_setmode.argtypes = [POINTER(pcap_t), c_int]
    
    # int pcap_setmintocopy(pcap_t *p, int size);
    pcap_setmintocopy = _pcap.pcap_setmintocopy
    pcap_setmintocopy.restype = c_int
    pcap_setmintocopy.argtype = [POINTER(pcap_t), c_int]

    if WPCAP:
        # Include file with the wpcap-specific extensions
        #include <Win32-Extensions.h>
        class pcap_send_queue(Structure):
            _fields_ = [('maxlen', c_uint),
                        ('len', c_uint),
                        ('buffer', c_char_p),
            ]

        # pcap_send_queue* pcap_sendqueue_alloc(u_int memsize);
        pcap_sendqueue_alloc = _pcap.pcap_sendqueue_alloc
        pcap_sendqueue_alloc.restype = POINTER(pcap_send_queue)
        pcap_sendqueue_alloc.argtypes = [c_uint]

        # void pcap_sendqueue_destroy(pcap_send_queue* queue);
        pcap_sendqueue_destroy = _pcap.pcap_sendqueue_destroy
        pcap_sendqueue_destroy.restype = None
        pcap_sendqueue_destroy.argtypes = [POINTER(pcap_send_queue)]

        # int pcap_sendqueue_queue(pcap_send_queue* queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
        pcap_sendqueue_queue = _pcap.pcap_sendqueue_queue
        pcap_sendqueue_queue.restype = c_int
        pcap_sendqueue_queue.argtypes = [POINTER(pcap_send_queue), POINTER(pcap_pkthdr), POINTER(u_char)]

        # u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue, int sync);
        pcap_sendqueue_transmit = _pcap.pcap_sendqueue_transmit
        pcap_sendqueue_transmit.retype = c_uint
        pcap_sendqueue_transmit.argtypes = [POINTER(pcap_t), POINTER(pcap_send_queue), c_int]

        # HANDLE pcap_getevent(pcap_t *p);
        HANDLE = c_void_p
        pcap_getevent = _pcap.pcap_getevent
        pcap_getevent.restype = HANDLE
        pcap_getevent.argtypes = [POINTER(pcap_t)]

        # struct pcap_stat *pcap_stats_ex(pcap_t *p, int *pcap_stat_size);
        pcap_stats_ex = _pcap.pcap_stats_ex
        pcap_stats_ex.restype = POINTER(pcap_stat)
        pcap_stats_ex.argtypes = [POINTER(pcap_t), POINTER(c_int)]

        # int pcap_setuserbuffer(pcap_t *p, int size);
        pcap_setuserbuffer = _pcap.pcap_setuserbuffer
        pcap_setuserbuffer.restype = c_int
        pcap_setuserbuffer.argtypes = [POINTER(pcap_t), c_int]

        # int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks);
        pcap_live_dump = _pcap.pcap_live_dump
        pcap_live_dump.restype = c_int
        pcap_live_dump.argtypes = [POINTER(pcap_t), c_char_p, c_int, c_int]

        # int pcap_live_dump_ended(pcap_t *p, int sync);
        pcap_live_dump_ended = _pcap.pcap_live_dump_ended
        pcap_live_dump_ended.restype = c_int
        pcap_live_dump_ended.argtypes = [POINTER(pcap_t), c_int]

        # int pcap_offline_filter(struct bpf_program *prog, const struct pcap_pkthdr *header, const u_char *pkt_data);
        pcap_offline_filter = _pcap.pcap_offline_filter
        pcap_offline_filter.restype = c_int
        pcap_offline_filter.argtypes = [POINTER(bpf_program), POINTER(pcap_pkthdr), POINTER(u_char)]

        # int pcap_start_oem(char* err_str, int flags);
        #pcap_start_oem = _pcap.pcap_start_oem
        #pcap_start_oem.restype = c_int
        #pcap_start_oem.argtypes = [c_char_p, c_int]

        # PAirpcapHandle pcap_get_airpcap_handle(pcap_t *p);
        # TODO

    MODE_CAPT = 0
    MODE_STAT = 1
    MODE_MON = 2

elif MSDOS:
    """
    MSDOS definitions
    """
    # Now, if WIN32 is True, always MSDOS is True.
    pass
    """
    # int pcap_stats_ex (pcap_t *, struct pcap_stat_ex *);
    pcap_stats_ex = _pcap.pcap_stats_ex
    pcap_stats_ex.restype = c_int
    pcap_stats_ex.argtypes = [POINTER(POINTER(pcap_t)), POINTER(pcap_stat_ex)]

    # void pcap_set_wait (pcap_t *p, void (*yield)(void), int wait);
    pcap_set_wait = _pcap.pcap_set_wait
    pcap_set_wait.restype = None
    pcap_set_wait.argtypes = [POINTER(pcap_t), c_void_p, c_int]

    # u_long pcap_mac_packets (void);
    pcap_mac_packets = _pcap.pcap_mac_packets
    pcap_mac_packets.restype = c_long
    pcap_mac_packets.argtypes = []
    """
    
else:
    """
    UN*X definitions
    """
    # int pcap_get_selectable_fd(pcap_t *);
    pcap_get_selectable_fd = _pcap.pcap_get_selectable_fd
    pcap_get_selectable_fd.restype = c_int
    pcap_get_selectable_fd.argtype = [POINTER(pcap_t)]

#ifdef HAVE_REMOTE
# /* Includes most of the public stuff that is needed for the remote capture */
#include <remote-ext.h>
if HAVE_REMOTE:
    
    PCAP_BUF_SIZE = 1024
    PCAP_SRC_FILE = 2
    PCAP_SRC_IFLOCAL = 3
    PCAP_SRC_IFREMOTE = 4

    PCAP_SRC_FILE_STRING = "file://"
    PCAP_SRC_IF_STRING = "rpcap://"

    PCAP_OPENFLAG_PROMISCUOUS = 1
    PCAP_OPENFLAG_DATATX_UDP = 2
    PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4
    PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8
    PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16

    PCAP_SAMP_NOSAMP = 0
    PCAP_SAMP_1_EVERY_N = 1
    PCAP_SAMP_FIRST_AFTER_N_MS = 2

    RPCAP_RMTAUTH_NULL = 0
    RPCAP_RMTAUTH_PWD = 1

    class pcap_rmtauth(Structure):
        _fields_=[("type", c_int),
                  ("username", c_char_p),
                  ("password", c_char_p),
    ]

    class pcap_samp(Structure):
        _fields_=[("method", c_int),
                  ("value", c_char_p),
    ]

    RPCAP_HOSTLIST_SIZE = 1024

    """
    \name New WinPcap functions

	This section lists the new functions that are able to help considerably in writing
	WinPcap programs because of their easiness of use.
    """
    # pcap_t *pcap_open(const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf);
    pcap_open = _pcap.pcap_open
    pcap_open.restype = POINTER(pcap_t)
    pcap_open.argtypes = [c_char_p, c_int, c_int, c_int, POINTER(pcap_rmtauth), c_char_p]

    # int pcap_createsrcstr(char *source, int type, const char *host, const char *port, const char *name, char *errbuf);
    pcap_createsrcstr = _pcap.pcap_createsrcstr
    pcap_createsrcstr.restype = c_int
    pcap_createsrcstr.argtypes = [c_char_p, c_int, c_char_p, c_char_p, c_char_p, c_char_p]

    # int pcap_parsesrcstr(const char *source, int *type, char *host, char *port, char *name, char *errbuf);
    pcap_parsesrcstr = _pcap.pcap_parsesrcstr
    pcap_parsesrcstr.restype = c_int
    pcap_parsesrcstr.argtypes = [c_char_p, POINTER(c_int), c_char_p, c_char_p, c_char_p, c_char_p]

    # int pcap_findalldevs_ex(char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);
    pcap_findalldevs_ex = _pcap.pcap_findalldevs_ex
    pcap_findalldevs_ex.restype = c_int
    pcap_findalldevs_ex.argtypes = [c_char_p, POINTER(pcap_rmtauth), POINTER(POINTER(pcap_if_t)), c_char_p]

    # struct pcap_samp *pcap_setsampling(pcap_t *p);
    pcap_setsampling = _pcap.pcap_setsampling
    pcap_setsampling.restype = pcap_samp
    pcap_setsampling.argtypes = [POINTER(pcap_t)]


    """
    \name Remote Capture functions
    """
    SOCKET = c_int
    # SOCKET pcap_remoteact_accept(const char *address, const char *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth, char *errbuf);
    pcap_remoteact_accept = _pcap.pcap_remoteact_accept
    pcap_remoteact_accept.restype = SOCKET
    pcap_remoteact_accept.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, POINTER(pcap_rmtauth), c_char_p]

    # int pcap_remoteact_list(char *hostlist, char sep, int size, char *errbuf);
    pcap_remoteact_list = _pcap.pcap_remoteact_list
    pcap_remoteact_list.restype = c_int
    pcap_remoteact_list.argtypes = [c_char_p, c_char, c_int, c_char_p]

    # int pcap_remoteact_close(const char *host, char *errbuf);
    pcap_remoteact_close = _pcap.pcap_remoteact_close
    pcap_remoteact_close.restype = c_int
    pcap_remoteact_close.argtypes = [c_char_p, c_char_p]

    # void pcap_remoteact_cleanup();
    pcap_remoteact_cleanup = _pcap.pcap_remoteact_cleanup
    pcap_remoteact_cleanup.restype = None
    pcap_remoteact_cleanup.argtypes = None

