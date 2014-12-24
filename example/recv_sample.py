#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ctypes import *
from optparse import OptionParser
from pppcap.pppcap import *
version = u'%prog 1.1'

def dev_discovery():
    alldevs = POINTER(pcap_if_t)()
    errbuf  = create_string_buffer(PCAP_ERRBUF_SIZE)
    pcap_findalldevs(byref(alldevs), errbuf)

    dev_count = 0
    try:
        dev = alldevs.contents
    except:
        print ("Error in pcap_findalldevs: %s" % errbuf.value)
        print ("Have you network admin privilege?\n")
        return

    while dev:
        dev_count = dev_count+1
        print("%d. %s (%s)" % (dev_count, dev.name, dev.description))
        dev = dev.next.contents if dev.next else False

    if (dev_count==0):
        print ("\nNo interfaces found! Make sure WinPcap is installed.\n")

    pcap_freealldevs(alldevs)


def dump(opts):
    alldevs = POINTER(pcap_if_t)()
    errbuf  = create_string_buffer(PCAP_ERRBUF_SIZE)
    pcap_findalldevs(byref(alldevs), errbuf)

    try:
        dev = alldevs.contents
    except:
        print ("Error in pcap_findalldevs: %s" % errbuf.value)
        print ("Have you network admin privilege?\n")
        return

    try:
        dev = alldevs
        for i in range(opts.interface-1):
            dev = dev.contents.next
    except:
        print ("Invalid interface number.")
        pcap_freealldevs(alldevs)
        return

    dev = dev.contents
    print("Send interface: %s" % dev.name)
    adhandle = pcap_open(dev.name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, None, errbuf)
    if (adhandle == None):
        print("\nUnable to open the adapter. %s is not supported by libcap/winpcap\n" % dev.name)
        pcap_freealldevs(alldevs)
        return
    pcap_freealldevs(alldevs)

    print("listening on {}: {} ({})\n".format(opts.interface, dev.name, dev.description))

    pkt_no = 1
    pkt_hdr = POINTER(pcap_pkthdr)()
    pkt_data = POINTER(c_ubyte)()

    import time
    time.clock()

    try:
        while True:
            if pcap_next_ex(adhandle, byref(pkt_hdr), byref(pkt_data)) != 0:
                print("No.{} {}.{} {}[Byte]".format(pkt_no, pkt_hdr.contents.ts.tv_sec, pkt_hdr.contents.ts.tv_usec, pkt_hdr.contents.len))
                pkt_no += 1
    except KeyboardInterrupt:
        print("User stop.")
    pcap_close(adhandle)


def main():
    p = OptionParser(version=version)
    p.add_option('-d', '--discovery', action='store_true', help="Discovery device")
    p.add_option('-i', '--interface', action='store', type='int', default=0, help="Interface number")
    p.add_option('-c', '--count', action='store', type='int', help="Traffic send count")
    opts, args = p.parse_args()

    if opts.discovery:
        dev_discovery()

    elif opts.interface > 0:
        dump(opts)

    else:
        p.print_version()
        p.print_help()

if __name__ == '__main__':
    main()
