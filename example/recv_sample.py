#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ctypes import *
from optparse import OptionParser
from pppcap import *
import sys
import time

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

    if sys.platform.startswith('win'):
        adhandle = pcap_open(dev.name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 200, None, errbuf)
    else:
        adhandle = pcap_open_live(dev.name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 200, errbuf)
    if (adhandle == None):
        print("\nUnable to open the adapter. %s is not supported by libcap/winpcap\n" % dev.name)
        pcap_freealldevs(alldevs)
        return

    pkt_no = 1
    pkt_hdr = POINTER(pcap_pkthdr)()
    pkt_data = POINTER(c_ubyte)()

    print("listening on {}: {} ({})\n".format(opts.interface, dev.name, dev.description))
    try:
        while opts.count >= pkt_no:
            if pcap_next_ex(adhandle, byref(pkt_hdr), byref(pkt_data)) == 1:
                print("No.{} {}.{} {}[Byte]".format(pkt_no, pkt_hdr.contents.ts.tv_sec, pkt_hdr.contents.ts.tv_usec, pkt_hdr.contents.len))
                pkt_no += 1
    except KeyboardInterrupt:
        print("User stop.")
    pcap_freealldevs(alldevs)
    pcap_close(adhandle)


def main():
    p = OptionParser(version=version)
    p.add_option('-d', '--discovery', action='store_true', help="Discovery device")
    p.add_option('-i', '--interface', action='store', type='int', default=0, help="Interface number")
    p.add_option('-c', '--count', action='store', type='int', help="Packet receive count", default=10)
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
