#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ctypes import *
from optparse import OptionParser
from pppcap import *
import sys

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

def pkt_send(dev, buf):
    pcap_sendpacket(dev, cast(buf, POINTER(c_ubyte)), len(buf))
    return


def generator(opts):
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

    buf = b"\x02\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x01\x08\x00"
    buf = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x01\x08\x00"
    buf += b"E\x00\x00\x1c\x00\x00\x00\x00@\x11z\xdd\x00\x00\x00\x00\x00\x00\x00\x00"
    buf += b"\xde\xad\x00\x00\x00\x08!1"

    try:
        for i in range(opts.count):
            pkt_send(adhandle, buf)
            print("Packet sent")
    except KeyboardInterrupt:
        print("User stop.")
    pcap_freealldevs(alldevs)
    pcap_close(adhandle)


def main():
    p = OptionParser(version=version)
    p.add_option('-d', '--discovery', action='store_true', help="Discovery device")
    p.add_option('-i', '--interface', action='store', type='int', default=0, help="Interface number")
    p.add_option('-c', '--count', action='store', type='int', help="Packet send count", default=3)
    opts, args = p.parse_args()

    if opts.discovery:
        dev_discovery()

    elif opts.interface > 0:
        generator(opts)

    else:
        p.print_version()
        p.print_help()

if __name__ == '__main__':
    main()
