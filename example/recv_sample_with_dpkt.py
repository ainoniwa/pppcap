#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# NOTE: Only work python 2.x. And requirement dpkt package.
#

import socket
import dpkt
from pppcap import *

eth0 = Port("eth0")
for i in range(10):
    hdr, data = eth0.recv()
    if hdr is None or data is None:
        continue

    print("{}.{} {}[Byte]".format(hdr.ts_sec, hdr.ts_usec, hdr.len))

    try:
        eth = dpkt.ethernet.Ethernet(data)
    except:
        print('Fail parse')
        continue

    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        print("  [IPv4] {} -> {}".format(src, dst))
