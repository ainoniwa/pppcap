#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# NOTE: Only work python 3.x. And requirement pypacker package.
#

import socket
from pypacker.layer12.ethernet import Ethernet
from pypacker.layer12.arp import ARP
from pypacker.layer3.ip import IP
from pppcap import *

eth0 = Port("ens18")
for i in range(10):
    hdr, buf = eth0.recv()
    if hdr is None or buf is None:
        continue

    print("{}.{} {}[Byte]".format(hdr.ts_sec, hdr.ts_usec, hdr.len))

    try:
        eth = Ethernet(buf)
    except:
        print('Fail parse')
        continue

    if eth[ARP] is not None:
        print("  [ARP] who has {}".format(eth[ARP].tpa_s))
    if eth[IP] is not None:
        print("  [IPv4] {} -> {}".format(eth[IP].src_s, eth[IP].dst_s))
