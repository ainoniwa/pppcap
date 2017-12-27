#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pppcap
pppcap.list_pcap_port()
if_0 = pppcap.Port('ens18')

def packet_recv_callback(cls, param, pkt_hdr, pkt_data):
    print("{}.{}".format(pkt_hdr.ts_sec, pkt_hdr.ts_usec))

if_0.capture(callback=packet_recv_callback, cnt=10)

