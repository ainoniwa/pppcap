#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
from pppcap import *

eth0 = Port("eth0")
for i in range(10):
    hdr, data = eth0.recv()
    if hdr is None or data is None:
        continue
    print("{}.{} {}[Byte]\n  RAW: {}".format(hdr.ts_sec, hdr.ts_usec, hdr.len, binascii.hexlify(data)))
