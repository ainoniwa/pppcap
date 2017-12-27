#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
from pppcap import *

lo = Port("lo")

# Eth
buf = b"\x02\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x01\x08\x00"
# IPv4
buf += b"\x45\x00\x00\x14\x00\x00\x00\x00\x80\x11\x01\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
# UDP
buf += b"\x10\x00\x20\x00\x00\x00\x00\x00"
print("Send buffer: {}".format(binascii.hexlify(buf)))

for i in range(10):
    lo.send(buf)