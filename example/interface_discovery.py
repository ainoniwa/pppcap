#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ctypes import *
from pppcap.pppcap import *

alldevs = POINTER(pcap_if_t)()
errbuf  = create_string_buffer(PCAP_ERRBUF_SIZE)
pcap_findalldevs(byref(alldevs), errbuf)
dev = alldevs.contents

dev_count = 0
while dev:
	dev_count = dev_count+1
	print("%d. %s (%s)" % (dev_count, dev.name, dev.description))
	if dev.next:
		dev = dev.next.contents
	else:
		dev = False

pcap_freealldevs(alldevs)