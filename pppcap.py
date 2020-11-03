#!/usr/bin/env python

from ctypes import *
from pppcap_headers import *
from logging import getLogger
from threading import Event, Thread
import queue

logger = getLogger(__name__)

class Pppcap:
    def __init__(self, device_name, capture_length=65535,
                 promiscuous=PCAP_OPENFLAG_PROMISCUOUS, recv_timeout=100):
        self.device = None
        self.devices = []
        self.alldevs = POINTER(pcap_if_t)()
        self.errbuf  = create_string_buffer(PCAP_ERRBUF_SIZE)
        pcap_findalldevs(byref(self.alldevs), self.errbuf)
        try:
            dev = self.alldevs.contents
        except:
            logger.warn("Error in pcap_findalldevs: %s" % self.errbuf.value,
                        "Have you network admin privilege ?")
            pcap_freealldevs(self.alldevs)
            return

        while dev:
            dev_name = dev.name.decode()
            self.devices.append((dev_name, dev.description))
            logger.debug("Found interface: {}".format(dev_name))
            if dev.name.decode() == device_name:
                logger.info("Set device: {}".format(dev_name))
                self.device = dev
            dev = dev.next.contents if dev.next else None

        if len(self.devices) < 1:
            print("No interfaces found. Make sure libpcap or WinPcap installed.")

        if self.device is None:
            logger.error("Invalid interface name.")
            pcap_freealldevs(self.alldevs)
            return

        if sys.platform.startswith('win'):
            self.adhandle = pcap_open(self.device.name, capture_length, promiscuous,
                                      recv_timeout, None, self.errbuf)
        else:
            self.adhandle = pcap_open_live(self.device.name, capture_length, promiscuous,
                                      recv_timeout, self.errbuf)
        if (self.adhandle == None):
            logger.warn("Unable to open the adapter.",
                        "{} is not supported by libcap/winpcap".format(dev.name))
            pcap_freealldevs(self.alldevs)
            return

    def capture(self):
        logger.info("listening on {} ({})".format(self.device.name, self.device.description))
        packet_queue = queue.Queue()
        stopped = Event()

        def start():
            pcap_loop(self.adhandle, -1, pcap_handler(callback), None)

        def callback(args, pkt_hdr, pkt_data):
            """
            Args:
                args: Always None
                pkt_hdr: POINTER(pcap_pkthdr)()
                pkt_data: POINTER(c_ubyte)()
            """
            logger.debug("{}.{} {}[Byte]".format(pkt_hdr.contents.ts.tv_sec, pkt_hdr.contents.ts.tv_usec, pkt_hdr.contents.len))
            hdr = pcap_pkthdr(pkt_hdr.contents.ts, pkt_hdr.contents.caplen, pkt_hdr.contents.len)
            packet_queue.put((hdr, string_at(pkt_data, pkt_hdr.contents.len)))

        def iterator():
            while not stopped.is_set():
                packet = packet_queue.get()
                if packet is None:
                    continue
                yield packet

        def stop():
            stopped.set()
            if thread.is_alive():
                pcap_breakloop(self.adhandle)
                pcap_close(self.adhandle)
                pcap_freealldevs(self.alldevs)

        thread = Thread(target=start, name="Capture-{}".format(self.device.name.decode()), daemon=True)
        thread.start()
        return iterator(), stop

    def send(self, buf):
        if isinstance(buf, c_ubyte):
            pcap_sendpacket(self.adhandle, buf, len(buf))
        else:
            pcap_sendpacket(self.adhandle, cast(buf, POINTER(c_ubyte)), len(buf))
