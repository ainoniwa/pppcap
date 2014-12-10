About
=======================================================================
pppcap is pure python wrapper for libpcap/winpcap.

* There are no dependencies on other python modules.
* There are no need to compile the other modules.


Requirement
=======================================================================
* winpcap (Windows)
* libpcap (Linux, Max, or other UNIXs)


Install
=======================================================================
::

    $ python setup.py install


Example
=======================================================================
::

    >>> from ctypes import *
    >>> from pppcap.pppcap import *
    >>>
    >>> alldevs = POINTER(pcap_if_t)()
    >>> errbuf  = create_string_buffer(PCAP_ERRBUF_SIZE)
    >>> pcap_findalldevs(byref(alldevs), errbuf)
    0
    >>> dev = alldevs.contents
    >>>
    >>> dev_count = 0
    >>> while dev:
    ...     dev_count = dev_count+1
    ...     print("%d. %s (%s)" % (dev_count, dev.name, dev.description))
    ...     if dev.next:
    ...             dev = dev.next.contents
    ...     else:
    ...             dev = False
    ...
    1. b'\\Device\\NPF_{B1EC0C55-DB7C-441E-A74F-84CD083EC177}' (b'Microsoft Corporation')
    2. b'\\Device\\NPF_{29F85A41-F2B3-4C02-A8F0-3A5C5818860D}' (b'USB3.0 to Gigabit Ethernet Adapt')

