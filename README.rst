About
=======================================================================
pppcap is pure python wrapper for libpcap/winpcap.

* There are no dependencies on other python modules.
* There are no need to compile the other modules.


Requirement
=======================================================================
* winpcap (Windows)
* libpcap (Linux, Mac, or other UNIXs)


Install
=======================================================================
::

    $ python setup.py install

Need to `sudo` when using system python.


Example script
=======================================================================
::

    $ ./example/recv_sample.py -d
    1. b'eno1' (None)
    2. b'enp0s25' (None)
    $ sudo ./example/recv_sample.py -i 1
    Send interface: eno1
    listening on 1: eno1 (None)

    No.1 1488642855.772344 4434[Byte]
    No.2 1488642855.772356 4434[Byte]
    No.3 1488642855.772436 3027[Byte]
    No.4 1488642855.772709 60[Byte]
    No.5 1488642855.772736 60[Byte]
    No.6 1488642855.772847 6833[Byte]
    No.7 1488642855.773225 60[Byte]
    No.8 1488642855.773302 6422[Byte]
    No.9 1488642855.773624 60[Byte]
    No.10 1488642855.773777 6787[Byte]


Example interactive
=======================================================================
::

    >>> from ctypes import *
    >>> from pppcap import *
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

