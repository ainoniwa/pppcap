About
=======================================================================
pppcap is pure python wrapper for libpcap/winpcap.

* There are no dependencies on other python modules.
* There are no need to compile the other modules.


Requirement
=======================================================================
* winpcap or Win10Pcap (Windows)
* libpcap (Linux, Mac, or other UNIXs)


Pre-configure (Ubuntu 16.04 and python3.5)
=======================================================================
Create venv, and setcap to bind ports.
::

    $ sudo apt install python3-venv
    $ python3 -m venv --copies dev
    $ . dev/bin/activate
    $ sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' dev/bin/python3


Pre-configure (CentOS 7.4 and python2.7)
=======================================================================
Create virtualenv, and setcap to bind ports.
::

    $ sudo yum install python-virtualenv
    $ virtualenv dev
    $ cd dev
    $ . bin/activate
    $ sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' bin/python2


Pre-configure (Windows and python 3.6)
=======================================================================
Create virtualenv.
::

    > python3 -m venv dev
    > cd dev
    > Set-ExecutionPolicy RemoteSigned -Scope Process -Force
    > .\Scripts\Activate.ps1


Install
=======================================================================
In virtualenv.
::

    (dev)$ python setup.py install

Need to use `sudo` when using system python.


Example script
=======================================================================
::

    (dev)$ pip install pypacker
    (dev)$ python example/interface_discovery.py
    1. b'ens18' (None)
    2. b'any' (b'Pseudo-device that captures on all interfaces')
    3. b'lo' (None)
    4. b'nflog' (b'Linux netfilter log (NFLOG) interface')
    5. b'nfqueue' (b'Linux netfilter queue (NFQUEUE) interface')
    6. b'usbmon1' (b'USB bus number 1')
    (dev)$ python example/recv_sample_with_pypacker.py
    1514269159.755425 60[Byte]
      [ARP] who has 192.168.1.102
    1514269159.841045 297[Byte]
      [IPv4] 192.168.1.252 -> 192.168.1.255
    1514269159.843053 297[Byte]
      [IPv4] 192.168.1.253 -> 192.168.1.255
    1514269159.854584 98[Byte]
      [IPv4] 192.168.1.51 -> 192.168.1.174
    1514269159.854638 90[Byte]
      [IPv4] 192.168.1.51 -> 192.168.1.174
    1514269159.854829 90[Byte]
      [IPv4] 192.168.1.51 -> 192.168.1.174
    1514269159.854877 90[Byte]
      [IPv4] 192.168.1.51 -> 192.168.1.174
    1514269159.854987 98[Byte]
      [IPv4] 192.168.1.51 -> 192.168.1.174
    1514269159.855024 90[Byte]
      [IPv4] 192.168.1.51 -> 192.168.1.174
    1514269159.855199 98[Byte]
      [IPv4] 192.168.1.51 -> 192.168.1.174


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
    >>> while dev:
    ...     print("{} ({})".format(dev.name, dev.description))
    ...     if dev.next:
    ...         dev = dev.next.contents
    ...     else:
    ...         dev = False
    ...
    b'\\Device\\NPF_{C05CB6F2-F965-46AC-A311-0D9787AC93EC}' (b'Microsoft')
    b'\\Device\\NPF_{9E497729-6883-464E-A177-74178E7AB03C}' (b'Realtek USB NIC')
    b'\\Device\\NPF_{DD007737-0821-491D-A0CD-630454C06183}' (b'TAP-Windows Adapter V9')
    >>> port = Port("\\Device\\NPF_{9E497729-6883-464E-A177-74178E7AB03C}")
    >>> hdr, buf = port.recv()
    >>> hdr.ts_sec
    1514268768
    >>> hdr.ts_usec
    578115
    >>> hdr.len
    112
    >>> buf
    b'\xff\xff\xff\xff\xff\xffRT\x00g9!\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01RT\x00g9!\xc0\xa8\x01\x01\x00\x00\x00\x00\x00\x00\xc0\xa8\x01f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
