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

Recommend to use virtualenv.

::

    $ python -m venv --copies ~/.venvs/pppcap
    $ source ~/.venvs/pppcap/bin/activate
    (pppcap)$ python setup.py install
    or
    (pppcap)$ pip install git+ssh://git@github.com/ainoniwa/pppcap

The pppcap uses wpcap or pcap native library.
So, should have capability `CAP_NET_RAW` and `CAP_NET_ADMIN` to use on Linux.

::

    (pppcap)$ sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' $(which python)


Example
=======================================================================
Recv

::

    >>> from pppcap import Pppcap
    >>> eno1 = Pppcap("eno1")
    >>> buf, stop = eno1.capture()
    >>> for hdr, pkt in buf:
    ...     print("{}.{} {}[Byte]".format(hdr.ts.tv_sec, hdr.ts.tv_usec, hdr.len))
    ...     stop()
    ...     break
    ... 
    1604399617.222295 60[Byte]

Send

::

    >>> from pppcap import Pppcap
    >>> eno1 = Pppcap("eno1")
    >>> buf = bytes.fromhex("{eth} {ipv4} {udp} {data}".format(
            eth ="020000000001 020000000002 0800",
            ipv4="4500 0020 0000 0000 4011 0000 c0a80001 c0a80002",
            udp ="f001 f002 000c 0000",
            data="ffff ffff"
        ))
    >>> eno1.send(buf)

tcpdump view

::

    $ sudo tcpdump -eni eno1 udp port 61441 -c1 -X 2> /dev/null
    20:55:07.989777 02:00:00:00:00:02 > 02:00:00:00:00:01, ethertype IPv4 (0x0800), length 46: 192.168.0.1.61441 > 192.168.0.2.61442: UDP, length 4
            0x0000:  4500 0020 0000 0000 4011 0000 c0a8 0001  E.......@.......
            0x0010:  c0a8 0002 f001 f002 000c 0000 ffff ffff  ................
