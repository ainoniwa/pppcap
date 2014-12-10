#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name="pppcap",
    version="1.0",
    author="Ruy",
    author_email="ruy.suzu7(at)gmail.com",
    url="https://github.com/ainoniwa/pppcap",
    description="Pppcap: pure python wrapper for libpcap/winpcap",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: System :: Networking",
    ],
    packages = ["pppcap"],
)