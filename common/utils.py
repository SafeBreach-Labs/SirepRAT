#!/usr/bin/env python
"""
BSD 3-Clause License

Copyright (c) 2017, SafeBreach Labs
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Helper functions
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import struct
from datetime import datetime

from common.constants import MOUSTACHE_PREFIX, MOUSTACHE_SUFFIX

# http://support.microsoft.com/kb/167296
EPOCH_FILETIME = 116444736000000000
HUNDRED_NANOSECONDS = 10000000


def string_to_unicode(string_):
    """Converts a given ASCII string to unicode"""
    return "".join([c.ljust(2, "\x00") for c in string_])


def pack_string(string_):
    """
    Returns given string, binary packed according to the Sirep protocol.

    The given ASCII string is converted to the Sirep compatible struct:
    -------------------------------------------------
    |		Integer		|		Unicode bytes		|
    -------------------0x4-------------------------len
    |	length in bytes	|		Unicode chars		|
    -------------------------------------------------
    """
    return struct.pack("%ss" % (len(string_) * 2), string_to_unicode(string_))


def unpack_string(data):
    """
    Returns the packed string as an ASCII string.

    Unpacks a binary packed string from a Sirep protocol buffer.
    """
    if len(data) < 4:
        return ""
    string_size = struct.unpack("I", data[:4])[0]
    return struct.unpack("%ss" % string_size, data[4:4 + string_size])[0].replace("\x00", "")


def unpack_bytes(data, data_size=None):
    """
    """
    if len(data) < 4:
        return ""
    if data_size is None:
        data_size = struct.unpack("I", data[:4])[0]
        return struct.unpack("%ss" % data_size, data[4:4 + data_size])[0]
    else:
        return struct.unpack("%ss" % data_size, data[:data_size])[0]


def moustache_to_env_var(string_):
    """Converts moustaches in the given string to environment variable references"""
    return string_.replace(MOUSTACHE_PREFIX, '%').replace(MOUSTACHE_SUFFIX, '%')


def windows_filetime_to_string(windows_filetime_low, windows_filetime_high):
    """Returns a datetime string given a windows FILETIME value"""
    windows_filetime = windows_low_high_to_int(windows_filetime_low, windows_filetime_high)
    return str(datetime.fromtimestamp((windows_filetime - EPOCH_FILETIME) / HUNDRED_NANOSECONDS))


def windows_low_high_to_int(windows_int_low, windows_int_high):
    """Returns an int given the low and high integers"""
    return (windows_int_high << 32) + windows_int_low
