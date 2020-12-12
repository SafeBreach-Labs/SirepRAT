#!/usr/bin/env python3
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

from common.constants import INT_SIZE, MOUSTACHE_PREFIX, MOUSTACHE_SUFFIX

# http://support.microsoft.com/kb/167296
EPOCH_FILETIME = 116444736000000000
HUNDRED_NANOSECONDS = 10000000


SIREP_ENCODING = 'utf-16le'


def pack_uint(uint):
    return struct.pack('I', uint)


def pack_uints(*uints):
    return struct.pack('I'*len(uints), *uints)


def pack_string(string):
    """
    Returns given string, binary packed according to the Sirep protocol.

    Sirep encodes strings in UTF-16 little endian, with a 4-byte unsigned integer in front.
    """
    encoded_string = string.encode(SIREP_ENCODING)
    return struct.pack("I%ss" % len(encoded_string), len(encoded_string), encoded_string)


def pack_string_array(*strings):
    """
    An array of strings is packed the following way:
    1. A table with the offset and length of each string as 4-byte unsigned integers
    2. The unsigned integer 0
    3. All strings concatenated
    """
    encoded_strings = [s.encode(SIREP_ENCODING) for s in strings]

    table = []
    # first offset is after the table, i.e. 2 integers for each string and the zero
    offset = (2 * len(encoded_strings) + 3) * INT_SIZE

    for length in map(len, encoded_strings):
        table += [offset, length]
        offset += length

    # add the zero
    table += [0]

    # return the packed table plus the concatenated encoded strings
    return pack_uints(*table) + b''.join(encoded_strings)


def unpack_uint(data):
    return struct.unpack('I', data)[0]


def unpack_uints(data):
    count = len(data) // INT_SIZE

    return struct.unpack('I'*count, data)


def unpack_string(data):
    """
    Returns the packed string as UTF-8 string.

    Unpacks a binary packed string from a Sirep protocol buffer.
    """
    if len(data) < INT_SIZE:
        return ''

    length = unpack_uint(data[:INT_SIZE])
    return data[INT_SIZE:INT_SIZE+length].decode(SIREP_ENCODING)


def unpack_strings(data):
    """
    Returns a tuple of multiple strings found in the data.
    """
    strings = []
    start, end = 0, INT_SIZE

    while end < len(data):
        length = unpack_uint(data[start:end])

        if length < 1:
            break

        start, end = end, end+length

        if end > len(data):
            break

        strings.append(data[start:end].decode(SIREP_ENCODING))
        start, end = end, end+INT_SIZE

    return tuple(strings)


def unpack_string_array(data):
    strings = []

    for header in data[::INT_SIZE*2]:
        offset, length = unpack_uints(header)

        if offset == 0:
            break

        strings.append(data[offset:offset+length].decode(SIREP_ENCODING))

    return tuple(strings)


def unpack_bytes(data, data_size=None):
    """
    """
    if len(data) < INT_SIZE:
        return ""
    if data_size is None:
        data_size = unpack_uint(data[:INT_SIZE])
        return struct.unpack("%ss" % data_size, data[INT_SIZE:INT_SIZE + data_size])[0]
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
    return (windows_int_high << 33) + windows_int_low

