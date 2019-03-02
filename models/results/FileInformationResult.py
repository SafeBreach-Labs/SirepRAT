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


Concrete implementation of the FileInformation result
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import struct

import common.utils as utils
from SirepResult import SirepResult
from common.constants import FILE_INFORMATION_SIZE


class FileInformationResult(SirepResult):
    """Concrete implementation of the FileInformation result"""

    def __init__(self, raw_data):
        """Described in parent class"""
        super(FileInformationResult,
              self).__init__(raw_data, data_size=FILE_INFORMATION_SIZE)

    @staticmethod
    def _parse_payload_to_kv(result_payload):
        """Described in parent class"""
        kv = super(FileInformationResult,
                   FileInformationResult)._parse_payload_to_kv(result_payload)
        HResult, \
        kv['dwFileAttributes'], \
        nFileSizeLow, \
        nFileSizeHigh, \
        dwLowDateTime_Created, \
        dwHighDateTime_Created, \
        dwLowDateTime_LastAccess, \
        dwHighDateTime_LastAccess, \
        dwLowDateTime_LastWrite, \
        dwHighDateTime_LastWrite = \
            struct.unpack("IIIIIIIIII", result_payload[:FILE_INFORMATION_SIZE])
        if HResult == 0x0:
            kv['file_size'] = utils.windows_low_high_to_int(nFileSizeLow, nFileSizeHigh)
            kv['time_created'] = utils.windows_filetime_to_string(dwLowDateTime_Created, dwHighDateTime_Created)
            kv['time_last_access'] = utils.windows_filetime_to_string(dwLowDateTime_LastAccess,
                                                                      dwHighDateTime_LastAccess)
            kv['time_last_write'] = utils.windows_filetime_to_string(dwLowDateTime_LastWrite, dwHighDateTime_LastWrite)
        kv['HResult'] = hex(HResult)
        return kv

    def __str__(self):
        """Described in parent class"""
        return "<FileInformationResult | type: %s, payload length: %s, kv: %s>" % (
            self.result_type, self.payload_length, str(self.parsed_kv))
