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


Concrete implementation of the SystemInformation result
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import struct

from SirepResult import SirepResult
from common.constants import OS_VERSION_INFO_EX_SIZE


class SystemInformationResult(SirepResult):
    """Concrete implementation of the SystemInformation result"""

    def __init__(self, raw_data):
        """Described in parent class"""
        super(SystemInformationResult,
              self).__init__(raw_data, data_size=OS_VERSION_INFO_EX_SIZE)

    @staticmethod
    def _parse_payload_to_kv(result_payload):
        """Described in parent class"""
        kv = super(SystemInformationResult,
                   SystemInformationResult)._parse_payload_to_kv(result_payload)
        kv['dwOSVersionInfoSize'], \
        kv['dwMajorVersion'], \
        kv['dwMinorVersion'], \
        kv['dwBuildNumber'], \
        kv['dwPlatformId'], \
        kv['szCSDVersion'], \
        kv['wServicePackMajor'], \
        kv['wServicePackMinor'], \
        kv['wSuiteMask'], \
        kv['wProductType'], \
        kv['wReserved'] = \
            struct.unpack("IIIIIIHHHBB", result_payload[:OS_VERSION_INFO_EX_SIZE])
        return kv

    def __str__(self):
        """Described in parent class"""
        return "<SystemInformationResult | type: %s, payload length: %s, kv: %s>" % (
            self.result_type, self.payload_length, str(self.parsed_kv))
