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


Base class for all Sirep results
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import struct
from pprint import pformat

import common.utils as utils
from common.constants import INT_SIZE


class SirepResult(object):
    """Base class for all Sirep results"""

    def __init__(self, raw_data, data_size=None):
        """Initializes the result buffer representation"""
        result_type = struct.unpack("I", raw_data[:INT_SIZE])[0]
        result_payload = utils.unpack_bytes(raw_data[INT_SIZE:], data_size=data_size)
        self.result_type = result_type
        self.payload_length = len(result_payload)
        self.result_payload = result_payload
        self.parsed_kv = self._parse_payload_to_kv(self.result_payload)

    @staticmethod
    def _parse_payload_to_kv(result_payload):
        """Returns the parsed result data, parsed into a dictionary"""
        return {}

    def _get_payload_peek(self, size=20):
        payload_peek = ""
        if len(self.result_payload) > 0:
            if len(self.result_payload) > size:
                payload_peek = self.result_payload[:size]
            else:
                payload_peek = self.result_payload
        return payload_peek.replace("\n", "").replace("\r", "")

    def get_result_type(self):
        """Returns the result type (type ResultRecordType)"""
        return self.result_type

    def get_result_payload(self):
        """Returns the result payload"""
        return self.result_payload

    def get_parsed_kv(self):
        return self.parsed_kv

    def __repr__(self):
        """Returns the instance's representation"""
        return pformat(self.__dict__)

    def __str__(self):
        """Returns the instance's string representation"""
        return "<SirepResult | type: %s, payload length: %s>" % (
            self.result_type, self.payload_length)
