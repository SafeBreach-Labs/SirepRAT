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


Concrete implementation of the PutFileOnDevice command
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import common.utils as utils
from .SirepCommand import SirepCommand
from common.enums.CommandType import CommandType
from common.constants import INT_SIZE
from common.enums.WriteRecordType import WriteRecordType


class PutFileOnDeviceCommand(SirepCommand):
    def __init__(self, remote_path, data=""):
        super(PutFileOnDeviceCommand, self).__init__(CommandType.PutFileOnDevice)
        self.remote_path = remote_path
        self.data = data
        self.write_record_type = WriteRecordType.RegularChunk
        self.data_length = len(data) * 2
        self.payload_length = self._calculate_payload_length()

    def _calculate_payload_length(self):
        return len(self.remote_path) * 2

    def serialize_sirep(self):
        """Described in parent class"""
        return b''.join((
            utils.pack_uint(self.command_type.value),
            utils.pack_string(self.remote_path),
            utils.pack_uint(self.write_record_type.value),
            utils.pack_string(self.data),
            ))

    @staticmethod
    def deserialize_sirep(self, command_buffer):
        command_type, payload_length = utils.unpack_uints(command_buffer[:2*INT_SIZE])
        remote_path, data = utils.unpack_strings(command_buffer[2*INT_SIZE:])
        return PutFileOnDeviceCommand(remote_path, data)

