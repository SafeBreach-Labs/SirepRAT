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


Concrete implementation of the GetFileInformationFromDevice command
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import struct

import common.utils as utils
from SirepCommand import SirepCommand
from common.constants import INT_SIZE
from common.enums.CommandType import CommandType


class GetFileInformationFromDeviceCommand(SirepCommand):
    """Concrete implementation of the GetFileInformationFromDevice command"""

    def __init__(self, remote_path):
        """Described in parent class"""
        super(GetFileInformationFromDeviceCommand, self).__init__(CommandType.GetFileInformationFromDevice)
        self.remote_path = remote_path
        self.payload_length = self._calculate_payload_length()

    def _calculate_payload_length(self):
        """
        Returns the payload length of the command.

        The payload length for this command type is the unicode length of the remote path.
        """
        return len(self.remote_path) * 2

    def serialize_sirep(self):
        """Described in parent class"""
        serialized = ""
        # serialize the command global headers
        serialized += struct.pack("II", self.command_type.value, self.payload_length)
        # serialize the remote path parameter
        serialized += utils.pack_string(self.remote_path)
        return serialized

    @staticmethod
    def deserialize_sirep(self, command_buffer):
        """Described in parent class"""
        remote_path = utils.unpack_string(command_buffer[INT_SIZE * 2:])
        return GetFileInformationFromDeviceCommand(remote_path)
