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


Base class for all Sirep commands
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import struct
from pprint import pformat


class SirepCommand(object):
    """Base class for all Sirep commands"""

    def __init__(self, command_type):
        """Initializes the command buffer representation"""
        self.command_type = command_type
        self.payload_length = 0

    def get_command_type(self):
        """Returns the command type (type CommandType)"""
        return self.command_type

    def serialize_sirep(self):
        """
        Returns the serialzed string of the instance.

        Serialization is done according to the Sirep protocol.
        """
        return struct.pack("II", self.command_type.value, self.payload_length)

    @staticmethod
    def deserialize_sirep(self, command_buffer):
        """
        A factory for SirepCommand instances.

        Instances are built from the given binary command buffer.
        """
        command_type, payload_length = struct.unpack("II", command_buffer)
        return SirepCommand(command_type)

    def __repr__(self):
        """Returns the instance's representation"""
        return pformat(self.__dict__)

    def __str__(self):
        """Returns the instance's string representation"""
        return "<SirepCommand | type: %s, payload length: %s>" % (
            self.command_type, self.payload_length)
