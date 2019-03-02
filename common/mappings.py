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


Mappings used for main SirepRAT, based on the Sirep protocol
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-02-04 08:03:08
"""

import types

from enums.CommandType import CommandType
from enums.ResultRecordType import ResultRecordType
from models import commands
from models import results


def _load_sirep_commands(module, base_class, type_enum, suffix_length):
    """Loads all available classes from the given module direcroty"""
    _sirep_commands = {}
    for symbol_name in dir(module):
        symbol = getattr(module, symbol_name)
        if not isinstance(symbol, (type, types.ClassType)):
            continue
        # fill only classes that derive from given base class
        if issubclass(symbol, base_class) and \
                symbol != base_class:
            _sirep_commands[getattr(type_enum, symbol_name[:-suffix_length])] = symbol
    return _sirep_commands


# maps available Sirep CommandType to its corresponding command class
SIREP_COMMANDS = _load_sirep_commands(commands, commands.SirepCommand, CommandType, 7)

RESULT_TYPE_TO_RESULT = {
    ResultRecordType.SystemInformation.value: results.SystemInformationResult,
    ResultRecordType.HResult.value: results.HResultResult,
    ResultRecordType.OutputStream.value: results.OutputStreamResult,
    ResultRecordType.ErrorStream.value: results.ErrorStreamResult,
    ResultRecordType.File.value: results.FileResult,
    ResultRecordType.FileInformation.value: results.FileInformationResult,
}
