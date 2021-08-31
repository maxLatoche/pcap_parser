#!/usr/bin/env python3

"""
This script parses packets.
"""

import argparse
from collections import namedtuple
import struct

pcap_file_header_fields = [
    "magic_number",
    "major_version",
    "minor_version",
    "tz_offset",
    "tz_accuracy",
    "snap_length",
    "link_type",
]

pcap_packet_header_fields = ['ts_seconds', 'ts_micro_nano', 'payload_length',
                             'untruncated_length']

pcap_file_header_length = 24

pcap_packet_header_length = 16

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="parse a captured pcap file")
    parser.add_argument("path", help="path to file to be parsed")
    args = parser.parse_args()

    with open(args.path, "rb") as file:
        count = 0

        nt_fh = namedtuple("FileHeader", pcap_file_header_fields)

        file_headers = nt_fh(*struct.unpack("IHHIIII", file.read(pcap_file_header_length)))

        # check magic number
        assert 0xa1b2c3d4 == file_headers.magic_number

        snap_length = file_headers.snap_length

        while True:
            nt_ph = namedtuple("PcapHeader", pcap_packet_header_fields)

            if len(file.peek()) > 0:
                packet_headers = nt_ph(*struct.unpack("IIII", file.read(pcap_packet_header_length)))

                payload_length = packet_headers.payload_length


                data = file.read(payload_length)

                count += 1
            else:
                print(count)
                break
