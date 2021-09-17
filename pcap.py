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

pcap_packet_header_fields = [
    "ts_seconds",
    "ts_micro_nano",
    "payload_length",
    "untruncated_length",
]

datagram_header_fields = [
    "version",
    "ihl",
    "dscp",
    "ecn",
    "total_length",
    "identification",
    "flags",
    "fragment_offset",
    "ttl",
    "protocol",
    "checksum",
    "source_ip",
    "destination_ip",
]

pcap_file_header_length = 24

pcap_packet_header_length = 16

ethernet_header_length = 14

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="parse a captured pcap file")
    parser.add_argument("path", help="path to file to be parsed")
    parser.add_argument('-o', '--output',
                        help='write to given destination file')
    args = parser.parse_args()

    with open(args.path, "rb") as file:
        count = 0

        nt_fh = namedtuple("FileHeader", pcap_file_header_fields)

        file_headers = nt_fh(
            *struct.unpack("IHHIIII", file.read(pcap_file_header_length))
        )

        # check magic number
        assert 0xA1B2C3D4 == file_headers.magic_number

        snap_length = file_headers.snap_length

        data = {}
        while True:
            nt_ph = namedtuple("PcapHeader", pcap_packet_header_fields)

            if len(file.peek()) > 0:
                packet_headers = nt_ph(
                    *struct.unpack("IIII", file.read(pcap_packet_header_length))
                )

                frame = file.read(packet_headers.payload_length)

                nt_eh = namedtuple(
                    "EthernetHeader", ["dest_mac_addr", "src_mac_addr", "ether_type"]
                )

                frame_headers = nt_eh(frame[0:6], frame[6:12], frame[12:14])

                # this assumes an ipv4 protocol
                datagram = frame[ethernet_header_length:]

                # the bitmask of "& 0x0f" removes the value from greater significant byte (ex: (first binary number is the ip version) 0100 XXXX & 0000 0000 === 0000 XXXX)
                # the remaining value (header length) is muliplied by 4 to see how many 32-bit words are in the header
                datagram_ihl = (datagram[0] & 0x0F) * 4

                destination_addr = datagram[16:20]

                segment = datagram[datagram_ihl:]

                # get data offset for tcp segment
                # bit shift instead of mask here since the data we need is the most significant byte
                tcp_header_length = (segment[12] >> 4) * 4

                segment_SYN_header = (segment[13] >> 1) & 0x01

                segment_seq_number_header = segment[4:7]

                tcp_payload = segment[tcp_header_length:]

                if tuple(destination_addr) == (192, 168, 0, 101) and not segment_SYN_header:
                    data[segment_seq_number_header] = tcp_payload

                count += 1
            else:
                # print(count, data)
                break


        http_payload = b''.join(d for _, d in sorted(data.items()))
        http_header, http_payload = http_payload.split(b'\r\n\r\n', 1)


        with open(args.output, 'wb') as file:
            file.write(http_payload)
            print('wrote to file', args.output)
