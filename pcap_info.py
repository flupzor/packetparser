#!/usr/bin/env python

#
# Copyright (c) 2015 Alexander Schrijver <alex@flupzor.nl>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import sys

from packetparser.pcap import PcapFile
from packetparser.ieee80211 import ieee80211_type_to_str, ieee80211_subtype_to_str

def print_radiotap_info(radiotap_frame):
    radiotap_options = "frequency: {0}".format(radiotap_frame.frequency)
    radiotap_options += ", during cfp" if radiotap_frame.during_cfp else ""
    radiotap_options += ", with short preamble: " if radiotap_frame.with_short_preamble else ""
    radiotap_options += ", with wep" if radiotap_frame.with_wep else ""
    radiotap_options += ", with fragmentation" if radiotap_frame.with_fragmentation else ""
    radiotap_options += ", with includes fcs" if radiotap_frame.with_includes_fcs else ""
    radiotap_options += ", is padded" if radiotap_frame.is_padded else ""
    radiotap_options += ", failed fcs check" if radiotap_frame.failed_fcs_check else ""
    radiotap_options += ", turbo channel" if radiotap_frame.turbo_channel else ""
    radiotap_options += ", cck_channel" if radiotap_frame.cck_channel else ""
    radiotap_options += ", ofdm_channel" if radiotap_frame.ofdm_channel else ""
    radiotap_options += ", band 2ghz" if radiotap_frame.band_2ghz else ""
    radiotap_options += ", band 5ghz" if radiotap_frame.band_5ghz else ""
    radiotap_options += ", passive " if radiotap_frame.passive else ""
    radiotap_options += ", dynamic" if radiotap_frame.dynamic else ""
    radiotap_options += ", gfsk" if radiotap_frame.gfsk else ""
    print "  radiotap frame " + radiotap_options

def print_pcap_frame_info(frame_number, pcap_frame):
    pcap_frame_options = "recorded: {0}".format(pcap_frame.time_recorded)
    pcap_frame_options += ", length: {0}".format(pcap_frame.len)
    pcap_frame_options += ", original length: {0}".format(pcap_frame.orig_len)

    print(" pcap frame (" + str(frame_number) + "): " + pcap_frame_options)

def print_ieee80211_frame_info(ieee80211_frame):
    print "   ieee80211 frame type: " + ieee80211_type_to_str.get(ieee80211_frame.type) + " subtype: " + ieee80211_subtype_to_str.get(ieee80211_frame.type).get(ieee80211_frame.subtype)

def print_pcap_file_info(pcap_file):

    pcap_file_options = "version: {0}.{1}".format(pcap_file.version_major, pcap_file.version_minor)
    pcap_file_options += ', little endian' if pcap_file.swapped else 'big endian'
    pcap_file_options += ', tzoff: {0}'.format(pcap_file.tzoff) if pcap_file.tzoff else ''
    pcap_file_options += ', sigfigs: {0}'.format(pcap_file.sigfigs) if pcap_file.sigfigs else ''
    pcap_file_options += ", snaplen: {0}".format(pcap_file.snaplen)
    pcap_file_options += ", network type: {0}".format(pcap_file.network)

    print("pcap file " + pcap_file_options)

    frame_count = 0
    for pcap_frame in pcap_file.frames():
        print_pcap_frame_info(frame_count, pcap_frame)
        print_radiotap_info(pcap_frame.radiotap_frame)
        print_ieee80211_frame_info(pcap_frame.radiotap_frame.ieee80211_frame)

        frame_count += 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write("usage: {cmd} <filename> ...\n")
        sys.exit(1)  # EXIT_FAILURE

    for filename in sys.argv[1:]:
        file_handle = open(filename, 'rb')
        pcap_file = PcapFile.parse_header(file_handle)

        print_pcap_file_info(pcap_file)
