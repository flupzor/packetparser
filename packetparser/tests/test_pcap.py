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

from datetime import datetime, timedelta
from tempfile import TemporaryFile
import array
import unittest
import os

from packetparser.pcap import PcapFile
from packetparser.radiotap import RadiotapFrame
from packetparser.ieee80211 import (
    IEEE80211Frame, IEEE80211Types, IEEE80211ManagementSubtypes
)

class PcapMixin(object):
    def _create_pcap_header(self):

        magic_number = [0xd4, 0xc3, 0xb2, 0xa1,]  # Magic number which makes this frame Little endian
        version_major = [0x02, 0x00]  # Major version number
        version_minor = [0x04, 0x00]  # Minor version number
        thiszone = [0x00, 0x00, 0x00, 0x00]  # Unused field.
        sigfigs = [0x00, 0x00, 0x00, 0x00]  # Unused field.
        snaplen = [0xb4, 0x00, 0x00, 0x00]  # 180 bytes
        network = [0x7f, 0x00, 0x00, 0x00]  # IEEE80211 Radiotap

        header_frame = magic_number + version_major + \
            version_minor + thiszone + sigfigs + snaplen + network

        header_frame_array = array.array('B', header_frame)

        return header_frame_array

    def _assert_pcap_header(self, pcap_header):

        self.assertEquals(pcap_header.swapped, True)
        self.assertEquals(pcap_header.version_major, 2)
        self.assertEquals(pcap_header.version_minor, 4)
        self.assertEquals(pcap_header.tzoff, timedelta(seconds=0))
        self.assertEquals(pcap_header.sigfigs, 0)
        self.assertEquals(pcap_header.snaplen, 180)
        self.assertEquals(pcap_header.network, 127)

    def _create_pcap_frame(self, incl_len, orig_len=None):
        ts_sec = [0x01, 0x00, 0x00, 0x00]  # 1970-1-1 00:00:01
        ts_usec = [0x01, 0x00, 0x00, 0x00]  # + 1 microseconds

        incl_len = incl_len
        if not orig_len:
            orig_len = incl_len

        frame = ts_sec + ts_usec + incl_len + orig_len

        frame_array = array.array('B', frame)

        return frame_array

    def _assert_pcap_frame(self, pcap_frame, length, orig_length):
        self.assertEquals(pcap_frame.time_recorded, datetime(1970, 1, 1, 0, 0, 1, 1))
        self.assertEquals(pcap_frame.len, length)
        self.assertEquals(pcap_frame.orig_len, orig_length)
        self.assertIsInstance(pcap_frame.radiotap_frame, RadiotapFrame)


class RadiotapMixin(object):
    def _create_radiotap_frame(self):

        version = [0x00, ]
        padding = [0x00, ]
        header_length = [0x11, 0x00]  # 17 bytes
        bitmap = [0x2e, 0x18, 0x00, 0x00]  # Enabled: Flags, Rate, Channel, AntennaSignal
                                           # Antenna, db Antenna Signal

        flags = [0x00, ]  # no flags set
        rate = [0x02, ]  # 1.0 mbps
        channel = [0x60, 0x09, 0x80, 0x00]  # Frequency: 2400mhz
                                            # Flag: 2ghz_channel

        antenna_signal = [0xc3, ]  # -61 dbM
        antenna = [0x00, ]
        antenna_db_signal = [0x00, ]

        frame = version + padding + header_length + bitmap \
                        + flags + rate + channel + antenna_signal \
                        + antenna + antenna_db_signal

        frame_array = array.array('B', frame)

        return frame_array

    def _assert_radiotap_frame(self, radiotap_frame):
        # RadioTapFlags
        self.assertEquals(radiotap_frame.during_cfp, False)
        self.assertEquals(radiotap_frame.with_short_preamble, False)
        self.assertEquals(radiotap_frame.with_wep, False)
        self.assertEquals(radiotap_frame.with_fragmentation, False)
        self.assertEquals(radiotap_frame.with_includes_fcs, False)
        self.assertEquals(radiotap_frame.is_padded, False)
        self.assertEquals(radiotap_frame.failed_fcs_check, False)

        # RadioTapChannel
        self.assertEquals(radiotap_frame.frequency, 2400)
        self.assertEquals(radiotap_frame.turbo_channel, False)
        self.assertEquals(radiotap_frame.cck_channel, False)
        self.assertEquals(radiotap_frame.ofdm_channel, False)
        self.assertEquals(radiotap_frame.band_2ghz, True)
        self.assertEquals(radiotap_frame.band_5ghz, False)
        self.assertEquals(radiotap_frame.passive, False)
        self.assertEquals(radiotap_frame.dynamic, False)
        self.assertEquals(radiotap_frame.gfsk, False)

        self.assertIsInstance(radiotap_frame.ieee80211_frame, IEEE80211Frame)


class IEEE80211Tests(object):

    def _create_ieee80211_data_frame(self):
        fc = [0x80, 0x20] # DATA, CFPOLL??

    def _create_ieee80211_probe_request_frame(self):
        fc = [0x40, 0x00] # Probe request

        dur = [0x00, 0x00]
        addr1 = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]  # Destination address
        addr2 = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11]  # Source address
        addr3 = [0x22, 0x22, 0x22, 0x22, 0x22, 0x22]  # BSS ID
        seq = [0x01, 0x00]

        # SSID, page 95
        ssid = [0x00, 0x04, ord('A'), ord('B'), ord('C'), ord('D')]  # element 0, length 4, "ABCD"

        # Supported rates; Page 97
        supported_rates = [0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24,  # element: 1, length 8
                           0x30, 0x48, 0x6c ]                         # 1(B), 2(B), 5.5(B), 11(B)
                                                                      # 18, 24, 36, 54
        # XXX: Extended supported rates;

        frame = fc + dur + addr1 + addr2 + addr3 + seq + ssid + supported_rates
        frame_array = array.array('B', frame)

        return frame_array

    def _assert_ieee80211_probe_request_frame(self, ieee80211_frame):
        self.assertEquals(ieee80211_frame.version, 0)

        # For frame types see page 49
        self.assertEquals(ieee80211_frame.type, IEEE80211Types.MANAGEMENT)
        self.assertEquals(ieee80211_frame.subtype, IEEE80211ManagementSubtypes.PROBE_REQ)

        # TODO: Is this correct?
        self.assertEquals(ieee80211_frame.fromds, False)
        self.assertEquals(ieee80211_frame.tods, False)

        # Page 109
        self.assertEquals(ieee80211_frame.addr1, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
        self.assertEquals(ieee80211_frame.addr2, [0x11, 0x11, 0x11, 0x11, 0x11, 0x11])
        self.assertEquals(ieee80211_frame.addr3, [0x22, 0x22, 0x22, 0x22, 0x22, 0x22])

        self.assertEquals(ieee80211_frame.seq, 1)

        self.assertEquals(ieee80211_frame.ssid, "ABCD")

        self.assertEquals(ieee80211_frame.supported_rates_mandatory, [1, 2, 5.5, 11])
        self.assertEquals(ieee80211_frame.supported_rates_optional, [18, 24, 36, 54])

    def _create_ieee80211_beacon_frame(self):
        # 802.11 Wireless Network The Definitive Guide - Page 109

        fc = [0x80, 0x00] # fc[0] = Beacon frame
                          # fc[1] = Nothing set.
        dur = [0x00, 0x00] # Seconds
        addr1 = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]  # Destination address
        addr2 = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11]  # Source address
        addr3 = [0x22, 0x22, 0x22, 0x22, 0x22, 0x22]  # BSS ID
        seq = [0x01, 0x00]

        # Fixed parameters
        timestamp = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        beacon_interval = [0x64, 0x00]
        capability_info = [0x00, 0x00]

        # Tagged parameters

        # SSID, page 95
        ssid = [0x00, 0x04, ord('A'), ord('B'), ord('C'), ord('D')]  # element 0, length 4, "ABCD"

        # Supported rates; Page 97
        supported_rates = [0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24,  # element: 1, length 8
                           0x30, 0x48, 0x6c ]                         # 1(M), 2(M), 5.5(M), 11(M)
                                                                      # 18(O), 24(O), 36(O), 54(O)

        # Traffic Indication Map
        traffic_indication_map = [0x05, 0x04, 0x00, 0x01, 0x00, 0x00] # element 5, length: 4
                                                                      # DTIM count: 0 DTIM period: 1
                                                                      # Bitmap: 0

        frame = fc + dur + addr1 + addr2 + addr3 + seq + timestamp + beacon_interval + capability_info + \
                ssid + supported_rates + traffic_indication_map

        frame_array = array.array('B', frame)

        return frame_array

    def _assert_ieee80211_beacon_frame(self, ieee80211_frame):
        self.assertEquals(ieee80211_frame.version, 0)

        # For frame types see page 49
        self.assertEquals(ieee80211_frame.type, IEEE80211Types.MANAGEMENT)
        self.assertEquals(ieee80211_frame.subtype, IEEE80211ManagementSubtypes.BEACON)

        # TODO: Is this correct?
        # I think a beacon frame should have both set to False, like in an IBSS.
        self.assertEquals(ieee80211_frame.fromds, False)
        self.assertEquals(ieee80211_frame.tods, False)

        # Page 109
        self.assertEquals(ieee80211_frame.addr1, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
        self.assertEquals(ieee80211_frame.addr2, [0x11, 0x11, 0x11, 0x11, 0x11, 0x11])
        self.assertEquals(ieee80211_frame.addr3, [0x22, 0x22, 0x22, 0x22, 0x22, 0x22])

        self.assertEquals(ieee80211_frame.seq, 1)
        self.assertEquals(ieee80211_frame.timestamp, 0) # Microseconds since it has been active; Page 91
        self.assertEquals(ieee80211_frame.beacon_interval, timedelta(microseconds=102400))  # 0x64 -> 100 TU
                                                                                            # 1 TU = 1024 microseconds
                                                                                            # ((100 / (1000/1024.0)) / 1000) = 0.1024 seconds

        self.assertEquals(ieee80211_frame.capability_ess, False)  # Page 88, capability information.
        self.assertEquals(ieee80211_frame.capability_ibss, False)
        self.assertEquals(ieee80211_frame.capability_privacy, False)
        self.assertEquals(ieee80211_frame.capability_short_preamble, False)
        self.assertEquals(ieee80211_frame.capability_pbcc, False)
        self.assertEquals(ieee80211_frame.capability_channel_agility, False)
        self.assertEquals(ieee80211_frame.capability_short_slot_time, False)
        self.assertEquals(ieee80211_frame.capability_dss_ofdm, False)

# Not implemented yet.
#        self.assertEquals(ieee80211_frame.capability_polling_not_supported, False)
#        self.assertEquals(ieee80211_frame.capability_polling_supported_no_list, False)
#        self.assertEquals(ieee80211_frame.capability_polling_supported_on_list, False)
#        self.assertEquals(ieee80211_frame.capability_polling_supported_never_polled, False)
#        self.assertEquals(ieee80211_frame.capability_polling_no_pcf, True)

        self.assertEquals(ieee80211_frame.ssid, "ABCD")

        self.assertEquals(ieee80211_frame.supported_rates_mandatory, [1, 2, 5.5, 11])
        self.assertEquals(ieee80211_frame.supported_rates_optional, [18, 24, 36, 54])

        self.assertEquals(ieee80211_frame.dtim_count, 0)
        self.assertEquals(ieee80211_frame.dtim_period, 1)
        self.assertEquals(ieee80211_frame.dtim_multicast_buffered, False)
        self.assertEquals(ieee80211_frame.dtim_bitmap_offset, 0)
        self.assertEquals(ieee80211_frame.dtim_bitmap, [0x00, ])


class ApiTests(IEEE80211Tests, RadiotapMixin, PcapMixin, unittest.TestCase):

    def _pcap_file_with_beacon_frame(self):
        return self._create_pcap_header() + \
               self._create_pcap_frame(
                   incl_len=[0x4b, 0x00, 0x00, 0x00]  # 75 bytes
               ) + \
               self._create_radiotap_frame() + \
               self._create_ieee80211_beacon_frame()

    def _pcap_file_with_probe_request_frame(self):
        return self._create_pcap_header() + \
               self._create_pcap_frame(
                   incl_len=[0x39, 0x00, 0x00, 0x00]  # 57 bytes
                ) + \
               self._create_radiotap_frame() + \
               self._create_ieee80211_probe_request_frame()

    def test_pcap_create(self):
        with TemporaryFile() as f:
            data = {
                'snaplen': 180,
                'network': 127,
            }

            pcap_file = PcapFile(data, f)
            pcap_file.write_header()
            written_data = array.array('B')
            f.seek(0)
            written_data.fromstring(f.read())

            expected = self._create_pcap_header()

            self.assertEquals(expected, written_data)

    def test_pcap_parse(self):

        # Create/Parse IEEE802111 Frame with a beacon frame.
        with TemporaryFile() as f:
            pcap_file_array = self._pcap_file_with_beacon_frame()
            pcap_file_array.tofile(f)
            f.seek(0)

            pcap_header = PcapFile.parse_header(f)
            self._assert_pcap_header(pcap_header)

            pcap_frames = list(pcap_header.frames())

            self.assertEqual(len(pcap_frames), 1)
            pcap_frame = pcap_frames[0]

            self._assert_pcap_frame(
                pcap_frame,
                length=75,
                orig_length=75
            )

            radiotap_frame = pcap_frame.radiotap_frame
            self._assert_radiotap_frame(radiotap_frame)

            ieee80211_frame = radiotap_frame.ieee80211_frame
            self._assert_ieee80211_beacon_frame(ieee80211_frame)

        # Create/Parse IEEE802111 Frame with a probe request frame.
        with TemporaryFile() as f:
            pcap_file_array = self._pcap_file_with_probe_request_frame()
            pcap_file_array.tofile(f)
            f.seek(0)

            pcap_header = PcapFile.parse_header(f)
            self._assert_pcap_header(pcap_header)

            pcap_frames = list(pcap_header.frames())

            self.assertEqual(len(pcap_frames), 1)
            pcap_frame = pcap_frames[0]
            self._assert_pcap_frame(
                pcap_frame,
                length=57,
                orig_length=57
            )

            radiotap_frame = pcap_frame.radiotap_frame
            self._assert_radiotap_frame(radiotap_frame)

            ieee80211_frame = radiotap_frame.ieee80211_frame
            self._assert_ieee80211_probe_request_frame(ieee80211_frame)

    def test_pcap_parse_multiple_frames(self):
        with TemporaryFile() as f:
            pcap_file_array = self._create_pcap_header()

            # Create 100 frames.
            for i in range(100):
                pcap_file_array += self._create_pcap_frame(
                   incl_len=[0x39, 0x00, 0x00, 0x00]  # 57 bytes
                ) + \
                self._create_radiotap_frame() + \
                self._create_ieee80211_probe_request_frame()

            pcap_file_array.tofile(f)

            f.seek(0)

            pcap_header = PcapFile.parse_header(f)
            self._assert_pcap_header(pcap_header)

            for pcap_frame in pcap_header.frames():
                self._assert_pcap_frame(
                    pcap_frame,
                    length=57,
                    orig_length=57
                )

            pcap_frames = list(pcap_header.frames())
            self.assertEqual(len(pcap_frames), 100)
