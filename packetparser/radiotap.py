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

from datetime import timedelta

from .base import PacketContainer
from .types import UInt32, UInt16, Int8, UInt8, Int32, UInt64, Structure
from .ieee80211 import IEEE80211Frame
from .utils import field_is_set

class RadioTapTSFT(Structure):
    """
        Bitmap id: 0
        http://www.radiotap.org/defined-fields/TSFT

        Value in microseconds of the MAC's 64 - bit 802.11 Time Synchronization
        Function timer when the first bit of the MPDU arrived at the MAC. For
        received frames only.
    """
    required_alignment = 8
    attribute_list = (
        ('tsft', UInt64),
    )

    @classmethod
    def to_python(cls, data):
        return {
            'tsft': timedelta(microseconds=data.get('tsft')),
        }


class RadioTapFlags(Structure):
    """
        Bitmap id: 1
        http://www.radiotap.org/defined-fields/Flags
    """
    required_alignment = 1
    attribute_list = (
        ('flags', UInt8),
    )

    @classmethod
    def to_python(cls, data):
        flags = data.get('flags')

        return {
            'during_cfp': field_is_set(flags, 0x01),
            'with_short_preamble': field_is_set(flags, 0x02),
            'with_wep': field_is_set(flags, 0x04),
            'with_fragmentation': field_is_set(flags, 0x08),
            'with_includes_fcs': field_is_set(flags, 0x10),
            'is_padded': field_is_set(flags, 0x20),
            'failed_fcs_check': field_is_set(flags, 0x40),
        }

class RadioTapRate(Structure):
    """
        Bitmap id: 2
        http://www.radiotap.org/defined-fields/Rate
    """
    required_alignment = 1
    attribute_list = (
        ('rate', UInt8),
    )


class RadioTapChannel(Structure):
    """
        Bitmap id: 3
        http://www.radiotap.org/defined-fields/Channel
    """

    required_alignment = 2
    attribute_list = (
        ('frequency', UInt16),
        ('flags', UInt16),
    )

    @classmethod
    def to_python(cls, data):
        parsed_data = {}

        flags = data.get('flags')
        frequency = data.get('frequency')

        return {
            'frequency': frequency,
            'turbo_channel': field_is_set(flags, 0x0010),
            'cck_channel': field_is_set(flags, 0x0020),
            'ofdm_channel': field_is_set(flags, 0x0040),
            'band_2ghz': field_is_set(flags, 0x0080),
            'band_5ghz': field_is_set(flags, 0x0100),
            'passive': field_is_set(flags, 0x0200),
            'dynamic': field_is_set(flags, 0x0400),
            'gfsk': field_is_set(flags, 0x0800),
        }

        return parsed_data


class RadioTapFHSS(Structure):
    """
        Bitmap id: 4

        http://www.radiotap.org/defined-fields/FHSS
    """

    required_alignment = 1

    # NOTE: The FHSS is defined as two unsigned 8-bit types
    # (hence the alignment), while here i've used an unsigned
    # 16-bit value. This is probably wrong.

    attribute_list = (
        ('fhss', UInt16),
    )


class RadioTapAntennaSignal(Structure):
    """
        Bitmap id: 5
        http://www.radiotap.org/defined-fields/Antenna%20signal
    """

    required_alignment = 1
    attribute_list = (
        ('antenna_signal_dbm', Int8),
    )


class RadioTapAntennaNoise(Structure):
    """
        Bitmap id: 6
        http://www.radiotap.org/defined-fields/Antenna%20noise
    """

    required_alignment = 1
    attribute_list = (
        ('antenna_noise_dbm', UInt8),
    )


class RadioTapLockQuality(Structure):
    """
        Bitmap id: 7
        http://www.radiotap.org/defined-fields/Lock%20quality
    """

    required_alignment = 2
    attribute_list = (
        ('lock_quality', UInt16),
    )


class RadioTapTXAttenuation(Structure):
    """
        Bitmap id: 8
        http://www.radiotap.org/defined-fields/TX%20attenuation
    """

    required_alignment = 2
    attribute_list = (
        ('tx_attenuation', UInt16),
    )


class RadioTapDbTXAttenuation(Structure):
    """
        Bitmap id: 9
        http://www.radiotap.org/defined-fields/dB%20TX%20attenuation
    """

    required_alignment = 2
    attribute_list = (
        ('db_tx_attenuation', UInt16),
    )


class RadioTapDbmTXPower(Structure):
    """
        Bitmap id: 10
        http://www.radiotap.org/defined-fields/dBm%20TX%20power
    """

    required_alignment = 1
    attribute_list = (
        ('dbm_tx_power', Int8),
    )


class RadioTapAntenna(Structure):
    """
        Bitmap id: 11
        http://www.radiotap.org/defined-fields/Antenna
    """

    required_alignment = 1
    attribute_list = (
        ('antenna_index', UInt8),
    )


class RadioTapDbAntennaSignal(Structure):
    """
        Bitmap id: 12
        http://www.radiotap.org/defined-fields/dB%20antenna%20signal
    """

    required_alignment = 1
    attribute_list = (
        ('db_antenna_signal', UInt8),
    )


class RadioTapDbAntennaNoise(Structure):
    """
        Bitmap id: 13
        http://www.radiotap.org/defined-fields/dB%20antenna%20noise
    """

    required_alignment = 1
    attribute_list = (
        ('db_antenna_noise', UInt8),
    )


class RadioTapRXFlags(Structure):
    """
        Bitmap id: 14
        http://www.radiotap.org/defined-fields/RX%20flags
    """

    required_alignment = 2
    attribute_list = (
        ('rx_flags', UInt16),
    )

    def parse(self):
        rx_flags = self.data.get('rx_flags')

        return {
            'plcp_crc_failed': field_is_set(rx_flags, 0x0002)
        }


class RadioTapHwQueue(Structure):
    """
        Bitmap id: 15
        http://www.radiotap.org/defined-fields/

        XXX: OpenBSD specific?
    """

    attribute_list = (
    )


class RadioTapRSSI(Structure):
    """
        Bitmap id: 16
        http://www.radiotap.org/defined-fields/

        XXX: OpenBSD specific?
    """

    attribute_list = (
    )


class RadioTapBitmap(Structure):

    attribute_list = (
        ('present', UInt32),
    )


class RadioTapFrameStructure(Structure):
    attribute_list = (
        ('version', UInt8),
        ('padding', UInt8),
        ('header_length', UInt16),
    )

    @classmethod
    def to_python(cls, data):
        return {
            'version': data.get('version'),
            'header_length': data.get('header_length'),
        }



class RadiotapFrame(PacketContainer):
    """
        http://www.radiotap.org/
    """
    name = 'radiotap_frame'

    RADIOTAP_ANOTHER_BITMAP = 1 << 31

    extended_field_mapper = (
        (0, RadioTapTSFT),
        (1, RadioTapFlags),
        (2, RadioTapRate),
        (3, RadioTapChannel),
        (4, RadioTapFHSS),
        (5, RadioTapAntennaSignal),
        (6, RadioTapAntennaNoise),
        (7, RadioTapLockQuality),
        (8, RadioTapTXAttenuation),
        (9, RadioTapDbTXAttenuation),
        (10, RadioTapDbmTXPower),
        (11, RadioTapAntenna),
        (12, RadioTapDbAntennaSignal),
        (13, RadioTapDbAntennaNoise),
        (14, RadioTapRXFlags),
#        (15, RadioTapHwQueue),
#        (16, RadioTapRSSI),
    )


    @classmethod
    def parse(cls, buf, extra=None):
        i = 0
        frame_struct = RadioTapFrameStructure.unpack(buf)
        header_length = frame_struct.header_length

        radiotap_header_array = buf[:header_length]
        ieee80211_array = buf[header_length:]

        i += frame_struct.struct.size

        assert len(radiotap_header_array) == header_length

        fields_found = []
        bitmap_number = 1
        while True:
            bitmap = RadioTapBitmap.unpack(radiotap_header_array[i:])
            present_field = bitmap.present
            i += bitmap.size()

            for j in range(0, 32):
                if field_is_set(present_field, 1 << j):
                    fields_found.append(j * bitmap_number)

            # TODO: Set a limit here of max. number of bitmaps.
            if not field_is_set(present_field, cls.RADIOTAP_ANOTHER_BITMAP):
                break;

            bitmap_number += 1

        data = {}

        for bitmap_id, ext_field_cls in cls.extended_field_mapper:

            if bitmap_id in fields_found:
                req_align = ext_field_cls.required_alignment
                padding = (req_align - i % req_align) % req_align

                # TODO: test if the padding is zero
                # Test if we haven't gone beyond the end of the buffer.
                i += padding

                field_instance = ext_field_cls.unpack(radiotap_header_array[i:])
                data.update(field_instance.data)
                i += field_instance.size()

        frame = cls(data)

        extra = {
            'upper_layer': frame,
        }

        payload = IEEE80211Frame.parse(ieee80211_array, extra)

        # Attach the payload to the frame.
        frame.ieee80211_frame = payload

        return frame
