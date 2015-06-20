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
from .types import Structure, UInt8, UInt16, Array, LittleEndian
from .ieee80211_fields import (
    IEEE80211TimestampField, IEEE80211BeaconIntervalField,
    IEEE80211CapabilityInformationField
)
from .ieee80211_elements import (
    IEEE80211Element,
    IEEE80211TIM
)

from .ieee80211_types import (
    IEEE80211Types, ieee80211_type_to_str, IEEE80211ManagementSubtypes,
    ieee80211_management_subtype_to_str, IEEE80211ControlSubtypes,
    ieee80211_control_subtype_to_str, IEEE80211DataSubtypes,
    ieee80211_data_subtype_to_str, ieee80211_subtype_to_str
)

from .ieee80211_structures import (
    IEEE80211MinimalFrameStructure, IEEE80211FrameStructure
)


class IEEE80211Frame(PacketContainer):
    name='ieee80211_frame'

    @classmethod
    def process_element(cls, buf):
        element = IEEE80211Element.unpack(buf)

        i = element.struct.size

        data = {}
        if element.element_id == element.ELEMENT_SSID:
            # 802.11-2012 8.4.2.2

            ssid = buf[i:i+element.length]
            data.update({
                'ssid': ssid.tostring(),
                'ssid_invalid_length': element.length > 32  # SSIDs can be at most 32 octets
            })
        elif element.element_id == element.ELEMENT_SUPPORTED_RATES:
            # 8.4.2.3
            # TODO: The (HT PHY) membership selector is not implemented.

            supported_rates_buf = buf[i:i+element.length]

            j = 0
            mandatory_rates = []
            optional_rates = []
            while j < len(supported_rates_buf):

                if supported_rates_buf[j] & 0x80 == 0x80:
                    rate_in_500kbps = supported_rates_buf[j] & 0x7f
                    rate_in_mbps = rate_in_500kbps / 2.0
                    mandatory_rates.append(rate_in_mbps)
                else:
                    rate_in_500kbps = supported_rates_buf[j]
                    rate_in_mbps = rate_in_500kbps / 2.0
                    optional_rates.append(rate_in_mbps)

                j += 1

            data.update({
                'supported_rates_mandatory': mandatory_rates,
                'supported_rates_optional': optional_rates,
            })
        elif element.element_id == element.ELEMENT_TIM:
            tim_buf = buf[i:i+element.length]

            tim_element = IEEE80211TIM.unpack(tim_buf)

            data.update({
                'dtim_count': tim_element.dtim_count,
                'dtim_period': tim_element.dtim_period,
                'dtim_multicast_buffered': bool(tim_element.bitmap_control & 0x80),
                'dtim_bitmap_offset': tim_element.bitmap_control & 0x7f,
                'dtim_bitmap': tim_buf[tim_element.struct.size:].tolist()
            })

            # TODO: The virtual bitmap isn't processed yet.

        elif element.element_id == element.ELEMENT_DSSS_PARAMETER_SET:
            # TODO: If the element length is not equal to 1 there
            # is extra data we might be interested in.
            data.update({
                'dsss_invalid_length': element.length != 1,
                'dsss_current_channel': buf[i],
            })
        elif element.element_id == element.ELEMENT_COUNTRY:
            # TODO: This needs a lot more work.
            data.update({
                'country_string': buf[i:i+3].tostring()
            })

        i+= element.length

        return data, i


class IEEE80211ManagementFrame(IEEE80211Frame):
    pass


class IEEE80211DataFrame(IEEE80211Frame):
    pass


class IEEE80211ControlFrame(IEEE80211Frame):
    pass


class IEEE80211NotSupported(IEEE80211Frame):
    @classmethod
    def parse(cls, buf, extra=None):
        frame_struct = IEEE80211MinimalFrameStructure.unpack(buf)

        frame = cls(frame_struct.data)

        return frame


class IEEE80211BeaconFrame(IEEE80211ManagementFrame):
    """
    IEEE802.11-2012 8.3.3.2
    """

    @classmethod
    def process_beacon_frame(cls, buf):

        i = 0
        data = {}

        timestamp_struct = IEEE80211TimestampField.unpack(buf)
        i += timestamp_struct.struct.size
        data.update(timestamp_struct.data)

        beacon_interval_struct = IEEE80211BeaconIntervalField.unpack(buf[i:])
        i += beacon_interval_struct.struct.size
        data.update(beacon_interval_struct.data)

        capability_info_struct = IEEE80211CapabilityInformationField.unpack(buf[i:])
        i += capability_info_struct.struct.size
        data.update(capability_info_struct.data)

        while i < len(buf):
            element_data, octets_processed = cls.process_element(buf[i:])
            i += octets_processed
            data.update(element_data)

        return data

    @classmethod
    def parse(cls, buf, extra=None):
        frame_struct = IEEE80211FrameStructure.unpack(buf)

        frame_body = buf[frame_struct.struct.size:]

        data = {}
        data.update(frame_struct.data)

        data.update(
            cls.process_beacon_frame(frame_body)
        )

        frame = cls(data)

        return frame


class IEEE80211ProbeReq(IEEE80211ManagementFrame):

    @classmethod
    def process_probe_req(cls, buf):
        i = 0
        data = {}

        while i < len(buf):
            element_data, octets_processed = cls.process_element(buf[i:])
            i += octets_processed
            data.update(element_data)

        return data

    @classmethod
    def parse(cls, buf, extra=None):
        frame_struct = IEEE80211FrameStructure.unpack(buf)

        frame_body = buf[frame_struct.struct.size:]

        data = {}
        data.update(frame_struct.data)

        data.update(
            cls.process_probe_req(frame_body)
        )

        frame = cls(data)

        return frame

def to_key(t, s):
    if t == "MANAGEMENT":
        return (getattr(IEEE80211Types, t), getattr(IEEE80211ManagementSubtypes, s))
    elif t == "CONTROL":
        return (getattr(IEEE80211Types, t), getattr(IEEE80211ControlSubtypes, s))
    elif t == "DATA":
        return (getattr(IEEE80211Types, t), getattr(IEEE80211DataSubtypes, s))

    raise AssertionError("Type not supported")


ieee80211_mapping = {
    to_key('MANAGEMENT', 'BEACON'): IEEE80211BeaconFrame,
    to_key('MANAGEMENT', 'PROBE_REQ'): IEEE80211ProbeReq,
}


def parse_ieee80211_frame(buf, extra=None):
    """
    Based on the type and subtype in the given buffer create the appropriate
    IEEE80211 class instance.
    """

    frame_struct = IEEE80211MinimalFrameStructure.unpack(buf)

    frame_type = frame_struct.data.get('type')
    frame_subtype = frame_struct.data.get('subtype')

    cls = ieee80211_mapping.get((frame_type, frame_subtype)) or IEEE80211NotSupported

    return cls.parse(buf, extra)

