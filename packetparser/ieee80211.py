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


class IEEE80211Types:
    MANAGEMENT = 0x00
    CONTROL = 0x04
    DATA = 0x08


class IEEE80211ManagementSubtypes:
    # for TYPE_MGT
    ASSOC_REQ=0x00
    ASSOC_RESP=0x10
    REASSOC_REQ=0x20
    REASSOC_RESP=0x30
    PROBE_REQ=0x40
    PROBE_RESP=0x50
    BEACON=0x80
    ATIM=0x90
    DISASSOC=0xa0
    AUTH=0xb0
    DEAUTH=0xc0
    ACTION=0xd0
    ACTION_NOACK=0xe0	#/* 11n */


class IEEE80211ControlSubtypes:
    # for TYPE_CTL
    WRAPPER=0x70	#/* 11n */
    BAR=0x80
    BA=0x90
    PS_POLL=0xa0
    RTS=0xb0
    CTS=0xc0
    ACK=0xd0
    CF_END=0xe0
    CF_END_ACK=0xf0


class IEEE80211DataSubtypes:
    # for TYPE_DATA (bit combination)
    DATA=0x00
    CF_ACK=0x10
    CF_POLL=0x20
    CF_ACPL=0x30
    NODATA=0x40
    CFACK=0x50
    CFPOLL=0x60
    CF_ACK_CF_ACK=0x70
    QOS=0x80


class IEEE80211FrameStructure(Structure):
    """
        Described in 8.2.3 of 802.11-2012
    """
    endianness = LittleEndian
    attribute_list = (
        ('i_fc', Array(UInt8, 2)),
        ('i_dur', Array(UInt8, 2)),

        ('i_addr1', Array(UInt8, 6)),
        ('i_addr2', Array(UInt8, 6)),
        ('i_addr3', Array(UInt8, 6)),

        ('i_seq', UInt16),
    )

    # 80211-2012 8.2.4.1.1
    FC0_VERSION_MASK = 0x03 << 0
    FC0_TYPE_MASK = 0x03 << 2
    FC0_SUBTYPE_MASK = 0x0f << 4
    FC1_TODS_MASK = 0x01 << 1
    FC1_FROMDS_MASK = 0x01 << 2

    @classmethod
    def to_python(cls, data):
        fc = data.get('i_fc')

        i_version = fc[0] & cls.FC0_VERSION_MASK
        i_type = fc[0] & cls.FC0_TYPE_MASK
        i_subtype = fc[0] & cls.FC0_SUBTYPE_MASK
        i_tods = fc[1] & cls.FC1_TODS_MASK
        i_fromds = fc[1] & cls.FC1_FROMDS_MASK

        return {
            'version': i_version,
            'type': i_type,
            'subtype': i_subtype,
            'tods': i_tods,
            'fromds': i_fromds,
            'addr1': data.get('i_addr1'),
            'addr2': data.get('i_addr2'),
            'addr3': data.get('i_addr3'),
            'seq': data.get('i_seq'),
        }


class IEEE80211Frame(PacketContainer):
    name='ieee80211_frame'

    @staticmethod
    def print_macaddr(addr):
        print "{0:x}:{1:x}:{2:x}:{3:x}:{4:x}:{5:x}".format(
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            addr[4],
            addr[5],
        )

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

    @classmethod
    def process_beacon_frame(cls, buf):
        """
        IEEE802.11-2012 8.3.3.2
        """

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

        if frame_struct.type == IEEE80211Types.MANAGEMENT:
            if frame_struct.subtype == IEEE80211ManagementSubtypes.BEACON:
                data.update(
                    cls.process_beacon_frame(frame_body)
                )
            elif frame_struct.subtype == IEEE80211ManagementSubtypes.PROBE_REQ:
                data.update(
                    cls.process_probe_req(frame_body)
                )
            else:
                data.update({
                    'subtype_not_supported': True,
                })
        else:
            data.update({
                'type_not_supported': True,
                'subtype_not_supported': True,
            })

        frame = cls(data)

        return frame
