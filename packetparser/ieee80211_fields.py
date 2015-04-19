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

"""
    Fixed length fields

    802.11-2012 8.4.1
"""

from datetime import timedelta
from .types import Structure, UInt8, UInt16, UInt64, Array, LittleEndian

class IEEE80211TimestampField(Structure):
    """
    Def. Guide: Page 91

    802.11-2012 8.4.1.1
    """

    endianness = LittleEndian
    attribute_list = (
        ('timestamp', UInt64),
    )


class IEEE80211BeaconIntervalField(Structure):
    """
    Def. Guide: Page 88

    802.11-2012 8.4.1.3
    """

    endianness = LittleEndian
    attribute_list = (
        ('beacon_interval', UInt16),
    )

    @classmethod
    def to_python(cls, data):
        # Convert from TU (Time Units) to microseconds.
        # 1 TU = 1024 microseconds

        return {
            'beacon_interval': timedelta(microseconds=data.get('beacon_interval') * 1024)
        }


class IEEE80211CapabilityInformationField(Structure):
    """
    Def. Guide: Page 88, capability information.

    802.11-2014 8.4.1.4
    """

    endianness = LittleEndian
    attribute_list = (
        ('capability', Array(UInt8, 2)),
    )

    CAP0_ESS = 0x01 << 0
    CAP0_IBSS = 0x01 << 1
    CAP0_CF_POLLABLE = 0x01 << 2
    CAP0_CF_POLL_REQ = 0x01 << 3
    CAP0_PRIVACY = 0x01 << 4
    CAP0_SHORT_PREAMBLE = 0x01 << 5
    CAP0_PBCC = 0x01 << 6
    CAP0_CHANNEL_AGILITY = 0x01 << 0

    CAP1_DSSS_OFDM = 0x01 << 5
    CAP1_SHORT_SLOT_TIME = 0x01 << 2

    @classmethod
    def to_python(cls, data):
        def field_is_set(data, mask):
            return data & mask == mask

        cap = data.get('capability')

        # TODO: Deal with the CF_POLLABLE, CF_POLL_REQ and QoS fields and
        # the translation table in 802.11-2014 8.4.1.4

        return {
            "capability_ess": field_is_set(cap[0], cls.CAP0_ESS),
            "capability_ibss": field_is_set(cap[0], cls.CAP0_IBSS),
            "capability_privacy": field_is_set(cap[0], cls.CAP0_PRIVACY),
            "capability_short_preamble": field_is_set(cap[0], cls.CAP0_SHORT_PREAMBLE),
            "capability_pbcc": field_is_set(cap[0], cls.CAP0_PBCC),
            "capability_channel_agility": field_is_set(cap[0], cls.CAP0_CHANNEL_AGILITY),
            "capability_short_slot_time": field_is_set(cap[1], cls.CAP1_SHORT_SLOT_TIME),
            "capability_dss_ofdm": field_is_set(cap[1], cls.CAP1_DSSS_OFDM),
        }

        return data
