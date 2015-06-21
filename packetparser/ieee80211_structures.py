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

from .types import Structure, UInt8, UInt16, Array, LittleEndian

class IEEE80211MinimalFrameStructure(Structure):
    """
    A minimal 802.11 Frame to determine the type and subtype.
    """

    endianness = LittleEndian
    attribute_list = (
        ('i_fc', Array(UInt8, 2)),
    )

    # 80211-2012 8.2.4.1.1
    FC0_VERSION_MASK = 0x03 << 0
    FC0_TYPE_MASK = 0x03 << 2
    FC0_SUBTYPE_MASK = 0x0f << 4
    FC1_TODS_MASK = 0x01 << 1
    FC1_FROMDS_MASK = 0x01 << 2

    @classmethod
    def parse_fc(cls, data):
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
        }

    @classmethod
    def to_python(cls, data):
        return cls.parse_fc(data)


class IEEE80211FrameStructure(IEEE80211MinimalFrameStructure):
    """
    Described in 8.3.3 of 802.11-2012
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
