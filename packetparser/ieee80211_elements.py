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
    Information elements

    802.11-2012 8.4.2
"""

from .types import Structure, UInt8, UInt16, Array, LittleEndian


class IEEE80211Element(Structure):
    endianness = LittleEndian

    attribute_list = (
        ('element_id', UInt8),
        ('length', UInt8),
    )

    ELEMENT_SSID=0
    ELEMENT_SUPPORTED_RATES=1
    ELEMENT_FH_PARAMETER_SET=2
    ELEMENT_DSSS_PARAMETER_SET=3
    ELEMENT_CF_PARAMETER_SET=4
    ELEMENT_TIM=5
    ELEMENT_IBSS_PARAMETER_SET=6
    ELEMENT_COUNTRY=7
    # ...

class IEEE80211TIM(Structure):
    endianness = LittleEndian

    attribute_list = (
        ('dtim_count', UInt8),
        ('dtim_period', UInt8),
        ('bitmap_control', UInt8),
    )


class IEEE80211Country(Structure):
    endianness = LittleEndian

    attribute_list = (
        ('country_string', Array(UInt8, 3)),
    )

