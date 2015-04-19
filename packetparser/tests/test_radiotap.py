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

import array
import unittest

from ..radiotap import RadiotapFrame


class RadioTapTests(unittest.TestCase):

    def test_header_length_too_long(self):
        """
        Test the case where a invalid radiotap frame is created with
        the header length beyond the end of the buffer.

        This should throw an exception. We expect an exception here because
        the kernel(or any other tool) should never create an invalid frame.
        And this shouldn't happen often.
        """

        version = [0x00, ]
        padding = [0x00, ]
        header_length = [0x11, 0x00]  # 17 bytes
        bitmap = [0x2e, 0x18, 0x00, 0x00]  # Enabled: Flags, Rate, Channel, AntennaSignal
                                           # Antenna, db Antenna Signal

        flags = [0x00, ]  # no flags set
        # Ends here

        frame = version + padding + header_length + bitmap + flags

        frame_array = array.array('B', frame)

        with self.assertRaises(AssertionError):
            RadiotapFrame.parse(frame_array)


    def test_has_padding(self):
        """
        Create a Radiotap frame which requires padding between fields
        """

        pass

    def test_unsupported_fields(self):
        """
        Create a Radiotap frame which has fields not supported by this parser.
        """

        pass
