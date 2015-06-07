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
from datetime import datetime, timedelta
import time

from .base import PacketContainer
from .radiotap import RadiotapFrame
from .types import Structure, UInt32, UInt16, Int32


class PcapFrameStructure(Structure):
    attribute_list = (
        ('ts_sec', UInt32),
        ('ts_usec', UInt32),
        ('incl_len', UInt32),
        ('orig_len', UInt32),
    )

    @classmethod
    def defaults(cls):
        """
        The defaults for the human-readable form.
        """

        return {
            'time_recorded': datetime.now(),
            'len': None,
            'orig_len': None
        }

    @classmethod
    def from_python(cls, data):
        """
        Convert from human-readable python data types to their Structure
        counterparts.
        """

        ts_sec = None
        ts_usec = None
        time_recorded = data.get('time_recorded')

        if time_recorded:
            # TODO: Verify both of these are correct.
            ts_usec = time_recorded.microsecond
            ts_sec = time.mktime(time_recorded.time_tuple())

        return {
            'ts_sec': ts_sec,
            'ts_usec': ts_usec,
            'incl_len': data.get('len'),
            'orig_len': data.get('orig_len'),
        }

    @classmethod
    def to_python(cls, data):
        """
        Convert from the Structure specific data to human readable data.
        """

        if data['ts_usec'] >= 1000000:
            raise ValueError("ts_usec shouldn't be equal to or larger than 1 000 000 microseconds")

        timestamp = data['ts_sec']
        ms_offset = data['ts_usec']

        time_recorded = datetime.utcfromtimestamp(timestamp) + timedelta(microseconds=ms_offset)

        new = cls.defaults()
        new.update({
            'time_recorded': time_recorded,
            'len': data['incl_len'],
            'orig_len': data['orig_len'],
        })

        return new


class PcapFrame(PacketContainer):
    """
    Parse one PCAP Frame and its contents, then hand
    it off to the appropriate lower layer.
    """
    name = 'pcap_frame'

    @classmethod
    def parse(cls, file_handle, extra={}):

        # Read and parse the header.
        pcap_frame_array = array.array('B')
        pcap_frame_array.fromfile(
            file_handle,
            PcapFrameStructure.struct.size
        )
        pcap_frame_struct = PcapFrameStructure.unpack(pcap_frame_array)

        # Read the payload.
        pcap_payload_array = array.array('B')
        pcap_payload_array.fromfile(
            file_handle,
            pcap_frame_struct.len
        )

        payload_type = extra.get('payload_type')
        payload_name = payload_type.name

        data = pcap_frame_struct.data

        # First create the frame
        frame = cls(data)

        extra = {
            'upper_layer': frame
        }

        # Then create the payload
        payload = payload_type.parse(
            pcap_payload_array,
            extra
        )

        setattr(frame, payload_name, payload)

        return frame

    def to_buffer(self):
        pass


class PcapHeaderStructure(Structure):
    attribute_list = (
        ('magic_number', UInt32),
        ('version_major', UInt16),
        ('version_minor', UInt16),
        ('thiszone', Int32),
        ('sigfigs', UInt32),
        ('snaplen', UInt32),
        ('network', UInt32),
    )

    @classmethod
    def defaults(cls):
        """
        The defaults for the human-readable form.
        """

        return {
            'swapped': True,
            'magic_number': 0xa1b2c3d4,
            'version_major': 2,
            'version_minor': 4,
            'tzoff': timedelta(seconds=0),
            'sigfigs': 0,
            'snaplen': None,
            'network': None,
        }

    @classmethod
    def keys(cls):
        """
        The keys for the human-readable form.
        """

        return cls.defaults().keys()

    def is_valid(self):
        """
        Validate the human-readable form.
        """

        data = self.data

        if data['magic_number'] != 0xa1b2c3d4:
            return False  #raise Exception("magic_number is readonly")

        if data['version_major'] != 2:
            return False  #raise Exception("version_major is readonly")

        if data['version_minor'] != 4:
            return False  #raise Exception("version_minor is readonly")

        if data['tzoff'] != timedelta(seconds=0):
            return False  #raise Exception("thiszone is readonly")

        if data['sigfigs'] != 0:
            return False  #raise Exception("sigfigs is readonly")

        return True

    @classmethod
    def from_python(cls, data):
        """
        Convert from human-readable python data types to their Structure
        counterparts.
        """

        return {
            'magic_number': 0xa1b2c3d4,
            'version_major': 2,
            'version_minor': 4,
            'thiszone': 0,
            'sigfigs': 0,
            'snaplen': data.get('snaplen', 0),
            'network': data.get('network', 0),
        }

    @classmethod
    def to_python(cls, data):
        """
        Convert from the Structure specific data to human readable data.
        """

        new = cls.defaults()
        new.update({
            'snaplen': data.get('snaplen', 0),
            'network': data.get('network', 0)
        })

        return new

class PcapFile(PacketContainer):
    """
    An abstraction which reads the file from disk,
    parses the PCAP file header, and reads one frame at the
    time
    """

    def __init__(self, data, file_handle):
        self.file_handle = file_handle

        new = {}
        new.update(PcapHeaderStructure.defaults())
        new.update(data)
        self.data = new

    def data_for_keys(self, keys):
        data_keys = self.data.iterkeys()

        intersect = set(keys) & set(data_keys)

        if intersect != set(keys):
            raise Exception("Couldn't find all the keys")

        new_data = {}
        for key, value in self.data.iteritems():
            if key not in keys:
                raise Exception("Couldn't find {0} in the keys".format(key))

            assert key not in new_data

            new_data[key] = value

        return new_data

    def write_header(self):
        pcap_struct = PcapHeaderStructure(
            self.data_for_keys(PcapHeaderStructure.keys())
        )

        if not pcap_struct.is_valid():
            raise Exception("Data invalid.")

        header_frame_array = array.array('B', [0x00, ]*pcap_struct.struct.size)

        pcap_struct.pack(header_frame_array)

        # Write to file to the beginning of the file and
        # removing any existing frames.
        self.file_handle.seek(0)
        self.file_handle.truncate()
        header_frame_array.tofile(self.file_handle)
        self.file_handle.flush()

    def write_frame(self, frame):
        pass

    @classmethod
    def parse_header(cls, file_handle):
        file_handle.seek(0)

        header_frame_array = array.array('B')
        header_frame_array.fromfile(
            file_handle,
            PcapHeaderStructure.struct.size
        )

        pcap_header_struct = PcapHeaderStructure.unpack(header_frame_array)
        data = pcap_header_struct.data

        return cls(data, file_handle)

    def frames(self):
        # Start parsing right after the PCAP header.
        self.file_handle.seek(PcapHeaderStructure.struct.size)

        # TODO: For now we support 127, 80211 RadioTap only.
        extra = {
            'payload_type': RadiotapFrame,
        }

        try_next_frame = True

        while try_next_frame:
            try:
                yield PcapFrame.parse(
                    self.file_handle,
                    extra
                )
            except EOFError:
                try_next_frame = False

