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
An abstraction over the standard struct module to make
the structure definitions human-readable.
"""

import logging
import struct

logger = logging.getLogger(__name__)


class StructMetaClass(type):
    """
        A Metaclass which processes the format string to a struct on class initialization.
    """

    def __init__(cls, name, bases, dct):
        logger.debug("Initializing StructMetaClass: %s", name)

        has_attribute_list = hasattr(cls, 'attribute_list') and not cls.attribute_list is None

        if has_attribute_list:
            # Initialize a struct class with the type definition defined in the class
            # which will be used to unpack the data.
            struct_fmt = cls.endianness.format_char

            for attr, attr_cls in cls.attribute_list:
                if isinstance(attr_cls, Array):
                    struct_fmt += attr_cls.format_chars
                else:
                    struct_fmt += attr_cls.format_char

            cls.struct = struct.Struct(struct_fmt)

            initial_data = []
            initial_data_array = []

            array_mapping = []
            field_mapping = []

            field_idx = 0
            data_idx = 0
            for attr, attr_cls in cls.attribute_list:
                if isinstance(attr_cls, Array):
                    initial_data.append(attr)
                    initial_data_array.append((attr, attr_cls.size))

                    for array_idx in range(attr_cls.size):
                        array_mapping.append((attr, array_idx, data_idx))
                        data_idx += 1

                else:
                    initial_data.append(attr)
                    field_mapping.append((attr, data_idx))

                    data_idx += 1

                field_idx += 1

            cls._initial_data = initial_data
            cls._initial_data_array = initial_data_array
            cls._array_mapping = array_mapping
            cls._field_mapping = field_mapping

            cls._struct_size = cls.struct.size

        if has_attribute_list and hasattr(cls, 'Meta') and cls.Meta.abstract is False:
            print("{0} has no attribute_list defined".format(name))

        super(StructMetaClass, cls).__init__(name, bases, dct)


class Endianness(object):
    pass


class LittleEndian(Endianness):
    format_char = '<'


class BigEndian(Endianness):
    format_char = '>'


class Native(Endianness):
    format_char = '='


class Structure(object):
    __metaclass__ = StructMetaClass

    endianness = Native

    def __init__(self, data):
        for key, value in data.iteritems():
            setattr(self, key, value)

        # For backwards compat.
        self.data = data

    @classmethod
    def from_python(cls, data):
        """
        Convert from the human readable form in self.data
        to a form which will be used when packing the data.
        """

        return data

    @classmethod
    def to_python(cls, data):
        """
        Convert from packed data form to a human readable form
        """

        return data

    def pack(self, buf):
        pack_data = self.from_python(self.data)
        pack_args = []

        for attr, attr_cls in self.attribute_list:
            if isinstance(attr_cls, Array):
                for j in range(0, attr_cls.size):
                    pack_args.append(pack_data[attr][j])
            else:
                pack_args.append(pack_data[attr])

        return self.struct.pack_into(buf, 0, *pack_args)

    @classmethod
    def unpack(cls, buf):

        raw_data = cls.struct.unpack_from(buf)

#       XXX: Replace this assertion with something sane.
#        assert len(self.attribute_list) == len(raw_data)

        data = {}

        for attr, size in cls._initial_data_array:
            data[attr] = []

        for attr, array_idx, data_idx in cls._array_mapping:
            data[attr].append(raw_data[data_idx])

        for attr, data_idx in cls._field_mapping:
            data[attr] = raw_data[data_idx]

        return cls(cls.to_python(data))

    @classmethod
    def size(cls):
        return cls._struct_size

    class Meta:
        abstract=True


class DataType(object):
    pass


class Array(object):
    def __init__(self, cls, size):

        assert size >= 1

        self.cls = cls
        self.size = size

        self.format_chars = cls.format_char * size


class UInt64(DataType):
    format_char = 'Q'


class UInt32(DataType):
    format_char = 'I'


class UInt16(DataType):
    format_char = 'H'


class UInt8(DataType):
    format_char = 'B'


class Int8(DataType):
    format_char = 'b'


class Int16(DataType):
    format_char = 'h'


class Int32(DataType):
    format_char = 'i'

