import array
import unittest

from packetparser.types import (
    Structure, UInt32, UInt16, UInt8, Int32,
    Int16, Int8, LittleEndian, BigEndian, Array
)


class BaseDummyStructure(Structure):
    attribute_list = (
        ('uint32_value', UInt32),
        ('uint16_value', UInt16),
        ('uint8_value', UInt8),
        ('int32_value', Int32),
        ('int16_value', Int16),
        ('int8_value', Int8),

        ('int32_array', Array(Int32, 4)),
        ('int16_array', Array(Int16, 4)),
        ('int8_array', Array(Int8, 4)),
    )


class LittleEndianDummyStructure(BaseDummyStructure):
    endianness = LittleEndian


class BigEndianDummyStructure(BaseDummyStructure):
    endianness = BigEndian


class StructureTests(unittest.TestCase):

    def test_be_dummy_structure_pack(self):
        dummy_struct = BigEndianDummyStructure({
            'uint32_value': 1,
            'uint16_value': 2,
            'uint8_value': 3,

            'int32_value': -1,
            'int16_value': -2,
            'int8_value': -3,

            'int32_array': [-1, -1, -1, -1],
            'int16_array': [-2, -2, -2, -2],
            'int8_array': [-3, -3, -3, -3],

        })

        dummy_data_array = array.array('B', [1,] * 42)

        dummy_struct.pack(dummy_data_array)

        uint32_value = [0x00, 0x00, 0x00, 0x01]
        uint16_value = [0x00, 0x02, ]
        uint8_value = [0x03,]

        int32_value = [0xFF, 0xFF, 0xFF, 0xFF]
        int16_value = [0xFF, 0xFE, ]
        int8_value = [0xFD, ]

        int32_array = [0xFF, 0xFF, 0xFF, 0xFF] * 4
        int16_array = [0xFF, 0xFE, ] * 4
        int8_array = [0xFD, ] * 4

        expected = uint32_value + uint16_value + uint8_value + \
                   int32_value + int16_value + int8_value + \
                   int32_array + int16_array + int8_array

        expected_array = array.array('B', expected)

        self.assertEquals(expected_array, dummy_data_array)

    def test_le_dummy_structure_unpack(self):
        uint32_value = [0x01, 0x00, 0x00, 0x00]
        uint16_value = [0x02, 0x00, ]
        uint8_value = [0x03,]

        int32_value = [0xFF, 0xFF, 0xFF, 0xFF]
        int16_value = [0xFE, 0xFF, ]
        int8_value = [0xFD, ]

        int32_array = [0xFF, 0xFF, 0xFF, 0xFF] * 4
        int16_array = [0xFE, 0xFF, ] * 4
        int8_array = [0xFD, ] * 4

        dummy_data = uint32_value + uint16_value + uint8_value + \
                     int32_value + int16_value + int8_value + \
                     int32_array + int16_array + int8_array

        dummy_data_array = array.array('B', dummy_data)

        dummystruct = LittleEndianDummyStructure.unpack(dummy_data_array)

        self.assertEquals(dummystruct.uint32_value, 1)
        self.assertEquals(dummystruct.uint16_value, 2)
        self.assertEquals(dummystruct.uint8_value, 3)

        self.assertEquals(dummystruct.int32_value, -1)
        self.assertEquals(dummystruct.int16_value, -2)
        self.assertEquals(dummystruct.int8_value, -3)

        self.assertEquals(dummystruct.int32_array, [-1, -1, -1, -1])
        self.assertEquals(dummystruct.int16_array, [-2, -2, -2, -2])
        self.assertEquals(dummystruct.int8_array, [-3, -3, -3, -3])

    def test_be_dummy_structure_unpack(self):
        uint32_value = [0x00, 0x00, 0x00, 0x01]
        uint16_value = [0x00, 0x02, ]
        uint8_value = [0x03,]

        int32_value = [0xFF, 0xFF, 0xFF, 0xFF]
        int16_value = [0xFF, 0xFE, ]
        int8_value = [0xFD, ]

        int32_array = [0xFF, 0xFF, 0xFF, 0xFF] * 4
        int16_array = [0xFF, 0xFE, ] * 4
        int8_array = [0xFD, ] * 4

        dummy_data = uint32_value + uint16_value + uint8_value + \
                     int32_value + int16_value + int8_value + \
                     int32_array + int16_array + int8_array

        dummy_data_array = array.array('B', dummy_data)

        dummystruct = BigEndianDummyStructure.unpack(dummy_data_array)

        self.assertEquals(dummystruct.uint32_value, 1)
        self.assertEquals(dummystruct.uint16_value, 2)
        self.assertEquals(dummystruct.uint8_value, 3)

        self.assertEquals(dummystruct.int32_value, -1)
        self.assertEquals(dummystruct.int16_value, -2)
        self.assertEquals(dummystruct.int8_value, -3)

        self.assertEquals(dummystruct.int32_array, [-1, -1, -1, -1])
        self.assertEquals(dummystruct.int16_array, [-2, -2, -2, -2])
        self.assertEquals(dummystruct.int8_array, [-3, -3, -3, -3])
