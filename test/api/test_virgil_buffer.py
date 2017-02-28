import unittest

from virgil_sdk.api import VirgilBuffer


class VirgilBufferTest(unittest.TestCase):

    def test_from_string_utf8(self):
        line_utf_8 = "hello world"
        vb = VirgilBuffer.from_string(line_utf_8, "utf-8")
        self.assertEqual(vb.to_string("utf-8"), line_utf_8)
        self.assertEqual(type(vb.get_bytearray()), bytearray)
        self.assertEqual(vb.to_string(), line_utf_8)

    def test_from_string_base64(self):
        line_utf_8 = "hello world"
        line_base64 = "aGVsbG8gd29ybGQ="
        vb = VirgilBuffer.from_string(line_base64, "base64")
        self.assertEqual(vb.to_string("base64"), line_base64)
        self.assertEqual(type(vb.get_bytearray()), bytearray)
        self.assertEqual(vb.to_string(), line_utf_8)

    def test_from_string_hex(self):
        line_utf_8 = "hello world"
        line_hex = "68656c6c6f20776f726c64"
        vb = VirgilBuffer.from_string(line_hex, "hex")
        self.assertEqual(vb.to_string("hex"), line_hex)
        self.assertEqual(type(vb.get_bytearray()), bytearray)
        self.assertEqual(vb.to_string(), line_utf_8)

    def test_from_bytes(self):
        line_utf_8 = "hello world"
        byte_line = line_utf_8.encode()
        vb = VirgilBuffer.from_bytes(byte_line)
        self.assertEqual(vb.to_string(), line_utf_8)
        self.assertEqual(type(vb.get_bytearray()), bytearray)
        self.assertEqual(bytes(vb.get_bytearray()), byte_line)

    def test_from_constuctor(self):
        line_utf_8 = "hello world"
        byte_line = line_utf_8.encode()
        vb = VirgilBuffer(byte_line)
        self.assertEqual(vb.to_string(), line_utf_8)
        self.assertEqual(type(vb.get_bytearray()), bytearray)
        self.assertEqual(bytes(vb.get_bytearray()), byte_line)

    def test_from_empty_bytes(self):
        with self.assertRaises(Exception) as context:
            vb = VirgilBuffer(bytes())
            vb.get_bytearray()
        self.assertEqual("Buffer empty", str(context.exception))
