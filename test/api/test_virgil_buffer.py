# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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
