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
import base64
import binascii


class VirgilBuffer(object):
    """The VirgilBuffer class provides a list of methods that
    simplify the work with an array of bytes.
    """

    def __init__(
            self,
            raw_bytes  # type: Union[bytes, bytearray]
    ):
        # type: (...) -> None
        self._buffered_bytes = bytearray(raw_bytes)

    def get_bytearray(self):
        # type: () -> bytearray
        """Gets an array of bytes.
        Returns:
            A byte array
        """
        return self.__buffered_bytes

    @staticmethod
    def from_string(raw_string, string_encoding="utf-8"):
        # type: (str, str) -> VirgilBuffer
        """Creates a new VirgilBuffer containing the given string. If provided, the encoding parameter
        identifies the character encoding of string.
        Args:
            raw_string: String to encode.
            string_encoding: The encoding of string.
        Raises:
            ValueError when meet undeclared string encoding for VirgilBuffer
        """
        if string_encoding == "utf-8":
            return VirgilBuffer.__from_utf8_string(raw_string)
        if string_encoding == "hex":
            return VirgilBuffer.__from_hex_string(raw_string)
        if string_encoding == "base64":
            return VirgilBuffer.__from_base64_string(raw_string)
        raise ValueError("Undeclared string encoding for VirgilBuffer")

    @staticmethod
    def from_bytes(raw_bytes):
        # type: (Union[bytes, bytearray]) -> VirgilBuffer
        """Allocates a new VirgilBuffer using an array of bytes.
        Args:
            raw_bytes: An array of bytes to copy from.
        Returns:
            A new instance of VirgilBuffer class
        """
        return VirgilBuffer(raw_bytes)

    def to_string(self, string_encoding="utf-8"):
        # type: (str) -> str
        """Decodes the current VirgilBuffer to a string according to the specified
        character encoding in string_encoding
        Args:
            string_encoding: The character encoding to decode to.
        Returns:
            A string that represents this instance.
        Raises:
            ValueError when meet undeclared string encoding for VirgilBuffer
        """
        if string_encoding == "utf-8":
            return self.__to_utf8_string()
        if string_encoding == "hex":
            return self.__to_hex_string()
        if string_encoding == "base64":
            return self.__to_base64_string()
        raise ValueError("Undeclared string encoding for VirgilBuffer")

    @staticmethod
    def __from_base64_string(raw_string):
        # type: (str) -> VirgilBuffer
        """Initializes a new buffer from specified string,
        which encodes binary data as base-64 digits.
        Returns:
            A new instance of VirgilBuffer class.
        """
        return VirgilBuffer(base64.b64decode(raw_string))

    @staticmethod
    def __from_utf8_string(raw_string):
        # type: (str) -> VirgilBuffer
        """Initializes a new buffer from specified string,
        which encodes binary data as utf-8.
        Returns:
            A new instance of VirgilBuffer class.
        """
        return VirgilBuffer(raw_string.encode("utf-8"))

    @staticmethod
    def __from_hex_string(raw_string):
        # type: (str) -> VirgilBuffer
        """Initializes a new buffer from specified string,
        which encodes binary data as hexadecimal digits.
        Returns:
            A new instance of VirgilBuffer class.
        """
        return VirgilBuffer(binascii.a2b_hex(raw_string))

    def __to_base64_string(self):
        # type: () -> str
        """Converts all the bytes in current buffer to its equivalent string representation that
        is encoded with base-64 digits.
        Returns:
            The string representation of current buffer bytes.
        """
        return base64.b64encode(self.__buffered_bytes).decode("ascii")

    def __to_utf8_string(self):
        # type: () -> str
        """Decodes all the bytes in current buffer into a string.
        Returns:
            A string that contains the results of decoding the specified sequence of bytes
        """
        return self.__buffered_bytes.decode("ascii")

    def __to_hex_string(self):
        # type: () -> str
        """Converts the numeric value of each element of a current buffer bytes to its
        equivalent hexadecimal string representation.
        Returns:
            The string representation of current buffer bytes
        """
        return binascii.b2a_hex(self.__buffered_bytes).decode("ascii")

    @property
    def __buffered_bytes(self):
        # type: () -> bytearray
        """Buffered bytes"""
        if not self._buffered_bytes:
            raise ValueError("Buffer empty")
        return self._buffered_bytes
