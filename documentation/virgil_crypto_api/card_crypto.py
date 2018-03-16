# Copyright (C) 2016-2018 Virgil Security Inc.
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
from abc import ABCMeta, abstractmethod
from .private_key import PrivateKey
from .public_key import PublicKey


class CardCrypto(object):
    """
    The CardCrypto interface defines a list of methods that provide a signature generation
    and signature verification methods.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def generate_signature(self, input_bytes, private_key):
        # type: (bytearray, PrivateKey) -> bytearray
        """
        Generates the digital signature for the specified input_bytes using
        the specified PrivateKey
        Args:
            input_bytes: The input data for which to compute the signature.
            private_key: The private key

        Returns:
            The digital signature for the specified data.
        """
        raise NotImplementedError()

    @abstractmethod
    def verify_signature(self, signature, input_bytes, public_key):
        # type: (bytearray, bytearray, PublicKey) -> bool
        """
        Verifies that a digital signature is valid by checking the signature and
        provided public_key and input_bytes.
        Args:
            signature: The digital signature for the input_bytes
            input_bytes: The input data for which the signature has been generated.
            public_key:

        Returns:
            True if signature is valid, False otherwise.
        """
        raise NotImplementedError()

    @abstractmethod
    def generate_sha256(self, input_bytes):
        # type: (bytearray) -> bytearray
        """
        Generates the fingerprint(256-bit hash) for the specified input_bytes.
        Args:
            input_bytes: The input data for which to compute the fingerprint.

        Returns:
            The fingerprint for specified data.
        """
        raise NotImplementedError()

    @abstractmethod
    def import_public_key(self, public_key_bytes):
        # type: (bytearray) -> PublicKey
        """
        Imports the public key from its material representation.
        Args:
            public_key_bytes: The public key material representation bytes.

        Returns:
            The instance of PublicKey imported from public_key_bytes.
        """
        raise NotImplementedError()

    @abstractmethod
    def export_public_key(self, public_key):
        # type: (PublicKey) -> bytearray
        """
        Exports the public_key into material representation.
        Args:
            public_key: The public key

        Returns:

        """
        raise NotImplementedError()
