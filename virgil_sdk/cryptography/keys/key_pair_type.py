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
from collections import namedtuple
import virgil_crypto


class KeyPairType(object):
    """Enumeration containing supported KeyPairTypes"""

    class UnknownTypeException(Exception):
        """Exception raised when Unknown Type passed to convertion method"""

        def __init__(self, key_pair_type):
            super(KeyPairType.UnknownTypeException, self).__init__(key_pair_type)
            self.key_pair_type = key_pair_type

        def __str__(self):
            return "KeyPairType not found: %i" % self.key_pair_type

    Default = 0
    RSA_2048 = 1
    RSA_3072 = 2
    RSA_4096 = 3
    RSA_8192 = 4
    EC_SECP256R1 = 5
    EC_SECP384R1 = 6
    EC_SECP521R1 = 7
    EC_BP256R1 = 8
    EC_BP384R1 = 9
    EC_BP512R1 = 10
    EC_SECP256K1 = 11
    EC_CURVE25519 = 12
    FAST_EC_X25519 = 13
    FAST_EC_ED25519 = 14

    _TYPES_TO_NATIVE = {
        Default: virgil_crypto.VirgilKeyPair.Type_FAST_EC_ED25519,
        RSA_2048: virgil_crypto.VirgilKeyPair.Type_RSA_2048,
        RSA_3072: virgil_crypto.VirgilKeyPair.Type_RSA_3072,
        RSA_4096: virgil_crypto.VirgilKeyPair.Type_RSA_4096,
        RSA_8192: virgil_crypto.VirgilKeyPair.Type_RSA_8192,
        EC_SECP256R1: virgil_crypto.VirgilKeyPair.Type_EC_SECP256R1,
        EC_SECP384R1: virgil_crypto.VirgilKeyPair.Type_EC_SECP384R1,
        EC_SECP521R1: virgil_crypto.VirgilKeyPair.Type_EC_SECP521R1,
        EC_BP256R1: virgil_crypto.VirgilKeyPair.Type_EC_BP256R1,
        EC_BP384R1: virgil_crypto.VirgilKeyPair.Type_EC_BP384R1,
        EC_BP512R1: virgil_crypto.VirgilKeyPair.Type_EC_BP512R1,
        EC_SECP256K1: virgil_crypto.VirgilKeyPair.Type_EC_SECP256K1,
        EC_CURVE25519: virgil_crypto.VirgilKeyPair.Type_EC_CURVE25519,
        FAST_EC_X25519: virgil_crypto.VirgilKeyPair.Type_FAST_EC_X25519,
        FAST_EC_ED25519: virgil_crypto.VirgilKeyPair.Type_FAST_EC_ED25519,
    }

    @classmethod
    def convert_to_native(cls, key_pair_type):
        # type: (int) -> int
        """Converts type enum value to native value

        Args:
            key_pair_type: type id for conversion.

        Returns:
            Native library key pair type id.

        Raises:
            UnknownTypeException: if type is not supported.
        """
        if key_pair_type in cls._TYPES_TO_NATIVE:
            return cls._TYPES_TO_NATIVE[key_pair_type]
        raise cls.UnknownTypeException(key_pair_type)
