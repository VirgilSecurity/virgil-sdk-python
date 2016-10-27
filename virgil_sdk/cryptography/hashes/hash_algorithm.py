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
import virgil_crypto

class HashAlgorithm(object):
    """Enumeration containing supported Algorithms"""

    class UnknownAlgorithmException(Exception):
        """Exception raised when Unknown Algorithm passed to convertion method"""

        def __init__(self, algorithm):
            super(HashAlgorithm.UnknownAlgorithmException, self).__init__(algorithm)
            self.algorithm = algorithm

        def __str__(self):
            return "KeyPairType not found: %i" % self.algorithm
    MD5 = 0
    SHA1 = 1
    SHA224 = 2
    SHA256 = 3
    SHA384 = 4
    SHA512 = 5

    _ALGORITHMS_TO_NATIVE = {
        MD5: virgil_crypto.VirgilHash.Algorithm_MD5,
        SHA1: virgil_crypto.VirgilHash.Algorithm_SHA1,
        SHA224: virgil_crypto.VirgilHash.Algorithm_SHA224,
        SHA256: virgil_crypto.VirgilHash.Algorithm_SHA256,
        SHA384: virgil_crypto.VirgilHash.Algorithm_SHA384,
        SHA512: virgil_crypto.VirgilHash.Algorithm_SHA512,
    }

    @classmethod
    def convert_to_native(cls, algorithm):
        # type: (int) -> int
        """Converts algorithm enum value to native value

        Args:
            algorithm: algorithm for conversion.

        Returns:
            Native library algorithm id.

        Raises:
            UnknownAlgorithmException: if algorithm is not supported.
        """
        if algorithm in cls._ALGORITHMS_TO_NATIVE:
            return cls._ALGORITHMS_TO_NATIVE[algorithm]
        raise cls.UnknownAlgorithmException(algorithm)
