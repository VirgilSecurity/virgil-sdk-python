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
import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode


def b64_decode(data):
    """Decode base64, padding being optional.

    Args:
        data: Base64 data as an ASCII byte string
    Returns:
        The decoded byte string.

    """
    try:
        return urlsafe_b64decode(data)
    except binascii.Error as e:
        missing_padding = len(data) % 4
        if missing_padding != 0:
            if isinstance(data, str):
                data += '=' * (4 - missing_padding)
            if isinstance(data, bytes) or isinstance(data, bytearray):
                data += b'=' * (4 - missing_padding)
        return urlsafe_b64decode(data)


def b64_encode(data):
    """
    Removes any `=` used as padding from the encoded string.

    Args:
        Data for encoding.
    Returns:
        Encoded data without '=' sign
    """
    encoded = urlsafe_b64encode(data)
    return encoded.decode().rstrip("=")