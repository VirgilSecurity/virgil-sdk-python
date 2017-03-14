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
import json

class Utils(object):
    """Helpers used accross the project."""

    @staticmethod
    def strtobytes(source):
        # type: (str) -> Tuple[*int]
        """Convert string to bytes tuple used for all crypto methods."""
        return tuple(bytearray(source))

    @classmethod
    def b64tobytes(cls, source):
        # type: (str) -> Tuple[*int]
        """Convert source to bytearray and encode using base64."""
        return cls.strtobytes(cls.b64decode(source))

    @staticmethod
    def b64encode(source):
        # type: (str) -> str
        """Convert source to bytearray and encode using base64."""
        return base64.b64encode(bytearray(source)).decode("utf-8", "ignore")

    @staticmethod
    def b64decode(source):
        # type: (str) -> str
        """Convert source to bytearray and decode using base64."""
        return base64.b64decode(bytearray(source, "utf-8"))

    @staticmethod
    def json_loads(source):
        # type: (Union[str, bytes, bytearray]) -> dict
        """Convert source to bytearray and deserialize from json to python dict object."""
        return json.loads(bytearray(source).decode())

    @staticmethod
    def json_dumps(source):
        # type: (object) -> str
        """Convert python dict to json string"""
        return json.dumps(source)
