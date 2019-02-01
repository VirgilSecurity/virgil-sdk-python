# Copyright (C) 2016-2019 Virgil Security Inc.
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
from abc import ABCMeta


class BaseCardClient(object):
    """
    The BaseCardClient defines a list of operations with Virgil Cards service.
    """

    __metaclass__ = ABCMeta

    def search_card(self, identity, token):
        """
        Searches a cards on Virgil Services by specified identity.

        Args:
            identity: The identity.
            token: The string representation of Jwt token.

        Returns:
            A list of found cards in raw form.
        """
        raise NotImplementedError()

    def get_card(self, card_id, token):
        """
        Gets a card from Virgil Services by specified card ID.

        Args:
            card_id: The card ID.
            token: The string representation of Jwt token.

        Returns:
           An instance of RawSignedModel class and flag,
           which determines whether or not this raw card is superseded.
        """
        raise NotImplementedError()

    def publish_card(self, request, token):
        """
        Publishes card in Virgil Cards service.

        Args:
            request: An instance of RawSignedModel class.
            token: The string representation of Jwt token.

        Returns:
            Published raw card.
        """
        raise NotImplementedError()
